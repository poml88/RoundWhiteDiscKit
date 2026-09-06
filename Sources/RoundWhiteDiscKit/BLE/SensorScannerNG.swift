// SensorScannerNG -- event-driven CBCentralManager wrapper.
//
// Every CB delegate callback yields a single typed event on the
// events() stream. There are no pending-operation dictionaries, no
// continuation pools, no DispatchWorkItems for timeouts. Callers
// drive their own state machines off the events.
//
// This is the planned replacement for SensorScanner. Once consumers
// are migrated over, the old class will be removed.

import Foundation
import CoreBluetooth

public final class SensorScannerNG: NSObject, @unchecked Sendable {

    // MARK: - Events

    public enum Event: @unchecked Sendable {
        case stateChanged(CBManagerState)
        case didDiscover(DiscoveredSensor)
        case didConnect(CBPeripheral)
        case didFailToConnect(CBPeripheral, error: Error?)
        /// CB.didDisconnectPeripheral. Caller's cue to invalidate any
        /// outstanding session state.
        case didDisconnect(CBPeripheral, error: Error?)
        /// connectionEventDidOccur(_:for:) -- requires
        /// registerForConnectionEvents to be active.
        case connectionEvent(CBConnectionEvent, peripheral: CBPeripheral)
        case willRestoreState(SensorRestorationEvent)
    }

    /// Metadata supplied by CoreBluetooth's disconnect callback.
    public struct DisconnectMetadata: Sendable, Equatable {
        public let timestamp: CFAbsoluteTime
        public let isReconnecting: Bool

        public init(timestamp: CFAbsoluteTime, isReconnecting: Bool) {
            self.timestamp = timestamp
            self.isReconnecting = isReconnecting
        }
    }

    /// The unchanged scanner event together with disconnect context. Metadata
    /// is present for `.didDisconnect` and `nil` for every other event case.
    public struct ContextualEvent: Sendable {
        public let event: Event
        public let disconnectMetadata: DisconnectMetadata?

        public init(event: Event, disconnectMetadata: DisconnectMetadata?) {
            self.event = event
            self.disconnectMetadata = disconnectMetadata
        }
    }

    enum EventSubscriber {
        case legacy(AsyncStream<Event>.Continuation)
        case contextual(AsyncStream<ContextualEvent>.Continuation)

        func yield(_ contextualEvent: ContextualEvent) {
            switch self {
            case .legacy(let continuation):
                continuation.yield(contextualEvent.event)
            case .contextual(let continuation):
                continuation.yield(contextualEvent)
            }
        }

        func finish() {
            switch self {
            case .legacy(let continuation):
                continuation.finish()
            case .contextual(let continuation):
                continuation.finish()
            }
        }
    }


    private let configuration: SensorScannerConfiguration
    private let enableAutoReconnect: Bool
    /// Internal queue the CBCentralManager dispatches delegate callbacks
    /// on. Exposed publicly because callers who construct a SensorSession
    /// from a `.didConnect`'d peripheral typically want to use the same
    /// queue so CB peripheral-delegate callbacks land in the same
    /// serialization context as the central's events.
    public let centralQueue = DispatchQueue(label: "org.roundwhitedisc.ng", qos: .userInitiated)
    private lazy var central: CBCentralManager = {
        CBCentralManager(delegate: self, queue: centralQueue, options: configuration.centralOptions)
    }()

    /// AsyncStream continuations -- one per active subscriber of either API,
    /// keyed by a UUID we hand back on subscription for termination.
    /// Mutated only on centralQueue.
    private var eventSubscribers: [UUID: EventSubscriber] = [:]

    /// Restoration events arrive before any consumer has a chance to
    /// subscribe (CB delivers them before we even return from init()).
    /// Buffer them and replay to the first subscriber.
    private var pendingRestorationEvents: [SensorRestorationEvent] = []

    /// Strong references to the peripherals we're actively using. Core
    /// Bluetooth does NOT retain CBPeripheral objects for you -- a peripheral
    /// with a pending connect (or one handed back by state restoration) is
    /// deallocated once the last strong ref goes away, and iOS then silently
    /// drops the pending connect / tears down the restored connection. That
    /// manifested as a reconnect that never completes and, on a restored link,
    /// a handshake failing with `missingCharacteristic` + "the specified
    /// device has disconnected from us". We retain on requestConnect and on
    /// willRestoreState. We release only when an operation reaches a TERMINAL
    /// state, never merely when the CoreBluetooth command was issued: an
    /// intentional cancelConnection of a connected/disconnecting peripheral keeps
    /// the ref until its didDisconnect/didFailToConnect lands (owning it through
    /// the cancellation handoff), while cancelling a pending `.connecting` connect
    /// releases immediately (iOS fires no terminal callback for that). A plain
    /// unexpected didDisconnect keeps the ref -- it's still a reconnect candidate.
    /// Mutated only on centralQueue.
    private var retainedPeripherals: [UUID: CBPeripheral] = [:]

    /// Peripherals for which we issued an intentional `cancelPeripheralConnection`
    /// and are awaiting the terminal didDisconnect/didFailToConnect before dropping
    /// the retained strong ref. Distinguishes an intentional cancel (release on the
    /// terminal callback) from an unexpected disconnect (keep retaining). Mutated
    /// only on centralQueue.
    private var cancellingPeripherals: Set<UUID> = []

    /// All access is serialized on `centralQueue`. The policy value is kept
    /// separate so retirement decisions can be tested without a Bluetooth stack.
    private var retirementState = SensorScannerNGRetirementState()

    public init(
        configuration: SensorScannerConfiguration = .foreground,
        enableAutoReconnect: Bool = false
    ) {
        self.configuration = configuration
        self.enableAutoReconnect = enableAutoReconnect
        super.init()
        _ = central // force lazy init
    }

    // MARK: - State + events

    /// Snapshot of the central's current state.
    public var centralState: CBManagerState {
        var state: CBManagerState = .unknown
        centralQueue.sync { state = self.central.state }
        return state
    }

    /// Whether this scanner has permanently completed its retirement work.
    public var isRetired: Bool {
        var retired = false
        centralQueue.sync { retired = retirementState.isRetired }
        return retired
    }

    /// Subscribe to the event stream. Each subscriber gets an
    /// independent stream. On subscribe, the current central state is
    /// replayed as `.stateChanged(currentState)` so consumers don't
    /// race with already-fired transitions (e.g., a subscribe right
    /// after foreground-restore where CB has already settled to
    /// `.poweredOn`). Buffered restoration events from app launch are
    /// also flushed once to the first subscriber.
    public func events() -> AsyncStream<Event> {
        let id = UUID()
        return AsyncStream { continuation in
            centralQueue.async { [weak self] in
                guard let self else {
                    continuation.finish()
                    return
                }
                self.register(.legacy(continuation), id: id)
            }
        }
    }

    /// Subscribe to the same event stream as ``events()``, with optional
    /// metadata for disconnect callbacks that provide it. Registration,
    /// state replay and one-time restoration delivery are shared across both
    /// APIs, so the first subscriber of either kind receives restoration.
    public func eventsWithContext() -> AsyncStream<ContextualEvent> {
        let id = UUID()
        return AsyncStream { continuation in
            centralQueue.async { [weak self] in
                guard let self else {
                    continuation.finish()
                    return
                }
                self.register(.contextual(continuation), id: id)
            }
        }
    }

    /// Permanently retires this scanner. Completion means all retirement work
    /// has run on `centralQueue`; it does not imply a physical radio reset or a
    /// confirmed peripheral disconnection.
    public func retire() async {
        await withCheckedContinuation { continuation in
            centralQueue.async { [self] in
                retireOnCentralQueue()
                continuation.resume()
            }
        }
    }

    // MARK: - Scan (fire-and-forget)

    public func startScan(services: [CBUUID]? = [LibreSensorGATT.serviceUUID]) {
        centralQueue.async { [weak self] in
            guard let self, !self.retirementState.isRetired else { return }
            self.central.scanForPeripherals(
                withServices: services,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
            )
        }
    }

    public func stopScan() {
        centralQueue.async { [weak self] in
            guard let self, !self.retirementState.isRetired else { return }
            self.central.stopScan()
        }
    }

    // MARK: - Connect / disconnect (fire-and-forget)

    public func requestConnect(_ peripheral: CBPeripheral) {
        centralQueue.async { [weak self] in
            guard let self, !self.retirementState.isRetired else { return }
            // A fresh connect intent supersedes any pending cancellation handoff,
            // so a superseded cancel's terminal callback won't drop this new ref.
            self.cancellingPeripherals.remove(peripheral.identifier)
            // Retain the peripheral for the lifetime of the connect intent --
            // CB won't, and a deallocated peripheral drops the pending connect.
            self.retainedPeripherals[peripheral.identifier] = peripheral
            // central.connect is idempotent; if the peripheral is
            // already connecting or connected, this is a no-op.
            self.central.connect(
                peripheral,
                options: SensorScannerNGConnectOptions.merging(
                    self.configuration.connectOptions,
                    enableAutoReconnect: self.enableAutoReconnect
                )
            )
        }
    }

    public func cancelConnection(_ peripheral: CBPeripheral) {
        centralQueue.async { [weak self] in
            guard let self, !self.retirementState.isRetired else { return }
            let state = peripheral.state
            self.central.cancelPeripheralConnection(peripheral)
            switch state {
            case .connected, .disconnecting:
                // A terminal didDisconnect/didFailToConnect is coming -- keep the
                // strong ref (marked as an intentional cancel) until it lands, so we
                // don't drop the handle while CB still has a callback outstanding.
                self.cancellingPeripherals.insert(peripheral.identifier)
            default:
                // .connecting/.disconnected: iOS fires no terminal callback for a
                // pending-connect cancel, while watchOS does deliver didDisconnect.
                // Neither path needs the scanner to retain the peripheral here.
                self.cancellingPeripherals.remove(peripheral.identifier)
                self.retainedPeripherals[peripheral.identifier] = nil
            }
        }
    }

    /// Cancel a pending connect only if the peripheral is still `.connecting`. The
    /// state check and cancel run in one block on the central queue, where CB's
    /// delegate callbacks are also delivered, so a `didConnect` cannot slip in
    /// between them and be torn down by the cancel. A peripheral that has already
    /// connected, or has already dropped to `.disconnected`, is left alone.
    ///
    /// On watchOS a cancelled pending connect is followed by
    /// `didDisconnect(error: nil)`; on iOS it may not be. Callers must tolerate both.
    public func cancelConnectionIfStillConnecting(_ peripheral: CBPeripheral) {
        centralQueue.async { [weak self] in
            guard let self,
                  !self.retirementState.isRetired,
                  peripheral.state == .connecting else { return }
            self.central.cancelPeripheralConnection(peripheral)
            self.cancellingPeripherals.remove(peripheral.identifier)
            self.retainedPeripherals[peripheral.identifier] = nil
        }
    }

    // MARK: - Lookup helpers

    public func retrievePeripherals(withIdentifiers ids: [UUID]) -> [CBPeripheral] {
        var result: [CBPeripheral] = []
        centralQueue.sync {
            guard !retirementState.isRetired else { return }
            result = central.retrievePeripherals(withIdentifiers: ids)
        }
        return result
    }

    public func retrieveConnectedPeripherals(serviceUUIDs: [CBUUID] = [LibreSensorGATT.serviceUUID]) -> [CBPeripheral] {
        var result: [CBPeripheral] = []
        centralQueue.sync {
            guard !retirementState.isRetired else { return }
            result = central.retrieveConnectedPeripherals(withServices: serviceUUIDs)
        }
        return result
    }

    // MARK: - Background

    public func registerForConnectionEvents(
        peripheralIDs: [UUID]? = nil,
        serviceUUIDs: [CBUUID]? = nil
    ) {
        #if os(iOS)
        centralQueue.async { [weak self] in
            guard let self, !self.retirementState.isRetired else { return }
            var options: [CBConnectionEventMatchingOption: Any] = [:]
            if let peripheralIDs {
                options[.peripheralUUIDs] = peripheralIDs
            }
            if let serviceUUIDs {
                options[.serviceUUIDs] = serviceUUIDs
            }
            self.central.registerForConnectionEvents(options: options.isEmpty ? nil : options)
        }
        #else
        _ = peripheralIDs
        _ = serviceUUIDs
        #endif
    }

    // MARK: - Internal: emit

    /// Register either stream shape through the same ordering and restoration
    /// path. Must be called on centralQueue.
    private func register(_ subscriber: EventSubscriber, id: UUID) {
        guard !retirementState.isRetired else {
            subscriber.finish()
            return
        }

        eventSubscribers[id] = subscriber
        // Snapshot of the current state so a consumer that subscribes after CB
        // has already settled doesn't have to wait for the next transition.
        subscriber.yield(ContextualEvent(
            event: .stateChanged(central.state),
            disconnectMetadata: nil
        ))
        if !pendingRestorationEvents.isEmpty {
            for event in pendingRestorationEvents {
                subscriber.yield(ContextualEvent(
                    event: .willRestoreState(event),
                    disconnectMetadata: nil
                ))
            }
            pendingRestorationEvents.removeAll()
        }

        switch subscriber {
        case .legacy(let continuation):
            continuation.onTermination = { [weak self] _ in
                self?.removeSubscriber(id: id)
            }
        case .contextual(let continuation):
            continuation.onTermination = { [weak self] _ in
                self?.removeSubscriber(id: id)
            }
        }
    }

    private func removeSubscriber(id: UUID) {
        centralQueue.async { [weak self] in
            self?.eventSubscribers.removeValue(forKey: id)
        }
    }

    /// Yield an event to every subscriber. Must be called on centralQueue.
    private func emit(_ event: Event, disconnectMetadata: DisconnectMetadata? = nil) {
        guard !retirementState.isRetired else { return }
        let contextualEvent = ContextualEvent(
            event: event,
            disconnectMetadata: disconnectMetadata
        )
        for subscriber in eventSubscribers.values {
            subscriber.yield(contextualEvent)
        }
    }

    private func emitDisconnect(
        _ peripheral: CBPeripheral,
        error: Error?,
        timestamp: CFAbsoluteTime,
        isReconnecting: Bool
    ) {
        releaseIfCancelling(peripheral)
        emit(
            .didDisconnect(peripheral, error: error),
            disconnectMetadata: DisconnectMetadata(
                timestamp: timestamp,
                isReconnecting: isReconnecting
            )
        )
    }

    /// Must be called on centralQueue.
    private func retireOnCentralQueue() {
        let decision = retirementState.begin(centralState: central.state)
        guard decision.shouldRetire else { return }

        if decision.shouldIssueCentralCommands {
            central.stopScan()
            for peripheral in retainedPeripherals.values {
                central.cancelPeripheralConnection(peripheral)
            }
        }

        let subscribers = Array(eventSubscribers.values)
        eventSubscribers.removeAll()
        for subscriber in subscribers {
            subscriber.finish()
        }
        pendingRestorationEvents.removeAll()
        // Ordinary cancellation retains a peripheral until its terminal callback.
        // Retirement is the deliberate exception: all streams and delegate
        // delivery end here, so no callback remains for this scanner to service
        // and releasing its entire ownership graph is the intended outcome.
        retainedPeripherals.removeAll()
        cancellingPeripherals.removeAll()

        // Stop all future delegate delivery before the owning scanner releases
        // its final reference to this central manager.
        central.delegate = nil
    }
}

struct SensorScannerNGConnectOptions {
    static func merging(
        _ configuredOptions: [String: Any]?,
        enableAutoReconnect: Bool
    ) -> [String: Any]? {
        var options = configuredOptions ?? [:]
        if enableAutoReconnect {
            options[CBConnectPeripheralOptionEnableAutoReconnect] = true
        }
        return options.isEmpty ? nil : options
    }
}

struct SensorScannerNGRetirementDecision: Equatable {
    let shouldRetire: Bool
    let shouldIssueCentralCommands: Bool
}

struct SensorScannerNGRetirementState {
    private(set) var isRetired = false

    mutating func begin(centralState: CBManagerState) -> SensorScannerNGRetirementDecision {
        guard !isRetired else {
            return SensorScannerNGRetirementDecision(
                shouldRetire: false,
                shouldIssueCentralCommands: false
            )
        }
        isRetired = true
        return SensorScannerNGRetirementDecision(
            shouldRetire: true,
            shouldIssueCentralCommands: centralState == .poweredOn
        )
    }
}

// MARK: - CBCentralManagerDelegate

extension SensorScannerNG: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        emit(.stateChanged(central.state))
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let advSummary = advertisementData.reduce(into: [String: String]()) { acc, kv in
            acc[kv.key] = String(describing: kv.value)
        }
        let advertisedServices = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let discovered = DiscoveredSensor(
            id: peripheral.identifier,
            name: peripheral.name ?? (advertisementData[CBAdvertisementDataLocalNameKey] as? String),
            rssi: RSSI.intValue,
            advertisedServices: advertisedServices,
            advertisementData: advSummary,
            peripheral: peripheral
        )
        emit(.didDiscover(discovered))
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        emit(.didConnect(peripheral))
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        releaseIfCancelling(peripheral)
        emit(.didFailToConnect(peripheral, error: error))
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        timestamp: CFAbsoluteTime,
        isReconnecting: Bool,
        error: Error?
    ) {
        emitDisconnect(
            peripheral,
            error: error,
            timestamp: timestamp,
            isReconnecting: isReconnecting
        )
    }

    /// Terminal callback for a peripheral we intentionally cancelled: the
    /// cancellation handoff is complete, so drop the retained strong ref now.
    /// An unexpected disconnect (not marked cancelling) is left retained -- it's
    /// still a reconnect candidate. Runs on centralQueue (a CB delegate callback).
    private func releaseIfCancelling(_ peripheral: CBPeripheral) {
        if cancellingPeripherals.remove(peripheral.identifier) != nil {
            retainedPeripherals[peripheral.identifier] = nil
        }
    }

    #if os(iOS)
    public func centralManager(
        _ central: CBCentralManager,
        connectionEventDidOccur event: CBConnectionEvent,
        for peripheral: CBPeripheral
    ) {
        emit(.connectionEvent(event, peripheral: peripheral))
    }
    #endif

    public func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        guard !retirementState.isRetired else { return }
        let peripherals = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral]) ?? []
        // Retain the restored peripherals immediately (this delegate call is on
        // centralQueue). iOS hands them back connected, but if we don't hold a
        // strong ref they deallocate and the restored connection is torn down
        // before the reconnect can use it. (Mirrors G7's handleDiscoveredPeripheral
        // retaining each restored peripheral in managedPeripherals.)
        for peripheral in peripherals {
            retainedPeripherals[peripheral.identifier] = peripheral
        }
        let scanServices = (dict[CBCentralManagerRestoredStateScanServicesKey] as? [CBUUID]) ?? []
        let scanOptions = (dict[CBCentralManagerRestoredStateScanOptionsKey] as? [String: Any]) ?? [:]
        let event = SensorRestorationEvent(
            peripherals: peripherals,
            scanServices: scanServices,
            scanOptions: scanOptions.reduce(into: [String: String]()) { out, item in
                out[item.key] = String(describing: item.value)
            }
        )
        // willRestoreState fires before consumers can subscribe; buffer
        // until the first subscription of either event API, then replay.
        if eventSubscribers.isEmpty {
            pendingRestorationEvents.append(event)
        } else {
            emit(.willRestoreState(event))
        }
    }
}
