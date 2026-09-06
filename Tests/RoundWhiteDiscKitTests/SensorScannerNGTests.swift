import CoreBluetooth
import XCTest
@testable import RoundWhiteDiscKit

final class SensorScannerNGTests: XCTestCase {
    func testConnectOptionsLeaveDefaultBehaviorUnchangedWhenAutoReconnectIsDisabled() {
        XCTAssertNil(
            SensorScannerNGConnectOptions.merging(
                nil,
                enableAutoReconnect: false
            )
        )

        let configured: [String: Any] = [
            CBConnectPeripheralOptionNotifyOnDisconnectionKey: true
        ]
        let options = SensorScannerNGConnectOptions.merging(
            configured,
            enableAutoReconnect: false
        )

        XCTAssertEqual(options?.count, 1)
        XCTAssertEqual(
            options?[CBConnectPeripheralOptionNotifyOnDisconnectionKey] as? Bool,
            true
        )
        XCTAssertNil(options?[CBConnectPeripheralOptionEnableAutoReconnect])
    }

    func testConnectOptionsMergeAutoReconnectWithoutDiscardingConfiguredOptions() {
        let configured: [String: Any] = [
            CBConnectPeripheralOptionNotifyOnConnectionKey: true
        ]
        let options = SensorScannerNGConnectOptions.merging(
            configured,
            enableAutoReconnect: true
        )

        XCTAssertEqual(options?.count, 2)
        XCTAssertEqual(
            options?[CBConnectPeripheralOptionNotifyOnConnectionKey] as? Bool,
            true
        )
        XCTAssertEqual(
            options?[CBConnectPeripheralOptionEnableAutoReconnect] as? Bool,
            true
        )
    }

    func testDisconnectMetadataPreservesTimestampAndReconnectState() {
        let timestamp: CFAbsoluteTime = 812_345_678.25
        let metadata = SensorScannerNG.DisconnectMetadata(
            timestamp: timestamp,
            isReconnecting: true
        )

        XCTAssertEqual(metadata.timestamp, timestamp)
        XCTAssertTrue(metadata.isReconnecting)
    }

    func testEventSubscribersDeliverLegacyPayloadAndContextualMetadataOnce() async {
        let legacy = AsyncStream<SensorScannerNG.Event>.makeStream()
        let contextual = AsyncStream<SensorScannerNG.ContextualEvent>.makeStream()
        let metadata = SensorScannerNG.DisconnectMetadata(
            timestamp: 812_345_678.25,
            isReconnecting: true
        )
        let contextualEvent = SensorScannerNG.ContextualEvent(
            event: .stateChanged(.poweredOff),
            disconnectMetadata: metadata
        )

        let legacySubscriber = SensorScannerNG.EventSubscriber.legacy(legacy.continuation)
        legacySubscriber.yield(contextualEvent)
        legacySubscriber.finish()
        let contextualSubscriber = SensorScannerNG.EventSubscriber.contextual(contextual.continuation)
        contextualSubscriber.yield(contextualEvent)
        contextualSubscriber.finish()

        var legacyIterator = legacy.stream.makeAsyncIterator()
        var contextualIterator = contextual.stream.makeAsyncIterator()
        let legacyEvent = await legacyIterator.next()
        let secondLegacyEvent = await legacyIterator.next()
        let deliveredContextualEvent = await contextualIterator.next()
        let secondContextualEvent = await contextualIterator.next()

        guard case .stateChanged(.poweredOff)? = legacyEvent else {
            return XCTFail("Legacy subscriber did not receive the unchanged event")
        }
        XCTAssertNil(secondLegacyEvent)
        guard case .stateChanged(.poweredOff)? = deliveredContextualEvent?.event else {
            return XCTFail("Contextual subscriber did not receive the unchanged event")
        }
        XCTAssertEqual(deliveredContextualEvent?.disconnectMetadata, metadata)
        XCTAssertNil(secondContextualEvent)
    }

    func testRetirementIsIdempotentAndSkipsCentralCommandsWhenPoweredOff() {
        var state = SensorScannerNGRetirementState()

        XCTAssertEqual(
            state.begin(centralState: .poweredOff),
            SensorScannerNGRetirementDecision(
                shouldRetire: true,
                shouldIssueCentralCommands: false
            )
        )
        XCTAssertTrue(state.isRetired)
        XCTAssertEqual(
            state.begin(centralState: .poweredOn),
            SensorScannerNGRetirementDecision(
                shouldRetire: false,
                shouldIssueCentralCommands: false
            )
        )
    }

    func testRetirementAllowsCentralCleanupOnlyWhenPoweredOn() {
        var state = SensorScannerNGRetirementState()

        XCTAssertEqual(
            state.begin(centralState: .poweredOn),
            SensorScannerNGRetirementDecision(
                shouldRetire: true,
                shouldIssueCentralCommands: true
            )
        )
    }

    func testRetirementFinishesExistingAndLateSubscribersOfBothAPIs() async {
        let scanner = SensorScannerNG()
        var legacyIterator = scanner.events().makeAsyncIterator()
        var contextualIterator = scanner.eventsWithContext().makeAsyncIterator()

        let initialLegacyEvent = await legacyIterator.next()
        let initialContextualEvent = await contextualIterator.next()
        XCTAssertNotNil(initialLegacyEvent)
        XCTAssertNotNil(initialContextualEvent)

        await scanner.retire()
        await scanner.retire()
        XCTAssertTrue(scanner.isRetired)

        while await legacyIterator.next() != nil {}
        while await contextualIterator.next() != nil {}

        var lateLegacyIterator = scanner.events().makeAsyncIterator()
        var lateContextualIterator = scanner.eventsWithContext().makeAsyncIterator()
        let lateLegacyEvent = await lateLegacyIterator.next()
        let lateContextualEvent = await lateContextualIterator.next()

        XCTAssertNil(lateLegacyEvent)
        XCTAssertNil(lateContextualEvent)
    }
}
