# RoundWhiteDiscKit

> [!CAUTION]
> **This project is NOT from Abbott.** RoundWhiteDiscKit is an independent,
> community-developed project. It is **not** made, affiliated with, endorsed,
> sponsored, reviewed, or supported by Abbott Laboratories, Abbott Diabetes Care,
> or any of their affiliates. Do not contact Abbott about this software.
>
> FreeStyle Libre, Libre, and related names and marks are trademarks of Abbott;
> they are used here only to identify the sensors this software interoperates with.
> This software is experimental, is not a medical device, and is not approved or
> cleared by any regulator. Do not use it for treatment decisions. See [NOTICE.md](NOTICE.md).

RoundWhiteDiscKit is the clean-room Swift package for Libre 3 pairing, BLE transport,
authorization, sensor recovery, and post-auth data-plane decoding. It is built
as a reusable foundation for any iOS app that wants to integrate a Libre
sensor. The standalone `Apps/RoundWhiteDisc` app is the live-device harness around
this package.

This repo contains:

- `Package.swift`: the reusable `RoundWhiteDiscKit` Swift package.
- `Sources/RoundWhiteDiscKit`: BLE, NFC activation, pairing, crypto, persistence, and
  data-plane code.
- `Apps/RoundWhiteDisc`: an iOS PoC app that exercises pairing, state persistence,
  reconnect, backfill, and decoded realtime glucose/status display.
- `protocol.md`: a protocol-level summary of the NFC, BLE, authorization, and
  data-plane behavior currently modeled by the package.

The public app does not ship captured per-sensor state. Local files such as
`Libre3PatchContext.xml` and `Libre3SensorState.json` are ignored.

## Pairing Setup

Pairing uses plain P-256 identities and standard AES-CCM. The package no longer
requires a runtime-table blob or an installation call.

The optional identity file lives at
`Sources/RoundWhiteDiscKit/Resources/RWDKAppIdentities.json` and is copied into
the package resource bundle when supplied. It is git-ignored for now. Keep its
private keys and certificate contents out of logs, documentation, and tests.

The JSON format has three top-level fields:

| Field | Value |
| --- | --- |
| `format` | `1` |
| `curve` | `"P-256"` |
| `identities` | Array of identity entries |

Each entry contains `label` (String), `productType` (UInt8), `securityVersion`
(UInt16), `regions` (array of UInt8), `default` (Bool), `privateKeyHex` (32-byte
big-endian P-256 private scalar), and `certificateHex` (162-byte phone
certificate). Hex strings must be nonempty, even-length hexadecimal without
whitespace; either letter case is accepted. Loading checks that each private
key matches its certificate's public key and that each product/security-version
group has exactly one default.

`Libre3PairingIdentities.bundled()` loads the file or throws
`identityFileMissing` if it is absent. Apps may instead use
`Libre3PairingIdentities(jsonData:)` or construct validated entries from their
own identities. Synthetic tests do not require the real file; the bundled-file
test skips when it is missing.

### Identity Selection And Full Authorization

NFC patch info exposes `productType`, `securityVersion`, and the raw `region`
byte. Selection first finds the product/security-version group, then an explicit
region match, otherwise that group's default. Unknown and unlisted regions are
preserved and use the default. An unsupported group throws `noIdentity`.
The package selects one identity and does not retry with another.

Given parsed `patchInfo` and a loaded registry:

```swift
let entry = try identities.identity(
    productType: patchInfo.productType,
    securityVersion: patchInfo.securityVersion,
    region: patchInfo.region
)
```

The returned entry includes `label` for logging which identity the sensor
accepts. Create a new `PairingFlow` with `entry.identity.phoneCert` for each full
authorization so it uses a fresh ephemeral keypair, then call
`runCommandGatedAuthorizationHandshake(blePIN:identity:)` with `entry.identity`
and the NFC BLE PIN. This full flow is also used for saved-state authorization.

The Phase 5 key is the first 16 bytes of:

```text
SHA-256(00 00 00 01 || ECDH(phone_ephemeral, sensor_ephemeral)
                     || ECDH(phone_static, sensor_static))
```

Both ECDH inputs are 32-byte big-endian shared secrets. The order is fixed,
with no additional KDF input. Phase 5 and Phase 6 use this key with standard
AES-CCM and verify the echoed R1/R2 before accepting session material.

For package validation, run `swift build` and `swift test` on a supported Apple
platform.

## Current Library Boundary

The package currently owns:

- NFC activation payload construction and response parsing.
- Receiver identity generation, display, and recovery parsing
  (`Libre3ReceiverID`).
- BLE scanning, connecting, GATT discovery, notification subscription, writes,
  reads, CoreBluetooth restoration hooks, and iOS connection-event registration
  (`SensorScanner`, `SensorSession`).
- First-pair authorization primitives through Phase 6, including standard
  ECDSA-P256(SHA-256) verification of the sensor certificate with bundled
  Abbott patch-signing public keys.
- Post-auth data-plane framing, CCM decrypt, `patchStatus`, and realtime
  `glucoseData` parsing.
- Lifecycle and backfill helpers: `SensorLifecycle`, raw quality evidence,
  `Libre3GlucoseQualityAssessment`,
  `Libre3DataPlaneState`,
  `PatchControlCommand.backfillGreaterEqual`, `HistoricalReadingPage`,
  `HistoricalBackfill` coverage/gap summaries, clinical-data records, factory
  data command access, and bounded reconnect backfill command planning from the
  last accepted glucose life count.
- Persistence bridges between `Libre3SensorState` and `Libre3DataPlaneState`
  for seeding reconnect backfill after app relaunch.

An integrating app should own:

- User-facing pairing and recovery workflows.
- Persistence in app settings, keychain, cloud/device backup, or other durable
  state chosen by the app.
- Conversion from `RealtimeGlucoseReading` into the app's glucose sample model.
- Connection state policy, retry cadence, and UI error state.
- Background launch orchestration from app lifecycle callbacks.
- Protocol conformance and conversion into the app's own glucose sample types.

## Recovery Metadata

A Libre 3 receiver ID is the 4-byte value placed into the NFC activation/switch
payload as:

```text
timestamp_LE || receiverID_LE || abbott_crc16
```

The sensor-facing value is the receiver ID itself. A LibreView account is not a
protocol requirement for the observed first-pair and active-sensor recovery
paths.

Apps that support sensor recovery should persist and expose at least:

- `receiverID` as 4-byte little-endian hex.
- Sensor serial number.
- BLE address returned by NFC.
- Latest BLE PIN returned by NFC.
- `productType`, `securityVersion`, and raw `region` from NFC patch info, for
  identity selection on a later reconnect.
- Sensor start / lifecycle metadata once the remaining fields are named.

`Libre3SensorState` persists the three selection fields as optional values.
Older JSON files still load with them absent; scan NFC again to obtain missing
metadata. Sensors paired with the old `03 03` identity also need a new NFC scan
before authorizing with the selected plain identity.

If a user loses the original phone, a new install can accept the saved
`receiverID` before scanning the active sensor. Active-sensor recovery then uses
the switch-receiver NFC command and the normal BLE authorization flow.

### Account-Derived Receiver IDs

Abbott ships two phone apps that pair Libre 3 sensors, and both derive the
receiver ID from the same LibreView Account ID but fold it differently. A sensor
answers a later `0xA0`/`0xA8` carrying a receiver ID other than the one it was
activated with using NFC error `0xB1`, so an app that mirrors an Abbott account
must use the fold belonging to the app that activated the sensor:

```swift
let receiverID = Libre3ReceiverID(accountID: accountID, derivation: .libreByAbbott)
```

`.freeStyleLibre3` is the classic "FreeStyle Libre 3" app and applies the same
fold as `accountlessValue(from:)`. `.libreByAbbott` is the newer US "Libre by
Abbott" app. There is no default: the caller has to know which app activated the
sensor. Both entry points lowercase the account ID, which is a no-op for the
dashed UUID LibreView issues; `accountlessValue(from:)` and
`init(accountlessUniqueID:)` still fold their argument byte for byte.

An app that activates sensors itself needs neither fold — any stable 4-byte
value works as its own receiver identity, and a LibreView account remains
outside the protocol paths this package models.

## Data Quality

Each `RealtimeGlucoseReading` carries the sensor's own quality channels (data
quality error, sensor condition, displayable-range status, and actionability).
`currentGlucoseQualityAssessment(lifecycle:)` folds these into a
`Libre3GlucoseQualityAssessment` with an overall `isUsable` flag plus the
contributing `issues`.

Issues are split into two classes:

- Blocking issues suppress the reading: sensor warmup, expiry, a data-quality
  error, an unavailable/out-of-range value, or an abnormal sensor condition.
  These clear `isUsable` and are exposed via `blockingIssues`.
- Advisory issues are surfaced for visibility but do not suppress the reading.
  Currently the only advisory is `notActionable`, exposed via `advisories`.

Actionability (bit 3 of the realtime status byte) is intentionally advisory.
A non-actionable reading can still carry a displayable glucose value. A reading
whose other quality channels are clean therefore stays usable even when the
sensor reports it as non-actionable. Integrating apps that want stricter
behavior can inspect `reading.actionability` or the `advisories` list directly.

## Sensor End States

`PatchStatus.sensorError` separates normal end-of-wear from shutdown:
`errorData == 5` is `.expired`, while `6` and `8` are `.terminated`.
Expired sensors may still advertise over BLE; terminated is the
shutdown/end-session state. `PatchStatus` also exposes patch-state helpers for
known state groups: active (`4`), expired/error handling (`3`, `5`, `7`), and
already terminated (`6`, `8`).

Apps that need to notify users quickly should use
`PatchStatus.sensorAttention` or `Libre3DataPlaneState.latestSensorAttention`
instead of reimplementing Abbott's UI mapping. Current compatibility evidence
maps `errorData == 3` to `.checkSensor`, `5`/`6` to `.sensorEnded`, and
`7`/`8` to `.replaceSensor`; `shouldNotifyReplaceSensor` is true for the
replace-sensor cases. Code 7 is named `.transmissionError` at the raw
sensor-error layer, but Abbott's Android app sets its replace-sensor UI flag
for that code. The recovered Android alarm alert payload does not expose that
flag directly, so clients should treat `sensorAttention` as RoundWhiteDiscKit's stable
notification-routing surface and keep the raw fields for logging.

`PatchControlCommand.shutdownPatch()` builds the terminal shutdown command
`05 00 00 00 00 00 00`. It is not needed for routine disconnect, reconnect, or
bounded backfill.

## Standalone POC Exercise App

The `Apps/RoundWhiteDisc` NFC tab is currently the live-device harness for the public
integration surface. It uses product-facing "pairing" language:

- Initial pairing: a new sensor that accepts activation/switch NFC and BLE
  authorization with the current receiver ID.
- Sensor recovery pairing: a post-A8 active sensor that accepts the known saved
  receiver ID, then completes BLE authorization and resumes realtime data.

The harness now displays decoded `glucoseData` and `patchStatus`, persists
`Libre3SensorState.json`, records the last realtime glucose life count/value for
bounded reconnect backfill, can reconnect from that saved state, exposes an
explicit BLE disconnect button, registers CoreBluetooth connection-event wake
hooks, keeps a model-owned post-auth listener alive after the initial bootstrap,
and records scene/restoration/connection lifecycle events in-app. Temperature is
shown as the currently grounded raw field (`tempRaw`) until its unit/calibration
is confirmed.

The app has not yet been migrated to the plain pairing API and does not build
with the current package.

## Background Lifecycle Behavior

The four live-device behaviors that the library is shaped around have been
exercised end-to-end in real use:

- Background while connected: minute-spaced `glucoseData` notifications wake
  the app and are decrypted from the locked/backgrounded state.
- iOS termination restoration: `willRestoreState` delivers the peripheral and
  subscribed characteristics after system-driven termination.
- Disconnect recovery: registered connection events wake the app on reconnect
  or service match.
- Long idle run: locked-phone sessions sustain sample continuity against the
  sensor's history/backfill channel.

The library still deliberately exposes low-level hooks rather than owning a
finished CGM lifecycle policy, because the host app's connection-state policy,
retry cadence, persistence, and UI belong in the integrating app.

## Minute-Resolution Gap-Fill

Two backfill channels exist, with different resolution and cadence:

- Paged historical backfill (`HistoricalReadingPage` /
  `PatchControlCommand.backfillGreaterEqual`) commits only at 5-minute
  boundaries and lags the current life count by ~17 minutes.
- The clinical stream (`ClinicalReadingRecord`, char `0x08981ab8`) emits one
  per-minute record while connected. Its current-minute glucose
  (`currentGlucose`, decoded from word[5]) is keyed at the record's own
  `lifeCount` with no offset. The sensor buffers these records while the host
  is disconnected and replays the buffered window in a burst on resubscribe —
  field testing has seen 38+ contiguous per-minute records arrive within
  seconds of reconnect after a multi-tens-of-minutes outage.

The clinical stream is therefore the only published way to recover
*minute-resolution* glucose across a disconnect window. Apps that care about
gap-fill should subscribe to the clinical CCCD and forward `currentGlucose`
keyed at `lifeCount`, deduping against samples already received from the
realtime stream.

`historicGlucoseRaw` (word[6]) is the same 5-minute committed value the
realtime frame carries as its embedded historical and should not be keyed at
the clinical record's own `lifeCount`. When only a clinical record is in hand,
`historicLifeCountEstimate` snaps to the last 5-minute boundary at
`lifeCount − 17`; when the realtime frame is available, prefer its
authoritative `historicalLifeCount`.

## Reconnect Authorization Scope

After a sensor is initially paired and saved, an app can skip onboarding, avoid
repeating NFC activation/switch unless the saved state is missing, seed
`Libre3DataPlaneState` from the saved last glucose point, and request bounded
backfill instead of draining all available history.

The package exposes two reconnect shapes:

- Cached/direct reconnect: `0x11 StartAuthorization`, R1/nonce notify, Phase 5
  write, `0x08 SendChallengeLoadDone`, then `0843` + Phase 6. RoundWhiteDiscKit exposes
  this as `runCachedReconnectPreamble` and `runCachedReconnectHandshake`.
  The handshake takes `tail4` (the saved BLE PIN) and the plain `phase5Key`
  returned by the most recent successful full authorization.
- Full fallback authorization: certificate exchange, ephemeral exchange,
  `StartAuthorization`, Phase 5, and Phase 6. RoundWhiteDiscKit exposes this as
  `runCommandGatedAuthorizationPreamble` and
  `runCommandGatedAuthorizationHandshake(blePIN:identity:)`.

The Phase 5 key includes ephemeral ECDH, so it changes with each full
authorization. After every successful full authorization, store
`result.phase5Key` in the app's Keychain for that sensor, replacing the previous
key. Do not put it in JSON sensor state. If the sensor accepts cached reconnect,
only the key from the most recent full authorization can be valid.

Acceptance of the plain key on the cached path is not yet confirmed on a live
sensor. When a saved key is available, try the cached path; if it fails, fall
back to full authorization. Without a saved key, use full authorization directly.

## License

RoundWhiteDiscKit is available under the MIT License. See [LICENSE](LICENSE).
