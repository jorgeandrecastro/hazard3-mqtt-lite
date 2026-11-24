# Changelog

Notable changes to `hazard3-mqtt-lite` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Renamed the package to `hazard3-mqtt-lite` and the Rust crate to
  `hazard3_mqtt_lite` for [Hazard3](https://github.com/jorgeandrecastro/Hazard3).
- Translated the documentation into English and made the examples independent
  of a particular network stack or executor.

## [0.4.0] - 2026-10-20

### Added

- **TLS 1.3** via the `tls` feature (`tls` module, based on `embedded-tls`
  0.19): the server certificate is always verified, including the chain to a
  pinned CA, signature and hostname.
  - `tls::connect_with_clock`: also verifies validity dates using a `TlsClock`.
  - `tls::connect_ignoring_dates`: for devices without a clock; only the dates
    are unchecked.
  - `tls::TlsBuffers`, `tls::TlsSettings` and `tls::TlsConnectError` (with
    `is_certificate_error()`).
  - Invalid settings (empty server name, PEM CA) are rejected before I/O.
- `tls-p384` and `tls-ed25519` features for ECDSA P-384 and Ed25519
  certificate chains; ECDSA P-256 is always supported.
- `MqttClient::disconnect()`: sends DISCONNECT for a clean shutdown without
  publishing the Last Will.
- `MqttClient::publish_retained()`: publishes with the RETAIN flag.
- `MqttError::ConnectionClosed`, `MqttError::InvalidTopic` and
  `MqttError::InvalidOptions` error variants.
- Topic validation: publish names cannot contain wildcards or NUL and cannot
  be empty; subscription filters follow the specification's `+` and `#` rules.
- Mock transport tests (`embassy-futures` as a development dependency):
  55 tests in total, up from 15.

### Changed

- **Breaking**: `MqttError` is now `#[non_exhaustive]`; exhaustive matches
  must include a `_` arm.
- **Breaking**: transport read errors are no longer converted to
  `ConnackInvalid`, `PingFailed`, `SubackInvalid` or `UnexpectedPacket`.
  End of stream returns `ConnectionClosed`; a transport error returns `Io(e)`.
- Each send is followed by a transport `flush()`, required for buffered TLS writes.
- PUBLISH payloads are sent directly from the caller's buffer without copying.
  `MAX_PACKET_SIZE` limits only headers (client ID, credentials, Last Will and topic).
- CONNACK is validated strictly, including the reserved flag byte and return code.
- SUBACK is validated strictly: packet ID, length and return code (`0x00..=0x02`
  accepted, `0x80` refused, all other codes invalid).
- `subscribe()` ignores up to eight unrelated packets, such as PINGRESP,
  received before SUBACK.
- `connect_with_options()` rejects passwords without usernames (`InvalidOptions`)
  and validates the Last Will topic.
- Remaining Length is limited to four bytes, as required by the specification.
- Code is split into `packet.rs` (pure codec), `lib.rs` (client) and `tls.rs` (TLS).
- Added `embedded-tls` as an optional dependency.

### Fixed

- `receive()`: a PUBLISH larger than the supplied buffer previously left the
  stream out of sync. The message is now fully read and discarded,
  `PacketTooLarge` is returned, and the connection remains usable.

## [0.3.0]

### Added

- Subscription (SUBSCRIBE / SUBACK) and receipt of incoming PUBLISH messages
  via `subscribe()` and `receive()`.

## Earlier versions

- MQTT 3.1.1 CONNECT / CONNACK with Clean Session, username/password
  authentication and Last Will and Testament.
- QoS 0 publishing.
- Keep-alive with PINGREQ / PINGRESP.
- `no_std` client without dynamic allocation, independent of the transport
  (`embedded_io_async::Read + Write`).


