# hazard3-mqtt-lite
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20or%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![no_std](https://img.shields.io/badge/no__std-yes-success.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

A minimal, asynchronous, transport-independent **MQTT v3.1.1** client for
[Hazard3](https://github.com/jorgeandrecastro/Hazard3), with optional **TLS 1.3**
and server certificate verification against a pinned CA.

The client is `no_std`, requires no dynamic allocation, and does not impose a
network stack or executor. Any transport implementing `embedded_io_async::Read + Write`
can be used, including TCP, TLS and serial streams.

## Features

- MQTT 3.1.1 CONNECT/CONNACK with Clean Session
- Username/password authentication and Last Will and Testament
- Keep-alive with PINGREQ/PINGRESP and clean shutdown with DISCONNECT
- QoS 0 publishing, with or without RETAIN
- Subscription with SUBSCRIBE/SUBACK and incoming PUBLISH messages
- Optional TLS 1.3 with certificate chain, signature and hostname verification
- No dynamic allocation; publish payloads are sent without copying
- Topic name and subscription filter validation
- Minimal dependencies: `embedded-io-async`, plus `embedded-tls` when TLS is enabled

## Limitations

- Only QoS 0 is supported for both incoming and outgoing messages.
- Only one subscription is active per `MqttClient` instance, with no internal
  multiplexing. Use separate connections to publish and listen concurrently.
- TLS supports only TLS 1.3 with `TLS_AES_128_GCM_SHA256`; client certificates
  and RSA certificate chains are not supported.

## Installation
How to  use:

```toml
[dependencies]
hazard3-mqtt-lite =  "0.5"

# Or, with TLS 1.3:
# hazard3-mqtt-lite = { version = "0.5", features = ["tls"] }
```

| Feature | Effect |
|---------|--------|
| `tls` | TLS 1.3 with a pinned CA and ECDSA P-256 |
| `tls-p384` | `tls` plus ECDSA P-384 certificate chains |
| `tls-ed25519` | `tls` plus Ed25519 certificate chains |

## Publishing

Connect the transport to the broker before passing it to the client:

```rust
use embedded_io_async::{Read, Write};
use hazard3_mqtt_lite::{MqttClient, MqttError};

async fn publish_example<T: Read + Write>(transport: &mut T) -> Result<(), MqttError<T::Error>> {
    let mut client = MqttClient::new(transport);
    client.connect("hazard3-client", 60).await?;
    client.publish("home/living-room/temperature", b"21.5").await?;
    client.disconnect().await
}
```

For authentication and a retained Last Will, use `connect_with_options`:

```rust
use embedded_io_async::{Read, Write};
use hazard3_mqtt_lite::{ConnectOptions, LastWill, MqttClient, MqttError};

async fn publish_with_options<T: Read + Write>(
    transport: &mut T,
) -> Result<(), MqttError<T::Error>> {
    let mut client = MqttClient::new(transport);
    let options = ConnectOptions {
        username: Some("user"),
        password: Some(b"password"),
        last_will: Some(LastWill {
            topic: "sensors/status",
            message: b"offline",
            retain: true,
        }),
    };
    client.connect_with_options("hazard3-sensor", 60, &options).await?;
    client.publish_retained("sensors/status", b"online").await?;
    client.disconnect().await
}
```

A password requires a username. When there is no other activity, call `ping()`
before the negotiated keep-alive interval expires.

## Subscribing

```rust
use embedded_io_async::{Read, Write};
use hazard3_mqtt_lite::{MqttClient, MqttError};

async fn receive_one<T: Read + Write>(transport: &mut T) -> Result<(), MqttError<T::Error>> {
    let mut client = MqttClient::new(transport);
    client.connect("hazard3-subscriber", 60).await?;
    client.subscribe("home/command").await?;

    let mut buffer = [0u8; 256];
    let message = client.receive(&mut buffer).await?;
    // Process message.topic and message.payload before reusing buffer.
    let _ = message;
    client.disconnect().await
}
```

An incoming message larger than the supplied buffer is fully discarded and
`MqttError::PacketTooLarge` is returned; the stream remains synchronized.
Use distinct client IDs for separate publishing and subscribing connections.
Do not call `ping()` while `receive()` is pending on the same connection:
`receive()` consumes PINGRESP packets itself.

## TLS 1.3

Enable the `tls` feature to wrap an existing transport in a TLS session before
passing it to `MqttClient`. The server certificate chain, signature and hostname
are always verified. Invalid settings are rejected before I/O.

The broker must present a certificate signed by a trusted CA in **DER** format:

```bash
openssl x509 -in ca.pem -outform DER -out ca.der
```

`TlsSettings::server_name` must appear in the broker certificate's DNS SAN or CN.
Place `TlsBuffers` in static storage, for example with `static_cell`, because
the default buffers require approximately 32 KiB.

```rust,ignore
use hazard3_mqtt_lite::{tls, MqttClient};
use static_cell::StaticCell;

static TLS_BUFFERS: StaticCell<tls::TlsBuffers> = StaticCell::new();
static CA: &[u8] = include_bytes!("../certs/ca.der");

// `socket` is an already-connected transport; `rng` is a cryptographic RNG.
let buffers = TLS_BUFFERS.init(tls::TlsBuffers::new());
let settings = tls::TlsSettings {
    server_name: "broker.home.lan",
    ca_der: CA,
};
let mut session = tls::connect_ignoring_dates(&mut socket, buffers, &settings, rng).await?;
let mut client = MqttClient::new(&mut session);
client.connect("hazard3-client", 60).await?;
client.publish("sensors/temperature", b"21.5").await?;
client.disconnect().await?;
session.close().await?; // Sends close_notify.
```

`connect_ignoring_dates` explicitly skips certificate validity dates; the
chain, signature and hostname are still verified. If the device knows the time,
implement `TlsClock` and use `connect_with_clock` instead:

```rust,ignore
struct Clock;
impl tls::TlsClock for Clock {
    fn now() -> Option<u64> {
        Some(/* seconds since the Unix epoch */ 0)
    }
}

let session = tls::connect_with_clock::<_, _, Clock, 2048, { tls::TLS_RECORD_SIZE }>(
    &mut socket, buffers, &settings, rng,
).await?;
```

- A private ECDSA P-256 CA is a suitable choice for a self-hosted broker. RSA
  chains, including Let's Encrypt, are not supported without an allocator.
- `rng` must be cryptographically secure, such as a hardware TRNG.
- A certificate larger than `CERT_SIZE` fails the handshake with `TlsError::OutOfMemory`.
- The default 16,640-byte read buffer accommodates any TLS record. Reduce it
  only if the broker's behavior is known.
- Transport errors are returned as `MqttError::Io(TlsError)`.

## How it works

- `packet.rs`: pure packet construction and parsing, testable on the host.
- `lib.rs`: client and I/O; each send is followed by a flush, required for TLS.
- `tls.rs`: optional TLS 1.3 session and server verification using `embedded-tls`.

Packet headers use a fixed-size buffer (`MAX_PACKET_SIZE`, 256 bytes by default,
adjustable in the source), limiting client IDs, credentials, Last Will and topic
lengths. A PUBLISH payload is sent directly from the caller's buffer and is not
limited by this size.

## Error handling

Except for `PacketTooLarge` returned by `receive()`, treat every error as fatal
to the connection: close the transport and reconnect.

| Error | Meaning |
|-------|---------|
| `Io(e)` | Transport error |
| `ConnectionClosed` | The peer closed the stream |
| `PacketTooLarge` | Header or incoming message exceeds the available buffer |
| `InvalidTopic` | Invalid topic name or filter |
| `InvalidOptions` | Password without username |
| `ConnackInvalid` | Invalid CONNACK |
| `ConnectionRefused(code)` | Broker refused the connection |
| `PingFailed` | Invalid PINGREQ response |
| `SubackInvalid` / `SubscribeFailed` | Invalid SUBACK / subscription refused |
| `UnexpectedPacket` | Unexpected or malformed incoming packet |

`MqttError` is `#[non_exhaustive]`; include a wildcard arm in matches.

## Minimum Rust version

Rust **1.85** or later, using edition 2024.

## Tests

```bash
cargo test
cargo test --features tls
```

## Changelog and contributions

See [CHANGELOG.md](CHANGELOG.md) for release history. Issues and pull requests
are welcome in the [repository](https://github.com/jorgeandrecastro/embassy-mqtt-lite).

## 🛡️ License

Licensed under either of:

    MIT license (http://opensource.org/licenses/MIT)

    Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## 🦅 About

Developed by Jorge Andre Castro.