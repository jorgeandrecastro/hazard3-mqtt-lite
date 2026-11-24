#![no_std]

//! Minimal asynchronous `no_std` MQTT v3.1.1 client.
//!
//! Supports QoS 0 (fire-and-forget), username/password authentication,
//! Last Will and Testament, keep-alive via PINGREQ, subscriptions (`SUBSCRIBE`)
//! and incoming messages (`PUBLISH`). Works with any transport implementing
//! `embedded_io_async::Read + Write` (TCP, TLS, serial, etc.).
//!
//! # Organisation
//!
//! - `packet`: pure packet codec, testable on the host.
//! - `lib.rs` (this file): [`MqttClient`] and [`MqttError`], the I/O layer.
//! - `tls` (feature `tls`): TLS 1.3 with server certificate verification
//!   against a pinned CA.

use embedded_io_async::{Read, ReadExactError, Write};

mod packet;
#[cfg(feature = "tls")]
pub mod tls;

pub use packet::{
    ConnectOptions, IncomingMessage, LastWill, MAX_PACKET_SIZE, MAX_REMAINING_LENGTH,
};

use packet::{
    build_connect, build_publish_header, build_subscribe_packet, parse_connack, parse_suback,
    publish_layout, BuildError, ConnackResult, SubackResult, DISCONNECT, PINGREQ, PINGRESP,
};

/// Errors that may occur when using the MQTT client.
///
/// Except for [`PacketTooLarge`](MqttError::PacketTooLarge) returned by
/// [`receive`](MqttClient::receive), treat every error as fatal to the connection:
/// close the transport and reconnect.
#[derive(Debug)]
#[non_exhaustive]
pub enum MqttError<E> {
    /// Transport error (TCP, TLS, etc.).
    Io(E),
    /// The peer closed the transport (unexpected end of stream).
    ConnectionClosed,
    /// The outgoing or received packet exceeds the available size.
    PacketTooLarge,
    /// Invalid topic name or filter (empty, NUL character, misplaced wildcard, etc.).
    InvalidTopic,
    /// Invalid connection options (password without username).
    InvalidOptions,
    /// The broker did not respond with a valid CONNACK.
    ConnackInvalid,
    /// The broker refused the connection (nonzero CONNACK return code).
    ConnectionRefused(u8),
    /// The PINGREQ response is not a valid PINGRESP.
    PingFailed,
    /// The received SUBACK is invalid or malformed.
    SubackInvalid,
    /// The broker refused the subscription (SUBACK return code 0x80).
    SubscribeFailed,
    /// Unexpected or malformed incoming packet.
    UnexpectedPacket,
}

impl<E> From<E> for MqttError<E> {
    fn from(e: E) -> Self {
        MqttError::Io(e)
    }
}

/// Converts a packet construction error (`From` would conflict with
/// `From<E> for MqttError<E>`).
fn build_err<E>(e: BuildError) -> MqttError<E> {
    match e {
        BuildError::TooLarge => MqttError::PacketTooLarge,
        BuildError::InvalidTopic => MqttError::InvalidTopic,
        BuildError::InvalidOptions => MqttError::InvalidOptions,
    }
}

/// Distinguishes end of stream (`ConnectionClosed`) from a transport error.
fn read_err<E>(e: ReadExactError<E>) -> MqttError<E> {
    match e {
        ReadExactError::UnexpectedEof => MqttError::ConnectionClosed,
        ReadExactError::Other(e) => MqttError::Io(e),
    }
}

/// Minimal MQTT client using a caller-provided `Read + Write` transport.
pub struct MqttClient<'a, T: Read + Write> {
    transport: &'a mut T,
    packet_id: u16,
}

impl<'a, T: Read + Write> MqttClient<'a, T> {
    /// Creates a client around an already connected transport (TCP socket, TLS session, etc.).
    pub fn new(transport: &'a mut T) -> Self {
        Self {
            transport,
            packet_id: 1,
        }
    }

    /// Sends several chunks and then **flushes** the transport.
    ///
    /// Flushing is essential with TLS: `embedded-tls` buffers writes and only
    /// encrypts and sends the record on `flush`.
    async fn send(&mut self, parts: &[&[u8]]) -> Result<(), MqttError<T::Error>> {
        for part in parts {
            self.transport.write_all(part).await?;
        }
        self.transport.flush().await?;
        Ok(())
    }

    /// Sends CONNECT (Clean Session) and waits for CONNACK.
    /// This simple version uses neither authentication nor a Last Will.
    pub async fn connect(
        &mut self,
        client_id: &str,
        keep_alive_secs: u16,
    ) -> Result<(), MqttError<T::Error>> {
        self.connect_with_options(client_id, keep_alive_secs, &ConnectOptions::default())
            .await
    }

    /// Sends CONNECT with options (authentication, Last Will) and waits for CONNACK.
    pub async fn connect_with_options(
        &mut self,
        client_id: &str,
        keep_alive_secs: u16,
        options: &ConnectOptions<'_>,
    ) -> Result<(), MqttError<T::Error>> {
        let packet = build_connect(client_id, keep_alive_secs, options).map_err(build_err)?;
        self.send(&[packet.as_slice()]).await?;

        let mut connack = [0u8; 4];
        self.transport
            .read_exact(&mut connack)
            .await
            .map_err(read_err)?;

        match parse_connack(&connack) {
            ConnackResult::Accepted => Ok(()),
            ConnackResult::Refused(code) => Err(MqttError::ConnectionRefused(code)),
            ConnackResult::Invalid => Err(MqttError::ConnackInvalid),
        }
    }

    /// Publishes a QoS 0 message (fire-and-forget) to the given topic.
    ///
    /// The payload is sent directly from `payload` without copying; its size is
    /// not limited by [`MAX_PACKET_SIZE`].
    pub async fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), MqttError<T::Error>> {
        self.publish_inner(topic, payload, false).await
    }

    /// Like [`publish`](Self::publish), with RETAIN: the broker stores the message
    /// and delivers it to future subscribers (typically an `online` status).
    pub async fn publish_retained(
        &mut self,
        topic: &str,
        payload: &[u8],
    ) -> Result<(), MqttError<T::Error>> {
        self.publish_inner(topic, payload, true).await
    }

    async fn publish_inner(
        &mut self,
        topic: &str,
        payload: &[u8],
        retain: bool,
    ) -> Result<(), MqttError<T::Error>> {
        let header = build_publish_header(topic, payload.len(), retain).map_err(build_err)?;
        self.send(&[header.as_slice(), payload]).await
    }

    /// Sends a PINGREQ and waits for the corresponding PINGRESP.
    ///
    /// Call periodically before the `keep_alive_secs` negotiated at `connect`
    /// expires if there is no other activity (PUBLISH) on the connection, so
    /// the broker does not consider the client dead.
    ///
    /// Do not call while [`receive`](Self::receive) is pending on the same
    /// connection: [`receive`](Self::receive) consumes PINGRESP packets itself.
    pub async fn ping(&mut self) -> Result<(), MqttError<T::Error>> {
        self.send(&[&PINGREQ]).await?;

        let mut pingresp = [0u8; 2];
        self.transport
            .read_exact(&mut pingresp)
            .await
            .map_err(read_err)?;

        if pingresp != PINGRESP {
            return Err(MqttError::PingFailed);
        }
        Ok(())
    }

    /// Sends DISCONNECT for a clean shutdown; the broker does **not** publish the Last Will.
    ///
    /// Then close the transport yourself (with TLS: `tls.close().await`, which sends
    /// the `close_notify` alert).
    pub async fn disconnect(&mut self) -> Result<(), MqttError<T::Error>> {
        self.send(&[&DISCONNECT]).await
    }

    /// Reads a Remaining Length from the network (inverse of `encode_remaining_length`).
    async fn read_remaining_length(&mut self) -> Result<usize, MqttError<T::Error>> {
        let mut multiplier: usize = 1;
        let mut value: usize = 0;
        for _ in 0..4 {
            let mut byte = [0u8; 1];
            self.transport
                .read_exact(&mut byte)
                .await
                .map_err(read_err)?;
            value += ((byte[0] & 0x7F) as usize) * multiplier;
            if byte[0] & 0x80 == 0 {
                return Ok(value);
            }
            multiplier *= 128;
        }
        // 4 octets de continuation : encodage invalide (§2.2.3).
        Err(MqttError::UnexpectedPacket)
    }

    /// Reads and discards `n` bytes to remain synchronized with the stream.
    async fn discard(&mut self, mut n: usize) -> Result<(), MqttError<T::Error>> {
        let mut scratch = [0u8; 32];
        while n > 0 {
            let chunk = n.min(scratch.len());
            self.transport
                .read_exact(&mut scratch[..chunk])
                .await
                .map_err(read_err)?;
            n -= chunk;
        }
        Ok(())
    }

    /// Subscribes to a topic with QoS 0 and waits for SUBACK.
    ///
    /// Other packets received in the meantime (PINGRESP, etc.) are ignored.
    pub async fn subscribe(&mut self, topic: &str) -> Result<(), MqttError<T::Error>> {
        let packet_id = self.packet_id.wrapping_add(1).max(1);
        let packet = build_subscribe_packet(topic, packet_id).map_err(build_err)?;
        self.packet_id = packet_id;
        self.send(&[packet.as_slice()]).await?;

        // Quelques paquets parasites tolérés, pas une boucle infinie.
        for _ in 0..8 {
            let mut header = [0u8; 1];
            self.transport
                .read_exact(&mut header)
                .await
                .map_err(read_err)?;
            let remaining_len = self.read_remaining_length().await?;

            if header[0] != 0x90 {
                self.discard(remaining_len).await?;
                continue;
            }
            if remaining_len != 3 {
                return Err(MqttError::SubackInvalid);
            }
            let mut body = [0u8; 3];
            self.transport
                .read_exact(&mut body)
                .await
                .map_err(read_err)?;

            return match parse_suback(header[0], &body, packet_id) {
                SubackResult::Accepted => Ok(()),
                SubackResult::Refused => Err(MqttError::SubscribeFailed),
                SubackResult::Invalid => Err(MqttError::SubackInvalid),
            };
        }
        Err(MqttError::SubackInvalid)
    }

    /// Waits for and returns the next PUBLISH message from the broker.
    ///
    /// Other packets (PINGRESP, etc.) are silently consumed.
    ///
    /// If a PUBLISH exceeds `buf`, it is **fully read and discarded**, then
    /// [`MqttError::PacketTooLarge`] is returned. The stream remains synchronized
    /// and `receive` can be called again on the same connection.
    pub async fn receive<'buf>(
        &mut self,
        buf: &'buf mut [u8],
    ) -> Result<IncomingMessage<'buf>, MqttError<T::Error>> {
        loop {
            let mut header = [0u8; 1];
            self.transport
                .read_exact(&mut header)
                .await
                .map_err(read_err)?;
            let packet_type = header[0] & 0xF0;
            let remaining_len = self.read_remaining_length().await?;

            if remaining_len > buf.len() {
                self.discard(remaining_len).await?;
                if packet_type == 0x30 {
                    return Err(MqttError::PacketTooLarge);
                }
                continue;
            }

            self.transport
                .read_exact(&mut buf[..remaining_len])
                .await
                .map_err(read_err)?;

            if packet_type != 0x30 {
                continue; // Pas un PUBLISH (ex: PINGRESP) : paquet suivant
            }

            let (topic_len, payload_start) = publish_layout(header[0], &buf[..remaining_len])
                .map_err(|_| MqttError::UnexpectedPacket)?;

            let (topic_and_rest, payload_part) = buf[..remaining_len].split_at(payload_start);
            let topic_bytes = &topic_and_rest[2..2 + topic_len];
            let topic =
                core::str::from_utf8(topic_bytes).map_err(|_| MqttError::UnexpectedPacket)?;

            return Ok(IncomingMessage {
                topic,
                payload: payload_part,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::convert::Infallible;
    use embassy_futures::block_on;
    use embedded_io_async::ErrorType;
    use std::vec::Vec;

    /// Mock transport: `rx` contains broker bytes, `tx` contains client writes.
    struct Mock {
        rx: Vec<u8>,
        pos: usize,
        tx: Vec<u8>,
        flushes: usize,
    }

    impl Mock {
        fn new(rx: &[u8]) -> Self {
            Self {
                rx: rx.to_vec(),
                pos: 0,
                tx: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl ErrorType for Mock {
        type Error = Infallible;
    }

    impl Read for Mock {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let n = buf.len().min(self.rx.len() - self.pos);
            buf[..n].copy_from_slice(&self.rx[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n) // 0 = fin de flux
        }
    }

    impl Write for Mock {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.tx.extend_from_slice(buf);
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.flushes += 1;
            Ok(())
        }
    }

    const CONNACK_OK: [u8; 4] = [0x20, 0x02, 0x00, 0x00];

    #[test]
    fn connect_ok_flushes_and_sends_connect() {
        let mut m = Mock::new(&CONNACK_OK);
        block_on(MqttClient::new(&mut m).connect("id", 60)).unwrap();
        assert_eq!(m.tx[0], 0x10);
        assert_eq!(m.flushes, 1);
    }

    #[test]
    fn connect_refused_reports_code() {
        let mut m = Mock::new(&[0x20, 0x02, 0x00, 0x05]);
        let r = block_on(MqttClient::new(&mut m).connect("id", 60));
        assert!(matches!(r, Err(MqttError::ConnectionRefused(5))));
    }

    #[test]
    fn connect_invalid_connack() {
        let mut m = Mock::new(&[0x30, 0x02, 0x00, 0x00]);
        let r = block_on(MqttClient::new(&mut m).connect("id", 60));
        assert!(matches!(r, Err(MqttError::ConnackInvalid)));
    }

    #[test]
    fn connect_eof_is_connection_closed() {
        let mut m = Mock::new(&[0x20, 0x02]);
        let r = block_on(MqttClient::new(&mut m).connect("id", 60));
        assert!(matches!(r, Err(MqttError::ConnectionClosed)));
    }

    #[test]
    fn connect_rejects_password_without_username() {
        let mut m = Mock::new(&[]);
        let opts = ConnectOptions {
            password: Some(b"p"),
            ..Default::default()
        };
        let r = block_on(MqttClient::new(&mut m).connect_with_options("id", 60, &opts));
        assert!(matches!(r, Err(MqttError::InvalidOptions)));
        assert!(m.tx.is_empty()); // rien n'a été envoyé
    }

    #[test]
    fn publish_sends_header_then_payload_and_flushes() {
        let mut m = Mock::new(&[]);
        block_on(MqttClient::new(&mut m).publish("a/b", b"hi")).unwrap();
        assert_eq!(m.tx, [0x30, 0x07, 0x00, 0x03, b'a', b'/', b'b', b'h', b'i']);
        assert_eq!(m.flushes, 1);
    }

    #[test]
    fn publish_payload_larger_than_max_packet_size() {
        let payload = std::vec![0xAB_u8; 1000];
        let mut m = Mock::new(&[]);
        block_on(MqttClient::new(&mut m).publish("t", &payload)).unwrap();
        // 0x30, remaining = 2 + 1 + 1000 = 1003 -> [0xEB, 0x07]
        assert_eq!(&m.tx[..6], &[0x30, 0xEB, 0x07, 0x00, 0x01, b't']);
        assert_eq!(m.tx.len(), 6 + 1000);
        assert!(m.tx[6..].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn publish_retained_sets_bit() {
        let mut m = Mock::new(&[]);
        block_on(MqttClient::new(&mut m).publish_retained("t", b"x")).unwrap();
        assert_eq!(m.tx[0], 0x31);
    }

    #[test]
    fn publish_rejects_wildcard_topic_without_sending() {
        let mut m = Mock::new(&[]);
        let r = block_on(MqttClient::new(&mut m).publish("a/#", b"x"));
        assert!(matches!(r, Err(MqttError::InvalidTopic)));
        assert!(m.tx.is_empty());
    }

    #[test]
    fn ping_ok_and_bad_response() {
        let mut m = Mock::new(&PINGRESP);
        block_on(MqttClient::new(&mut m).ping()).unwrap();
        assert_eq!(m.tx, PINGREQ);

        let mut m = Mock::new(&[0xD0, 0x01]);
        let r = block_on(MqttClient::new(&mut m).ping());
        assert!(matches!(r, Err(MqttError::PingFailed)));
    }

    #[test]
    fn disconnect_sends_e0_00() {
        let mut m = Mock::new(&[]);
        block_on(MqttClient::new(&mut m).disconnect()).unwrap();
        assert_eq!(m.tx, [0xE0, 0x00]);
        assert_eq!(m.flushes, 1);
    }

    #[test]
    fn subscribe_ok_skips_stray_pingresp() {
        // packet id du premier subscribe = 2 (1 + 1)
        let mut m = Mock::new(&[0xD0, 0x00, 0x90, 0x03, 0x00, 0x02, 0x00]);
        block_on(MqttClient::new(&mut m).subscribe("a/b")).unwrap();
        assert_eq!(m.tx[0], 0x82);
    }

    #[test]
    fn subscribe_refused() {
        let mut m = Mock::new(&[0x90, 0x03, 0x00, 0x02, 0x80]);
        let r = block_on(MqttClient::new(&mut m).subscribe("a/b"));
        assert!(matches!(r, Err(MqttError::SubscribeFailed)));
    }

    #[test]
    fn subscribe_wrong_packet_id() {
        let mut m = Mock::new(&[0x90, 0x03, 0x00, 0x09, 0x00]);
        let r = block_on(MqttClient::new(&mut m).subscribe("a/b"));
        assert!(matches!(r, Err(MqttError::SubackInvalid)));
    }

    #[test]
    fn subscribe_rejects_invalid_filter() {
        let mut m = Mock::new(&[]);
        let r = block_on(MqttClient::new(&mut m).subscribe("a#"));
        assert!(matches!(r, Err(MqttError::InvalidTopic)));
        assert!(m.tx.is_empty());
    }

    #[test]
    fn receive_returns_publish_and_skips_pingresp() {
        let mut m = Mock::new(&[
            0xD0, 0x00, // PINGRESP ignoré
            0x30, 0x07, 0x00, 0x03, b'a', b'/', b'b', b'h', b'i',
        ]);
        let mut buf = [0u8; 32];
        let msg = block_on(MqttClient::new(&mut m).receive(&mut buf)).unwrap();
        assert_eq!(msg.topic, "a/b");
        assert_eq!(msg.payload, b"hi");
    }

    #[test]
    fn receive_oversized_publish_keeps_stream_in_sync() {
        let mut rx = std::vec![0x30, 0x2A, 0x00, 0x01, b't']; // remaining = 42
        rx.extend(core::iter::repeat(0x55).take(39)); // payload de 39 octets
        rx.extend_from_slice(&[0x30, 0x05, 0x00, 0x01, b't', b'o', b'k']);
        let mut m = Mock::new(&rx);
        let mut buf = [0u8; 16];

        let mut client = MqttClient::new(&mut m);
        let first = block_on(client.receive(&mut buf));
        assert!(matches!(first, Err(MqttError::PacketTooLarge)));

        let second = block_on(client.receive(&mut buf)).unwrap();
        assert_eq!(second.topic, "t");
        assert_eq!(second.payload, b"ok");
    }

    #[test]
    fn receive_eof_is_connection_closed() {
        let mut m = Mock::new(&[]);
        let mut buf = [0u8; 8];
        let r = block_on(MqttClient::new(&mut m).receive(&mut buf));
        assert!(matches!(r, Err(MqttError::ConnectionClosed)));
    }

    #[test]
    fn receive_rejects_endless_remaining_length() {
        let mut m = Mock::new(&[0x30, 0x80, 0x80, 0x80, 0x80, 0x01]);
        let mut buf = [0u8; 8];
        let r = block_on(MqttClient::new(&mut m).receive(&mut buf));
        assert!(matches!(r, Err(MqttError::UnexpectedPacket)));
    }

    #[test]
    fn receive_rejects_invalid_utf8_topic() {
        let mut m = Mock::new(&[0x30, 0x04, 0x00, 0x02, 0xFF, 0xFE]);
        let mut buf = [0u8; 8];
        let r = block_on(MqttClient::new(&mut m).receive(&mut buf));
        assert!(matches!(r, Err(MqttError::UnexpectedPacket)));
    }
}