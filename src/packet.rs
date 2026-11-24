//! MQTT v3.1.1 packet encoding and decoding: pure functions without I/O.
//!
//! This module can be tested on the host without a transport or runtime.

/// Maximum size in bytes of a packet header built by this crate
/// (complete CONNECT, SUBSCRIBE, or PUBLISH header and topic).
///
/// A PUBLISH **payload** is sent directly to the transport, not copied into
/// this buffer, so its size is not limited by this constant.
/// Increase it for very long client IDs, topics or credentials.
pub const MAX_PACKET_SIZE: usize = 256;

/// Largest encodable Remaining Length (4 bytes, MQTT 3.1.1 section 2.2.3).
pub const MAX_REMAINING_LENGTH: usize = 268_435_455;

/// Complete PINGREQ packet.
pub(crate) const PINGREQ: [u8; 2] = [0xC0, 0x00];
/// Expected PINGRESP packet.
pub(crate) const PINGRESP: [u8; 2] = [0xD0, 0x00];
/// Complete DISCONNECT packet.
pub(crate) const DISCONNECT: [u8; 2] = [0xE0, 0x00];

/// Packet construction error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// The packet exceeds `MAX_PACKET_SIZE` (or `MAX_REMAINING_LENGTH`).
    TooLarge,
    /// Invalid topic name or filter (empty, NUL, misplaced wildcard, etc.).
    InvalidTopic,
    /// Combination forbidden by the specification (password without username).
    InvalidOptions,
}

/// Optional connection settings: authentication and Last Will.
#[derive(Default)]
pub struct ConnectOptions<'a> {
    pub username: Option<&'a str>,
    pub password: Option<&'a [u8]>,
    pub last_will: Option<LastWill<'a>>,
}

/// Message automatically published by the broker after an abnormal connection loss
/// (crash, power failure, keep-alive timeout).
pub struct LastWill<'a> {
    pub topic: &'a str,
    pub message: &'a [u8],
    pub retain: bool,
}

/// Message received from the broker on a subscribed topic.
pub struct IncomingMessage<'buf> {
    pub topic: &'buf str,
    pub payload: &'buf [u8],
}

/// Fixed-size packet construction buffer without dynamic allocation.
pub(crate) struct PacketBuilder {
    buf: [u8; MAX_PACKET_SIZE],
    len: usize,
}

impl PacketBuilder {
    pub(crate) fn new() -> Self {
        Self {
            buf: [0u8; MAX_PACKET_SIZE],
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn push(&mut self, byte: u8) -> Result<(), BuildError> {
        if self.len >= MAX_PACKET_SIZE {
            return Err(BuildError::TooLarge);
        }
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Result<(), BuildError> {
        if self.len + bytes.len() > MAX_PACKET_SIZE {
            return Err(BuildError::TooLarge);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Encodes the MQTT Remaining Length in variable-length format.
pub(crate) fn encode_remaining_length(
    mut len: usize,
    out: &mut PacketBuilder,
) -> Result<(), BuildError> {
    if len > MAX_REMAINING_LENGTH {
        return Err(BuildError::TooLarge);
    }
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte)?;
        if len == 0 {
            break;
        }
    }
    Ok(())
}

/// Adds an MQTT UTF-8 string or binary data field with a two-byte length prefix.
pub(crate) fn push_string_field(builder: &mut PacketBuilder, s: &[u8]) -> Result<(), BuildError> {
    let len = u16::try_from(s.len()).map_err(|_| BuildError::TooLarge)?;
    builder.extend(&len.to_be_bytes())?;
    builder.extend(s)
}

/// A PUBLISH topic name: nonempty, without NUL or wildcards (section 4.7.3).
pub(crate) fn validate_topic_name(topic: &str) -> Result<(), BuildError> {
    if topic.is_empty() || topic.bytes().any(|b| matches!(b, 0 | b'+' | b'#')) {
        return Err(BuildError::InvalidTopic);
    }
    Ok(())
}

/// A SUBSCRIBE filter: `+` occupies a whole level, `#` the final level (section 4.7.1).
pub(crate) fn validate_topic_filter(filter: &str) -> Result<(), BuildError> {
    let b = filter.as_bytes();
    if b.is_empty() || b.contains(&0) {
        return Err(BuildError::InvalidTopic);
    }
    for (i, &c) in b.iter().enumerate() {
        let prev_ok = i == 0 || b[i - 1] == b'/';
        match c {
            b'#' if !(prev_ok && i + 1 == b.len()) => return Err(BuildError::InvalidTopic),
            b'+' if !(prev_ok && (i + 1 == b.len() || b[i + 1] == b'/')) => {
                return Err(BuildError::InvalidTopic)
            }
            _ => {}
        }
    }
    Ok(())
}

/// Builds a CONNECT packet (Clean Session), without I/O.
pub(crate) fn build_connect(
    client_id: &str,
    keep_alive_secs: u16,
    options: &ConnectOptions<'_>,
) -> Result<PacketBuilder, BuildError> {
    // MQTT 3.1.1 §3.1.2.9 : pas de mot de passe sans nom d'utilisateur.
    if options.password.is_some() && options.username.is_none() {
        return Err(BuildError::InvalidOptions);
    }

    let mut variable_header = PacketBuilder::new();
    variable_header.extend(&[0x00, 0x04])?;
    variable_header.extend(b"MQTT")?;
    variable_header.push(0x04)?; // niveau de protocole 3.1.1

    let mut flags: u8 = 0x02; // Clean Session
    if let Some(will) = &options.last_will {
        flags |= 0x04;
        if will.retain {
            flags |= 0x20;
        }
    }
    if options.username.is_some() {
        flags |= 0x80;
    }
    if options.password.is_some() {
        flags |= 0x40;
    }
    variable_header.push(flags)?;
    variable_header.extend(&keep_alive_secs.to_be_bytes())?;

    let mut payload = PacketBuilder::new();
    push_string_field(&mut payload, client_id.as_bytes())?;
    if let Some(will) = &options.last_will {
        validate_topic_name(will.topic)?;
        push_string_field(&mut payload, will.topic.as_bytes())?;
        push_string_field(&mut payload, will.message)?;
    }
    if let Some(username) = options.username {
        push_string_field(&mut payload, username.as_bytes())?;
    }
    if let Some(password) = options.password {
        push_string_field(&mut payload, password)?;
    }

    let mut packet = PacketBuilder::new();
    packet.push(0x10)?;
    encode_remaining_length(variable_header.len() + payload.len(), &mut packet)?;
    packet.extend(variable_header.as_slice())?;
    packet.extend(payload.as_slice())?;
    Ok(packet)
}

/// Builds a QoS 0 PUBLISH header (fixed byte, remaining length and topic).
///
/// The payload is deliberately **not** included: the caller sends it immediately
/// afterwards directly from its own buffer, without copying or a buffer size limit.
pub(crate) fn build_publish_header(
    topic: &str,
    payload_len: usize,
    retain: bool,
) -> Result<PacketBuilder, BuildError> {
    validate_topic_name(topic)?;
    let mut packet = PacketBuilder::new();
    packet.push(0x30 | u8::from(retain))?; // PUBLISH, QoS 0, DUP = 0
    encode_remaining_length(2 + topic.len() + payload_len, &mut packet)?;
    push_string_field(&mut packet, topic.as_bytes())?;
    Ok(packet)
}

/// Builds a QoS 0 SUBSCRIBE packet, without I/O.
pub(crate) fn build_subscribe_packet(
    topic: &str,
    packet_id: u16,
) -> Result<PacketBuilder, BuildError> {
    validate_topic_filter(topic)?;

    let mut variable_header = PacketBuilder::new();
    variable_header.extend(&packet_id.to_be_bytes())?;

    let mut payload = PacketBuilder::new();
    push_string_field(&mut payload, topic.as_bytes())?;
    payload.push(0x00)?; // QoS 0 demandé

    let mut packet = PacketBuilder::new();
    packet.push(0x82)?; // SUBSCRIBE (flags fixes = 0010)
    encode_remaining_length(variable_header.len() + payload.len(), &mut packet)?;
    packet.extend(variable_header.as_slice())?;
    packet.extend(payload.as_slice())?;
    Ok(packet)
}

/// Result of parsing a CONNACK.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnackResult {
    Accepted,
    Refused(u8),
    Invalid,
}

/// Parses a four-byte CONNACK, without I/O.
pub(crate) fn parse_connack(p: &[u8; 4]) -> ConnackResult {
    // Octet 2 : bit 0 = Session Present, bits 1-7 réservés à 0.
    if p[0] != 0x20 || p[1] != 0x02 || p[2] & 0xFE != 0 {
        return ConnackResult::Invalid;
    }
    match p[3] {
        0x00 => ConnackResult::Accepted,
        code => ConnackResult::Refused(code),
    }
}

/// Result of parsing a SUBACK packet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SubackResult {
    Accepted,
    Refused,
    Invalid,
}

/// Parses an in-memory SUBACK (one subscription), without I/O.
pub(crate) fn parse_suback(header_byte: u8, body: &[u8], expected_id: u16) -> SubackResult {
    if header_byte != 0x90 || body.len() != 3 {
        return SubackResult::Invalid;
    }
    if u16::from_be_bytes([body[0], body[1]]) != expected_id {
        return SubackResult::Invalid;
    }
    match body[2] {
        0x00..=0x02 => SubackResult::Accepted,
        0x80 => SubackResult::Refused,
        _ => SubackResult::Invalid,
    }
}

/// Computes the topic length and payload offset of an in-memory PUBLISH,
/// without I/O.
pub(crate) fn publish_layout(header_byte: u8, buf: &[u8]) -> Result<(usize, usize), ()> {
    if buf.len() < 2 {
        return Err(());
    }
    let topic_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let qos = (header_byte >> 1) & 0x03;
    let mut payload_start = 2 + topic_len;
    if qos > 0 {
        payload_start += 2; // Packet Identifier (QoS 1/2)
    }
    if payload_start > buf.len() {
        return Err(());
    }
    Ok((topic_len, payload_start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_length_zero() {
        let mut b = PacketBuilder::new();
        encode_remaining_length(0, &mut b).unwrap();
        assert_eq!(b.as_slice(), &[0x00]);
    }

    #[test]
    fn remaining_length_single_byte_max() {
        let mut b = PacketBuilder::new();
        encode_remaining_length(127, &mut b).unwrap();
        assert_eq!(b.as_slice(), &[0x7F]);
    }

    #[test]
    fn remaining_length_two_bytes() {
        let mut b = PacketBuilder::new();
        encode_remaining_length(200, &mut b).unwrap();
        assert_eq!(b.as_slice(), &[0xC8, 0x01]);
    }

    #[test]
    fn remaining_length_three_bytes() {
        let mut b = PacketBuilder::new();
        encode_remaining_length(16384, &mut b).unwrap();
        assert_eq!(b.as_slice(), &[0x80, 0x80, 0x01]);
    }

    #[test]
    fn remaining_length_four_bytes_max() {
        let mut b = PacketBuilder::new();
        encode_remaining_length(MAX_REMAINING_LENGTH, &mut b).unwrap();
        assert_eq!(b.as_slice(), &[0xFF, 0xFF, 0xFF, 0x7F]);
    }

    #[test]
    fn remaining_length_rejects_above_max() {
        let mut b = PacketBuilder::new();
        assert_eq!(
            encode_remaining_length(MAX_REMAINING_LENGTH + 1, &mut b),
            Err(BuildError::TooLarge)
        );
    }

    #[test]
    fn string_field_encoding() {
        let mut b = PacketBuilder::new();
        push_string_field(&mut b, b"MQTT").unwrap();
        assert_eq!(b.as_slice(), &[0x00, 0x04, b'M', b'Q', b'T', b'T']);
    }

    #[test]
    fn packet_builder_rejects_overflow() {
        let mut b = PacketBuilder::new();
        let big = [0u8; MAX_PACKET_SIZE + 1];
        assert!(b.extend(&big).is_err());
    }

    #[test]
    fn topic_name_validation() {
        assert!(validate_topic_name("home/clim").is_ok());
        assert_eq!(validate_topic_name(""), Err(BuildError::InvalidTopic));
        assert_eq!(validate_topic_name("home/+"), Err(BuildError::InvalidTopic));
        assert_eq!(validate_topic_name("home/#"), Err(BuildError::InvalidTopic));
        assert_eq!(validate_topic_name("a\0b"), Err(BuildError::InvalidTopic));
    }

    #[test]
    fn topic_filter_validation() {
        for ok in ["a/b", "a/+/c", "+", "#", "a/#", "+/+", "/", "a//b"] {
            assert!(validate_topic_filter(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a#", "a/#/b", "a+", "+a", "a/b+", "#/a", "a\0"] {
            assert_eq!(validate_topic_filter(bad), Err(BuildError::InvalidTopic), "{bad}");
        }
    }

    #[test]
    fn connect_minimal() {
        let p = build_connect("id", 60, &ConnectOptions::default()).unwrap();
        assert_eq!(
            p.as_slice(),
            &[
                0x10, 0x0E, // CONNECT, remaining length = 14
                0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, // protocole
                0x02, // Clean Session
                0x00, 0x3C, // keep-alive = 60
                0x00, 0x02, b'i', b'd', // client id
            ]
        );
    }

    #[test]
    fn connect_with_auth_and_will() {
        let opts = ConnectOptions {
            username: Some("u"),
            password: Some(b"p"),
            last_will: Some(LastWill {
                topic: "s",
                message: b"off",
                retain: true,
            }),
        };
        let p = build_connect("c", 30, &opts).unwrap();
        let s = p.as_slice();
        assert_eq!(s[0], 0x10);
        // flags : username(0x80) | password(0x40) | will retain(0x20) | will(0x04) | clean(0x02)
        assert_eq!(s[9], 0xE6);
        // payload : id, will topic, will msg, user, pass
        assert_eq!(
            &s[12..],
            &[
                0x00, 0x01, b'c', 0x00, 0x01, b's', 0x00, 0x03, b'o', b'f', b'f', 0x00, 0x01,
                b'u', 0x00, 0x01, b'p'
            ]
        );
    }

    #[test]
    fn connect_rejects_password_without_username() {
        let opts = ConnectOptions {
            password: Some(b"p"),
            ..Default::default()
        };
        assert_eq!(
            build_connect("c", 60, &opts).err(),
            Some(BuildError::InvalidOptions)
        );
    }

    #[test]
    fn connect_rejects_invalid_will_topic() {
        let opts = ConnectOptions {
            last_will: Some(LastWill {
                topic: "a/#",
                message: b"x",
                retain: false,
            }),
            ..Default::default()
        };
        assert_eq!(
            build_connect("c", 60, &opts).err(),
            Some(BuildError::InvalidTopic)
        );
    }

    #[test]
    fn publish_header_has_no_payload_but_counts_it() {
        let h = build_publish_header("a/b", 5, false).unwrap();
        // remaining = 2 + 3 + 5 = 10
        assert_eq!(h.as_slice(), &[0x30, 0x0A, 0x00, 0x03, b'a', b'/', b'b']);
    }

    #[test]
    fn publish_header_retain_bit() {
        let h = build_publish_header("t", 0, true).unwrap();
        assert_eq!(h.as_slice()[0], 0x31);
    }

    #[test]
    fn publish_header_accepts_large_payload_length() {
        let h = build_publish_header("t", 100_000, false).unwrap();
        assert_eq!(&h.as_slice()[..4], &[0x30, 0xA3, 0x8D, 0x06]); // 100003
    }

    #[test]
    fn publish_header_rejects_wildcard_topic() {
        assert_eq!(
            build_publish_header("a/+", 0, false).err(),
            Some(BuildError::InvalidTopic)
        );
    }

    #[test]
    fn subscribe_packet_encoding() {
        let packet = build_subscribe_packet("home/clim", 1).unwrap();
        let expected = [
            0x82, 0x0E, // SUBSCRIBE, remaining length = 14
            0x00, 0x01, // Packet Identifier = 1
            0x00, 0x09, b'h', b'o', b'm', b'e', b'/', b'c', b'l', b'i', b'm', // Topic Filter
            0x00, // QoS demandé = 0
        ];
        assert_eq!(packet.as_slice(), &expected);
    }

    #[test]
    fn subscribe_rejects_bad_filter() {
        assert_eq!(
            build_subscribe_packet("a#", 1).err(),
            Some(BuildError::InvalidTopic)
        );
    }

    #[test]
    fn connack_accepted_and_session_present() {
        assert_eq!(parse_connack(&[0x20, 0x02, 0x00, 0x00]), ConnackResult::Accepted);
        assert_eq!(parse_connack(&[0x20, 0x02, 0x01, 0x00]), ConnackResult::Accepted);
    }

    #[test]
    fn connack_refused_and_invalid() {
        assert_eq!(parse_connack(&[0x20, 0x02, 0x00, 0x05]), ConnackResult::Refused(5));
        assert_eq!(parse_connack(&[0x30, 0x02, 0x00, 0x00]), ConnackResult::Invalid);
        assert_eq!(parse_connack(&[0x20, 0x03, 0x00, 0x00]), ConnackResult::Invalid);
        assert_eq!(parse_connack(&[0x20, 0x02, 0x02, 0x00]), ConnackResult::Invalid);
    }

    #[test]
    fn suback_accepted() {
        let body = [0x00, 0x01, 0x00]; // packet id + return code 0 (QoS0 accordé)
        assert_eq!(parse_suback(0x90, &body, 1), SubackResult::Accepted);
    }

    #[test]
    fn suback_refused() {
        let body = [0x00, 0x01, 0x80];
        assert_eq!(parse_suback(0x90, &body, 1), SubackResult::Refused);
    }

    #[test]
    fn suback_wrong_header_type() {
        let body = [0x00, 0x01, 0x00];
        assert_eq!(parse_suback(0x20, &body, 1), SubackResult::Invalid); // pas un SUBACK
    }

    #[test]
    fn suback_body_wrong_length() {
        assert_eq!(parse_suback(0x90, &[0x00, 0x01], 1), SubackResult::Invalid);
        assert_eq!(parse_suback(0x90, &[0x00, 0x01, 0x00, 0x00], 1), SubackResult::Invalid);
    }

    #[test]
    fn suback_wrong_packet_id() {
        assert_eq!(parse_suback(0x90, &[0x00, 0x02, 0x00], 1), SubackResult::Invalid);
    }

    #[test]
    fn suback_unknown_return_code() {
        assert_eq!(parse_suback(0x90, &[0x00, 0x01, 0x42], 1), SubackResult::Invalid);
    }

    #[test]
    fn publish_layout_qos0() {
        let buf = [0x00, 0x03, b'a', b'/', b'b', b'h', b'i'];
        let (topic_len, payload_start) = publish_layout(0x30, &buf).unwrap();
        assert_eq!(topic_len, 3);
        assert_eq!(payload_start, 5);
        assert_eq!(&buf[payload_start..], b"hi");
    }

    #[test]
    fn publish_layout_qos1_skips_packet_identifier() {
        let buf = [0x00, 0x03, b'a', b'/', b'b', 0x00, 0x2A, b'h', b'i'];
        let (topic_len, payload_start) = publish_layout(0x32, &buf).unwrap();
        assert_eq!(topic_len, 3);
        assert_eq!(payload_start, 7);
        assert_eq!(&buf[payload_start..], b"hi");
    }

    #[test]
    fn publish_layout_rejects_truncated_buffer() {
        let buf = [0x00, 0x05, b'a', b'b']; // annonce topic_len=5 mais buffer trop court
        assert!(publish_layout(0x30, &buf).is_err());
    }
}