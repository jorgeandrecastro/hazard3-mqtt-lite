//! TLS 1.3 for [`MqttClient`](crate::MqttClient) (feature `tls`).
//!
//! Uses [`embedded-tls`](https://crates.io/crates/embedded-tls) (TLS 1.3, `no_std`,
//! no allocator) with `rustpki` certificate verification. This layer guarantees:
//!
//! - **the server certificate is always verified**: chain to the supplied pinned CA,
//!   `CertificateVerify` signature, and **hostname** (DNS SAN / CN). There is no
//!   mode that disables verification;
//! - validity dates are checked with a clock ([`connect_with_clock`]) or
//!   explicitly ignored ([`connect_ignoring_dates`]);
//! - TLS records use [`TlsBuffers`], which should be placed in a `static` (`StaticCell`);
//! - the transport remains yours: pass `&mut socket` to reuse it for reconnection.
//!
//! # Usage
//!
//! ```ignore
//! use hazard3_mqtt_lite::{tls, MqttClient};
//! use static_cell::StaticCell;
//!
//! static TLS_BUFFERS: StaticCell<tls::TlsBuffers> = StaticCell::new();
//! // Broker CA in DER format (not PEM): openssl x509 -in ca.pem -outform DER -out ca.der
//! static CA: &[u8] = include_bytes!("../certs/ca.der");
//!
//! let buffers = TLS_BUFFERS.init(tls::TlsBuffers::new());
//! let settings = tls::TlsSettings { server_name: "broker.maison.lan", ca_der: CA };
//!
//! let mut tls = tls::connect_ignoring_dates(&mut socket, buffers, &settings, rng).await?;
//! let mut mqtt = MqttClient::new(&mut tls);
//! mqtt.connect("esp32-salon", 60).await?;
//! mqtt.publish("capteurs/salon/temperature", b"21.5").await?;
//! mqtt.disconnect().await?;
//! tls.close().await.ok(); // sends close_notify
//! ```
//!
//! # Constraints
//!
//! - **A private or pinned CA is recommended.** The `no_std` verifier supports ECDSA P-256,
//!   P-384 (feature `tls-p384`) and Ed25519 (feature `tls-ed25519`). RSA chains, including
//!   Let's Encrypt, are not supported without an allocator. For a self-hosted broker,
//!   generate a P-256 CA and server certificate.
//! - The hostname must be a **DNS name** present in the certificate's SAN (or CN).
//! - Chain certificates must fit in `CERT_SIZE` bytes (2048 by default). A larger
//!   certificate causes the handshake to fail with `TlsError::OutOfMemory`.
//! - TLS 1.3 only, with `TLS_AES_128_GCM_SHA256` (mandatory in RFC 8446).
//!   Mosquitto 1.6 or later with OpenSSL 1.1.1 or later is suitable.
//! - The network stack must use `embedded-io-async` 0.7.
//! - The random number generator (`rng`) must be **cryptographic** (a hardware TRNG),
//!   not a deterministic PRNG.

use embedded_io_async::{Read, Write};
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Certificate, CryptoProvider, TlsConfig, TlsContext, TlsVerifier};

pub use embedded_tls::{
    Aes128GcmSha256, CryptoRngCore, NoClock, TlsClock, TlsConnection, TlsError,
};

/// Maximum TLS record size: 16,384 bytes of data plus 256 bytes of headers and MAC.
///
/// With a smaller read buffer, some server records cannot be decoded, potentially
/// causing intermittent handshake or message failures.
pub const TLS_RECORD_SIZE: usize = 16_640;

/// Default size in bytes reserved for a server certificate: see `CERT_SIZE`.
pub const DEFAULT_CERT_SIZE: usize = 2048;

/// TLS record buffers (read and write), approximately 32 KiB.
///
/// Too large for an embedded task stack: place in a `static`
/// (`StaticCell<TlsBuffers>`). Reusable across connections.
pub struct TlsBuffers<const N: usize = TLS_RECORD_SIZE> {
    read: [u8; N],
    write: [u8; N],
}

impl<const N: usize> TlsBuffers<N> {
    pub const fn new() -> Self {
        Self {
            read: [0; N],
            write: [0; N],
        }
    }
}

impl<const N: usize> Default for TlsBuffers<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Server verification settings.
#[derive(Clone, Copy)]
pub struct TlsSettings<'a> {
    /// Broker DNS name as it appears in its certificate (SAN / CN).
    /// Sent as SNI **and** compared with the certificate.
    pub server_name: &'a str,
    /// Trusted CA certificate in **DER format** (not PEM).
    pub ca_der: &'a [u8],
}

/// Errors from [`connect_with_clock`] / [`connect_ignoring_dates`].
#[derive(Debug, Clone, Copy)]
pub enum TlsConnectError {
    /// Empty `server_name`, or empty/non-DER `ca_der` (PEM starts with `-----BEGIN`).
    InvalidSettings,
    /// TLS handshake failed (see [`is_certificate_error`](Self::is_certificate_error)).
    Handshake(TlsError),
}

impl TlsConnectError {
    /// Returns `true` for server certificate failures (chain, signature, name, dates).
    /// Repeated retries are not useful: this indicates misconfiguration or an attack.
    pub fn is_certificate_error(&self) -> bool {
        matches!(
            self,
            TlsConnectError::Handshake(
                TlsError::InvalidCertificate
                    | TlsError::InvalidCertificateEntry
                    | TlsError::InvalidSignature
                    | TlsError::InvalidSignatureScheme
            )
        )
    }
}

impl From<TlsError> for TlsConnectError {
    fn from(e: TlsError) -> Self {
        TlsConnectError::Handshake(e)
    }
}

fn validate_settings(settings: &TlsSettings<'_>) -> Result<(), TlsConnectError> {
    // Un nom vide désactiverait la vérification du nom d'hôte : on refuse.
    if settings.server_name.is_empty() {
        return Err(TlsConnectError::InvalidSettings);
    }
    // Un certificat DER commence par une SEQUENCE ASN.1 (0x30).
    if settings.ca_der.first() != Some(&0x30) {
        return Err(TlsConnectError::InvalidSettings);
    }
    Ok(())
}

/// Cryptographic provider: RNG and pinned-CA verifier, without client authentication.
struct PinnedCaProvider<'a, RNG, Clock: TlsClock, const CERT_SIZE: usize> {
    rng: RNG,
    verifier: CertVerifier<'a, Aes128GcmSha256, Clock, CERT_SIZE>,
}

impl<RNG, Clock, const CERT_SIZE: usize> CryptoProvider
    for PinnedCaProvider<'_, RNG, Clock, CERT_SIZE>
where
    RNG: CryptoRngCore,
    Clock: TlsClock,
{
    type CipherSuite = Aes128GcmSha256;
    // Pas de certificat client : aucune signature n'est jamais produite.
    type Signature = [u8; 0];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }
}

/// Opens a TLS 1.3 session and verifies the server certificate **including its dates**
/// using `Clock` (seconds since the Unix epoch; see [`TlsClock`]).
///
/// Use this when the device knows the time (SNTP, RTC): it rejects expired and
/// not-yet-valid certificates.
///
/// `CERT_SIZE` is the number of bytes reserved for one chain certificate (2048 is
/// generally enough; see [`DEFAULT_CERT_SIZE`]). Pass `&mut socket` to retain the transport.
pub async fn connect_with_clock<'a, S, RNG, Clock, const CERT_SIZE: usize, const N: usize>(
    socket: S,
    buffers: &'a mut TlsBuffers<N>,
    settings: &TlsSettings<'a>,
    rng: RNG,
) -> Result<TlsConnection<'a, S, Aes128GcmSha256>, TlsConnectError>
where
    S: Read + Write + 'a,
    RNG: CryptoRngCore,
    Clock: TlsClock,
{
    validate_settings(settings)?;

    let config = TlsConfig::new().with_server_name(settings.server_name);
    let provider = PinnedCaProvider::<RNG, Clock, CERT_SIZE> {
        rng,
        verifier: CertVerifier::new(Certificate::X509(settings.ca_der)),
    };

    let mut tls = TlsConnection::new(socket, &mut buffers.read, &mut buffers.write);
    tls.open(TlsContext::new(&config, provider)).await?;
    Ok(tls)
}

/// Like [`connect_with_clock`] but **without checking validity dates**.
///
/// For devices without RTC or SNTP at startup. The chain, signatures and hostname
/// are still verified, but expired or not-yet-valid certificates may be accepted.
/// Prefer [`connect_with_clock`] once the time is known.
pub async fn connect_ignoring_dates<'a, S, RNG, const N: usize>(
    socket: S,
    buffers: &'a mut TlsBuffers<N>,
    settings: &TlsSettings<'a>,
    rng: RNG,
) -> Result<TlsConnection<'a, S, Aes128GcmSha256>, TlsConnectError>
where
    S: Read + Write + 'a,
    RNG: CryptoRngCore,
{
    connect_with_clock::<S, RNG, NoClock, DEFAULT_CERT_SIZE, N>(socket, buffers, settings, rng)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_server_name() {
        let s = TlsSettings {
            server_name: "",
            ca_der: &[0x30, 0x82],
        };
        assert!(matches!(
            validate_settings(&s),
            Err(TlsConnectError::InvalidSettings)
        ));
    }

    #[test]
    fn rejects_pem_and_empty_ca() {
        for ca in [&b"-----BEGIN CERTIFICATE-----"[..], &b""[..]] {
            let s = TlsSettings {
                server_name: "broker.lan",
                ca_der: ca,
            };
            assert!(matches!(
                validate_settings(&s),
                Err(TlsConnectError::InvalidSettings)
            ));
        }
    }

    #[test]
    fn accepts_der_looking_ca() {
        let s = TlsSettings {
            server_name: "broker.lan",
            ca_der: &[0x30, 0x82, 0x01, 0x0A],
        };
        assert!(validate_settings(&s).is_ok());
    }

    #[test]
    fn certificate_errors_are_classified() {
        assert!(TlsConnectError::Handshake(TlsError::InvalidCertificate).is_certificate_error());
        assert!(TlsConnectError::Handshake(TlsError::InvalidSignature).is_certificate_error());
        assert!(!TlsConnectError::Handshake(TlsError::ConnectionClosed).is_certificate_error());
        assert!(!TlsConnectError::InvalidSettings.is_certificate_error());
    }
}