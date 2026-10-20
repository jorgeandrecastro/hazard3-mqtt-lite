//! TLS 1.3 pour [`MqttClient`](crate::MqttClient) (feature `tls`).
//!
//! S'appuie sur [`embedded-tls`](https://crates.io/crates/embedded-tls) (TLS 1.3, `no_std`,
//! sans allocateur) avec la vérification de certificat « rustpki ». Ce que cette couche garantit :
//!
//! - **le certificat serveur est toujours vérifié** : chaîne jusqu'à la CA que tu fournis
//!   (épinglée), signature `CertificateVerify`, et **nom d'hôte** (SAN DNS / CN). Il n'existe
//!   volontairement aucun mode « sans vérification » dans cette crate ;
//! - les dates de validité sont vérifiées si tu fournis une horloge
//!   ([`connect_with_clock`]), sinon explicitement ignorées ([`connect_ignoring_dates`]) ;
//! - aucun buffer sur la pile : les enregistrements TLS vivent dans [`TlsBuffers`], à placer
//!   dans une `static` (`StaticCell`) ;
//! - le transport reste à toi : passe `&mut socket`, tu le réutilises pour reconnecter.
//!
//! # Utilisation
//!
//! ```ignore
//! use embassy_mqtt_lite::{tls, MqttClient};
//! use static_cell::StaticCell;
//!
//! static TLS_BUFFERS: StaticCell<tls::TlsBuffers> = StaticCell::new();
//! // CA du broker au format DER (pas PEM) : openssl x509 -in ca.pem -outform DER -out ca.der
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
//! tls.close().await.ok(); // envoie close_notify
//! ```
//!
//! # Contraintes à connaître
//!
//! - **CA privée ou épinglée recommandée.** Le vérificateur `no_std` gère ECDSA P-256 (toujours),
//!   P-384 (feature `tls-p384`) et Ed25519 (feature `tls-ed25519`). Les chaînes RSA — typiquement
//!   Let's Encrypt — ne sont pas supportées sans allocateur. Pour un broker maison : génère une
//!   CA et un certificat serveur en P-256.
//! - Le nom d'hôte doit être un **nom DNS** présent dans le SAN (ou le CN) du certificat.
//! - Les certificats de la chaîne doivent tenir dans `CERT_SIZE` octets (2048 par défaut).
//!   Un certificat plus gros fait échouer la poignée de main avec `TlsError::OutOfMemory`.
//! - TLS 1.3 uniquement, suite `TLS_AES_128_GCM_SHA256` (obligatoire dans la RFC 8446, donc
//!   offerte par tous les brokers TLS 1.3). Mosquitto ≥ 1.6 avec OpenSSL ≥ 1.1.1 convient.
//! - `embedded-io-async` 0.7 : ton pile réseau doit utiliser la même version
//!   (`embassy-net` ≥ 0.8).
//! - Le nombre aléatoire (`rng`) doit être **cryptographique** (TRNG matériel : `esp-hal::rng::Trng`,
//!   `embassy_rp::clocks::RoscRng`, RNG du STM32…), pas un PRNG déterministe.

use embedded_io_async::{Read, Write};
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Certificate, CryptoProvider, TlsConfig, TlsContext, TlsVerifier};

pub use embedded_tls::{
    Aes128GcmSha256, CryptoRngCore, NoClock, TlsClock, TlsConnection, TlsError,
};

/// Taille d'un enregistrement TLS maximal : 16 384 octets de données + 256 d'en-têtes / MAC.
///
/// Avec un buffer de lecture plus petit, certains enregistrements du serveur ne peuvent pas
/// être décodés (la poignée de main ou un message peut alors échouer de façon intermittente).
pub const TLS_RECORD_SIZE: usize = 16_640;

/// Taille par défaut (octets) réservée à un certificat serveur : voir `CERT_SIZE`.
pub const DEFAULT_CERT_SIZE: usize = 2048;

/// Buffers d'enregistrements TLS (lecture + écriture), ~32 Kio.
///
/// Trop gros pour une pile de tâche embarquée : place-le dans une `static`
/// (`StaticCell<TlsBuffers>`). Réutilisable d'une connexion à l'autre.
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

/// Paramètres de vérification du serveur.
#[derive(Clone, Copy)]
pub struct TlsSettings<'a> {
    /// Nom DNS du broker, tel qu'il figure dans son certificat (SAN / CN).
    /// Envoyé en SNI **et** comparé au certificat.
    pub server_name: &'a str,
    /// Certificat de la CA de confiance, **au format DER** (pas PEM).
    pub ca_der: &'a [u8],
}

/// Erreurs de [`connect_with_clock`] / [`connect_ignoring_dates`].
#[derive(Debug, Clone, Copy)]
pub enum TlsConnectError {
    /// `server_name` vide, ou `ca_der` vide / qui n'est pas du DER (un PEM commence par `-----BEGIN`).
    InvalidSettings,
    /// La poignée de main TLS a échoué (voir [`is_certificate_error`](Self::is_certificate_error)).
    Handshake(TlsError),
}

impl TlsConnectError {
    /// `true` si l'échec vient du certificat du serveur (chaîne, signature, nom, dates) :
    /// inutile de réessayer en boucle, c'est une erreur de configuration — ou une attaque.
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

/// Fournisseur cryptographique : RNG + vérificateur à CA épinglée, sans authentification client.
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

/// Ouvre une session TLS 1.3 en vérifiant le certificat serveur **y compris ses dates**
/// avec l'horloge `Clock` (secondes depuis l'epoch Unix, voir [`TlsClock`]).
///
/// Utilise cette variante dès que ton appareil connaît l'heure (SNTP, RTC) : elle refuse les
/// certificats expirés ou pas encore valides.
///
/// `CERT_SIZE` : octets réservés à un certificat de la chaîne (2048 suffit en général,
/// cf. [`DEFAULT_CERT_SIZE`]). Passe `&mut socket` pour garder la main sur le transport.
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

/// Comme [`connect_with_clock`] mais **sans contrôle des dates** de validité.
///
/// Pour les appareils sans RTC ni SNTP au démarrage. La chaîne, les signatures et le nom
/// d'hôte restent entièrement vérifiés ; seul un certificat **expiré** serait accepté.
/// Dès que l'heure est connue, préfère [`connect_with_clock`].
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