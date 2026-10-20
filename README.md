# embassy-mqtt-lite

[![Crates.io](https://img.shields.io/crates/v/embassy-mqtt-lite.svg)](https://crates.io/crates/embassy-mqtt-lite)
[![Downloads](https://img.shields.io/crates/d/embassy-mqtt-lite.svg)](https://crates.io/crates/embassy-mqtt-lite)
[![Documentation](https://docs.rs/embassy-mqtt-lite/badge.svg)](https://docs.rs/embassy-mqtt-lite)
[![License](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![no_std](https://img.shields.io/badge/no__std-yes-success.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

Un client **MQTT v3.1.1** minimal, asynchrone et `no_std`, agnostique du transport, avec **TLS 1.3 optionnel** (certificat serveur vérifié contre une CA épinglée).

Conçu pour les projets embarqués basés sur [Embassy](https://embassy.dev/) (ESP32, RP2040/RP2350, STM32, nRF...), sans dépendre d'un allocateur (`alloc`) et sans imposer de pile réseau spécifique : n'importe quel transport implémentant `embedded_io_async::Read + Write` (socket TCP, session TLS, série...) fait l'affaire.

## ✨ Fonctionnalités

- ✅ Connexion MQTT 3.1.1 (`CONNECT` / `CONNACK`), Clean Session
- ✅ Authentification username/password
- ✅ Last Will and Testament
- ✅ Keep-alive via `PINGREQ`/`PINGRESP`, fermeture propre via `DISCONNECT`
- ✅ Publication en **QoS 0**, avec ou sans `RETAIN`
- ✅ Souscription (`SUBSCRIBE`/`SUBACK`) et réception de messages (`PUBLISH` entrants)
- ✅ **TLS 1.3** (feature `tls`) : chaîne, signature et nom d'hôte toujours vérifiés
- ✅ `no_std`, zéro allocation dynamique
- ✅ Payload publié sans copie : pas de limite de taille liée au buffer interne
- ✅ Validation des topics (wildcards interdits en publication, filtres vérifiés en souscription)
- ✅ Agnostique du transport : TCP, TLS, ou tout autre flux `embedded-io-async`
- ✅ Dépendances minimales : `embedded-io-async` (et `embedded-tls` uniquement avec la feature `tls`)
- ✅ Compatible avec n'importe quelle pile réseau Embassy (`embassy-net` ≥ 0.8, qui utilise `embedded-io-async` 0.7)

## 🚧 Limitations actuelles

- Seule la **QoS 0** est supportée en réception comme en émission (pas d'accusés applicatifs QoS 1/2)
- Une seule souscription active par instance de `MqttClient` à la fois, et pas de multiplexage interne : prévoir une connexion dédiée pour publier et écouter en parallèle
- TLS : TLS 1.3 uniquement, suite `TLS_AES_128_GCM_SHA256`, pas de certificat client, pas de chaînes RSA (voir [TLS](#-tls-13))

Ces limitations correspondent à un usage simple de télémétrie et de commande à distance. Des contributions pour étendre les fonctionnalités sont bienvenues !

## 📦 Installation

```toml
[dependencies]
embassy-mqtt-lite = "0.4"

# avec TLS 1.3 :
embassy-mqtt-lite = { version = "0.4", features = ["tls"] }
```

| Feature       | Effet                                                                  |
|---------------|------------------------------------------------------------------------|
| `tls`         | Active le module `tls` (TLS 1.3, CA épinglée, ECDSA P-256)             |
| `tls-p384`    | `tls` + chaînes de certificats ECDSA P-384                             |
| `tls-ed25519` | `tls` + chaînes de certificats Ed25519                                 |

## 🚀 Exemple d'utilisation

```rust
use embassy_mqtt_lite::MqttClient;
use embassy_net::tcp::TcpSocket;

async fn publish_example(stack: embassy_net::Stack<'static>) {
    let mut rx_buffer = [0u8; 512];
    let mut tx_buffer = [0u8; 512];
    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

    let remote_endpoint = (embassy_net::IpAddress::v4(192, 168, 1, 84), 1883);
    socket.connect(remote_endpoint).await.unwrap();

    let mut client = MqttClient::new(&mut socket);

    client.connect("mon-client-esp32", 60).await.unwrap();

    client
        .publish("maison/salon/temperature", b"21.5")
        .await
        .unwrap();

    client.disconnect().await.unwrap();
}
```

## 🔐 TLS 1.3

Avec la feature `tls`, le module `embassy_mqtt_lite::tls` ouvre une session TLS 1.3 par-dessus un socket TCP, puis la session obtenue est passée à `MqttClient` comme n'importe quel autre transport.

**Ce que la crate garantit :**

- le certificat du serveur est **toujours** vérifié : chaîne jusqu'à la CA fournie, signature, et **nom d'hôte** (SAN DNS / CN). Il n'existe aucun mode « sans vérification » ;
- les dates de validité sont vérifiées si une horloge est fournie (`connect_with_clock`), sinon explicitement ignorées (`connect_ignoring_dates`) ;
- les paramètres invalides (nom vide, CA au format PEM) sont refusés **avant** toute I/O ;
- les buffers TLS (~32 Kio) ne sont jamais alloués sur la pile : ils sont à placer dans une `static`.

### Préparer la CA

Le broker doit présenter un certificat signé par une CA embarquée dans le firmware **au format DER** :

```bash
openssl x509 -in ca.pem -outform DER -out ca.der
```

Le nom d'hôte passé à `TlsSettings::server_name` doit figurer dans le SAN (ou le CN) du certificat du broker.

### Exemple

```rust
use embassy_mqtt_lite::{tls, MqttClient};
use static_cell::StaticCell;

static TLS_BUFFERS: StaticCell<tls::TlsBuffers> = StaticCell::new();
static CA: &[u8] = include_bytes!("../certs/ca.der");

async fn mqtt_tls(stack: embassy_net::Stack<'static>, rng: impl tls::CryptoRngCore) {
    let buffers = TLS_BUFFERS.init(tls::TlsBuffers::new());
    let settings = tls::TlsSettings {
        server_name: "broker.maison.lan",
        ca_der: CA,
    };

    let mut rx = [0u8; 1024];
    let mut tx = [0u8; 1024];
    let mut socket = embassy_net::tcp::TcpSocket::new(stack, &mut rx, &mut tx);
    socket
        .connect((embassy_net::IpAddress::v4(192, 168, 1, 84), 8883))
        .await
        .unwrap();

    // `&mut socket` : le socket reste disponible pour une reconnexion.
    let mut session = match tls::connect_ignoring_dates(&mut socket, buffers, &settings, rng).await
    {
        Ok(s) => s,
        Err(e) if e.is_certificate_error() => {
            // Erreur de configuration (mauvaise CA, mauvais nom) ou attaque : inutile de réessayer en boucle.
            return;
        }
        Err(_) => return, // problème transitoire : réessaie plus tard
    };

    let mut client = MqttClient::new(&mut session);
    client.connect("esp32-salon", 60).await.unwrap();
    client
        .publish("capteurs/salon/temperature", b"21.5")
        .await
        .unwrap();

    client.disconnect().await.unwrap();
    session.close().await.ok(); // envoie l'alerte close_notify
}
```

### Avec vérification des dates

Si l'appareil connaît l'heure (SNTP, RTC), implémenter `TlsClock` et utiliser `connect_with_clock` : un certificat expiré ou pas encore valide est alors refusé.

```rust
struct Horloge;
impl tls::TlsClock for Horloge {
    fn now() -> Option<u64> {
        Some(/* secondes depuis l'epoch Unix */ 0)
    }
}

// CERT_SIZE = 2048 octets réservés à un certificat de la chaîne, N = taille des buffers TLS.
let session = tls::connect_with_clock::<_, _, Horloge, 2048, { tls::TLS_RECORD_SIZE }>(
    &mut socket, buffers, &settings, rng,
)
.await?;
```

### À savoir

- **Une CA privée en ECDSA P-256** est le cas idéal (broker Mosquitto auto-hébergé, par exemple). Les chaînes **RSA**, donc Let's Encrypt, ne sont pas supportées sans allocateur. P-384 et Ed25519 s'activent via `tls-p384` / `tls-ed25519`.
- Le `rng` doit être **cryptographique** (TRNG matériel du microcontrôleur), jamais un PRNG déterministe.
- Un certificat plus gros que `CERT_SIZE` fait échouer la poignée de main avec `TlsError::OutOfMemory`.
- Le buffer de lecture de 16 640 octets (`TLS_RECORD_SIZE`) garantit de pouvoir décoder tout enregistrement TLS. Ne le réduire que si le comportement du broker est connu.
- Les erreurs de transport remontent en `MqttError::Io(TlsError)`.

## 🏭 Exemple avec reconnexion et authentification

```rust
use embassy_mqtt_lite::{MqttClient, ConnectOptions, LastWill};
use embassy_time::{Duration, Timer};

async fn mqtt_loop(stack: embassy_net::Stack<'static>) {
    loop {
        let mut rx_buffer = [0u8; 512];
        let mut tx_buffer = [0u8; 512];
        let mut socket = embassy_net::tcp::TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        let remote = (embassy_net::IpAddress::v4(192, 168, 1, 84), 1883);
        if socket.connect(remote).await.is_err() {
            Timer::after(Duration::from_secs(5)).await;
            continue;
        }

        let mut client = MqttClient::new(&mut socket);

        let options = ConnectOptions {
            username: Some("mon_user"),
            password: Some(b"mon_mdp"), // un mot de passe exige un username
            last_will: Some(LastWill {
                topic: "capteurs/salon/status",
                message: b"offline",
                retain: true,
            }),
        };

        if client.connect_with_options("esp32-salon", 60, &options).await.is_err() {
            Timer::after(Duration::from_secs(5)).await;
            continue;
        }

        // Statut "online" conservé par le broker, écrasé par le Last Will si on tombe.
        let _ = client.publish_retained("capteurs/salon/status", b"online").await;

        loop {
            if client.publish("capteurs/salon/temperature", b"21.5").await.is_err() {
                break; // reconnexion
            }
            Timer::after(Duration::from_secs(30)).await;
        }
    }
}
```

## 📡 Exemple : souscription et réception de commandes

```rust
use embassy_mqtt_lite::{MqttClient, MqttError};
use embassy_time::{Duration, Timer};

async fn mqtt_subscribe_loop(stack: embassy_net::Stack<'static>) {
    loop {
        let mut rx_buffer = [0u8; 512];
        let mut tx_buffer = [0u8; 512];
        let mut socket = embassy_net::tcp::TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        let remote = (embassy_net::IpAddress::v4(192, 168, 1, 84), 1883);
        if socket.connect(remote).await.is_err() {
            Timer::after(Duration::from_secs(5)).await;
            continue;
        }

        let mut client = MqttClient::new(&mut socket);

        // Utiliser un client_id différent de celui de la connexion de publication !
        if client.connect("esp32-salon-sub", 60).await.is_err() {
            Timer::after(Duration::from_secs(5)).await;
            continue;
        }

        if client.subscribe("maison/salon/commande").await.is_err() {
            Timer::after(Duration::from_secs(5)).await;
            continue;
        }

        let mut recv_buf = [0u8; 256];
        loop {
            match client.receive(&mut recv_buf).await {
                Ok(msg) => {
                    // Traiter msg.topic / msg.payload ici
                }
                // Message plus gros que recv_buf : il a été ignoré, la connexion reste utilisable.
                Err(MqttError::PacketTooLarge) => continue,
                Err(_) => break, // reconnexion
            }
        }

        Timer::after(Duration::from_secs(5)).await;
    }
}
```

> ⚠️ Une même connexion MQTT (`MqttClient`) ne peut pas à la fois publier et attendre indéfiniment un message entrant sans bloquer l'autre opération. Si les deux sont nécessaires en parallèle (ex : publier de la télémétrie tout en écoutant des commandes), utiliser deux connexions distinctes avec des `client_id` différents. Ne pas appeler `ping()` pendant qu'un `receive()` est en attente sur la même connexion : `receive()` consomme lui-même les `PINGRESP`.

## 🔧 Comment ça marche

La crate est découpée en trois fichiers :

- **`packet.rs`** : codec pur (construction et analyse des paquets `CONNECT`, `PUBLISH`, `SUBSCRIBE`, `CONNACK`, `SUBACK`), sans I/O, entièrement testable sur l'hôte.
- **`lib.rs`** : `MqttClient` et `MqttError`, la partie I/O. Chaque envoi est suivi d'un `flush()` (indispensable avec TLS, qui met les écritures en tampon).
- **`tls.rs`** (feature `tls`) : session TLS 1.3 avec vérification du serveur, basée sur [`embedded-tls`](https://crates.io/crates/embedded-tls).

Les en-têtes de paquets sont construits dans un buffer de taille fixe (`MAX_PACKET_SIZE`, 256 octets par défaut, ajustable dans le code source), ce qui borne `client_id`, identifiants, Last Will et topics. Le **payload** d'un `PUBLISH` n'y est pas copié : il est envoyé directement depuis le buffer de l'appelant.

Aucune hypothèse n'est faite sur la pile réseau : que ce soit `embassy-net`, un autre stack TCP/IP, ou même un flux série faisant office de passerelle, tant que le type implémente `Read + Write` de `embedded-io-async`, ça fonctionne.

## ❌ Gestion des erreurs

Sauf `MqttError::PacketTooLarge` renvoyée par `receive()` (message ignoré, flux resynchronisé), toute erreur est à considérer comme **fatale pour la connexion** : fermer le transport et se reconnecter.

| Erreur                        | Signification                                             |
|-------------------------------|-----------------------------------------------------------|
| `Io(e)`                       | Erreur du transport (TCP, TLS...)                         |
| `ConnectionClosed`            | Fin de flux : le pair a fermé la connexion                |
| `PacketTooLarge`              | En-tête trop grand pour `MAX_PACKET_SIZE`, ou message reçu trop grand pour le buffer fourni |
| `InvalidTopic`                | Topic vide, NUL, ou wildcard mal placé                    |
| `InvalidOptions`              | Mot de passe sans nom d'utilisateur                       |
| `ConnackInvalid`              | Réponse du broker invalide                                |
| `ConnectionRefused(code)`     | Le broker a refusé la connexion                           |
| `PingFailed`                  | Mauvaise réponse au `PINGREQ`                             |
| `SubackInvalid`/`SubscribeFailed` | `SUBACK` invalide / souscription refusée              |
| `UnexpectedPacket`            | Paquet entrant mal formé                                  |

## 🧰 Version de Rust minimale

La crate utilise l'edition 2024 : Rust **1.85** ou plus récent.

## 🧪 Tests

```bash
cargo test                  # codec + client sur un transport simulé
cargo test --features tls   # + validation des paramètres TLS
```

## 🎯 Pourquoi cette crate ?

Les clients MQTT `no_std` existants pour l'écosystème Rust embarqué imposent souvent des dépendances lourdes, des générations de types complexes, ou des versions de traits (`embedded-io-async`) qui entrent en conflit avec le reste de la stack Embassy/`esp-hal`. `embassy-mqtt-lite` vise la simplicité : une implémentation directe et lisible du strict nécessaire pour publier des données de capteurs vers un broker MQTT, sans négociation de version douloureuse, avec un chiffrement TLS 1.3 vérifié lorsque le réseau n'est pas de confiance.

## 📝 Changelog

Le détail complet de toutes les versions est dans [CHANGELOG.md](CHANGELOG.md).

### 0.4.0 - 2026-10-20

**Ajouté**

- TLS 1.3 (feature `tls`) avec certificat serveur vérifié contre une CA épinglée, nom d'hôte compris ; features `tls-p384` et `tls-ed25519`
- `disconnect()` et `publish_retained()`
- Variantes d'erreur `ConnectionClosed`, `InvalidTopic`, `InvalidOptions`
- Validation des topics et des filtres de souscription
- 55 tests sur transport simulé (contre 15)

**Modifié**

- ⚠️ `MqttError` est `#[non_exhaustive]` : prévoir une branche `_` dans les `match`
- ⚠️ Les erreurs de lecture remontent en `ConnectionClosed` ou `Io(e)` au lieu d'être ramenées à une erreur de protocole
- `flush()` après chaque envoi (nécessaire avec TLS)
- Payload publié sans copie : `MAX_PACKET_SIZE` ne borne plus que les en-têtes
- `CONNACK` et `SUBACK` validés strictement
- Code réparti en trois fichiers : `packet.rs`, `lib.rs`, `tls.rs`

**Corrigé**

- `receive()` : un message plus grand que le buffer désynchronisait le flux ; il est maintenant ignoré proprement

## 🤝 Contribuer

Les issues et pull requests sont les bienvenues sur le [dépôt GitHub](https://github.com/jorgeandrecastro/embassy-mqtt-lite).

## 📄 Licence

Distribué sous licence **GPL-2.0-or-later**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👤 Auteur

**Jorge Andre Castro**  [georgeandrec@gmail.com](mailto:georgeandrec@gmail.com)