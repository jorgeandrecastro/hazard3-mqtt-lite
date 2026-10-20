# Changelog

Toutes les modifications notables de `embassy-mqtt-lite` sont consignées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet respecte le [versionnement sémantique](https://semver.org/lang/fr/).

## [0.4.0] - 2026-10-20

### Ajouté

- **TLS 1.3** via la feature `tls` (module `tls`, basé sur `embedded-tls` 0.19) : certificat serveur toujours vérifié (chaîne jusqu'à une CA épinglée, signature, nom d'hôte).
  - `tls::connect_with_clock` : vérifie aussi les dates de validité à partir d'une horloge `TlsClock`.
  - `tls::connect_ignoring_dates` : pour les appareils sans horloge ; seules les dates ne sont pas contrôlées.
  - `tls::TlsBuffers`, `tls::TlsSettings`, `tls::TlsConnectError` (avec `is_certificate_error()`).
  - Rejet des paramètres invalides avant toute I/O (nom de serveur vide, CA au format PEM).
- Features `tls-p384` et `tls-ed25519` pour les chaînes de certificats ECDSA P-384 et Ed25519 (ECDSA P-256 est toujours supporté).
- `MqttClient::disconnect()` : envoie un `DISCONNECT` pour une fermeture propre (le Last Will n'est pas publié).
- `MqttClient::publish_retained()` : publication avec le drapeau `RETAIN`.
- Variantes d'erreur `MqttError::ConnectionClosed`, `MqttError::InvalidTopic` et `MqttError::InvalidOptions`.
- Validation des topics : les noms de publication n'acceptent ni wildcard, ni topic vide, ni caractère NUL ; les filtres de souscription respectent les règles de `+` et `#` de la spécification.
- Tests sur transport simulé (`embassy-futures` en `dev-dependency`) : 55 tests au total, contre 15 auparavant.

### Modifié

- **Rupture** : `MqttError` est désormais `#[non_exhaustive]` ; les `match` exhaustifs doivent prévoir une branche `_`.
- **Rupture** : les erreurs de lecture du transport ne sont plus ramenées à `ConnackInvalid`, `PingFailed`, `SubackInvalid` ou `UnexpectedPacket` : une fin de flux donne `ConnectionClosed`, une erreur du transport donne `Io(e)`.
- Chaque envoi est suivi d'un `flush()` du transport, indispensable avec TLS qui met les écritures en tampon.
- Le payload d'un `PUBLISH` est envoyé directement depuis le buffer de l'appelant, sans copie : `MAX_PACKET_SIZE` ne limite plus que les en-têtes (identifiant client, identifiants, Last Will, topic).
- Le `CONNACK` est validé strictement (octet de flags réservé, code de retour).
- Le `SUBACK` est validé strictement : identifiant de paquet, longueur et code de retour (`0x00..=0x02` accepté, `0x80` refusé, tout autre code invalide).
- `subscribe()` ignore les paquets parasites (par exemple un `PINGRESP`) reçus avant le `SUBACK`, dans la limite de 8 paquets.
- `connect_with_options()` refuse un mot de passe sans nom d'utilisateur (`InvalidOptions`) et valide le topic du Last Will.
- La lecture de la « Remaining Length » est limitée à 4 octets, conformément à la spécification.
- Le code est réparti en trois fichiers : `packet.rs` (codec pur), `lib.rs` (client), `tls.rs` (TLS).
- `Cargo.toml` : `embedded-tls` ajouté en dépendance optionnelle.

### Corrigé

- `receive()` : un `PUBLISH` plus grand que le buffer fourni laissait le flux désynchronisé. Le message est désormais lu en entier puis ignoré, `PacketTooLarge` est renvoyée et la connexion reste utilisable.

## [0.3.0]

### Ajouté

- Souscription (`SUBSCRIBE` / `SUBACK`) et réception des messages `PUBLISH` entrants (`subscribe()`, `receive()`).

## Versions antérieures

- Connexion MQTT 3.1.1 (`CONNECT` / `CONNACK`) en Clean Session, avec authentification username/password et Last Will and Testament.
- Publication en QoS 0.
- Keep-alive via `PINGREQ` / `PINGRESP`.
- Client `no_std`, sans allocation dynamique, agnostique du transport (`embedded_io_async::Read + Write`).

[0.4.0]: https://github.com/jorgeandrecastro/embassy-mqtt-lite/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jorgeandrecastro/embassy-mqtt-lite/releases/tag/v0.3.0