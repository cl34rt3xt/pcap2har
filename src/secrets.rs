use crate::diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub type ClientRandom = [u8; 32];

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct ClientSecrets {
    pub master_secret: Option<Vec<u8>>,
}

impl fmt::Debug for ClientSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSecrets")
            .field("master_secret_present", &self.master_secret.is_some())
            .finish()
    }
}

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct TrafficSecretSet {
    pub client_early: Option<Vec<u8>>,
    pub client_handshake: Option<Vec<u8>>,
    pub server_handshake: Option<Vec<u8>>,
    pub client_application_0: Option<Vec<u8>>,
    pub server_application_0: Option<Vec<u8>>,
    pub exporter: Option<Vec<u8>>,
}

impl TrafficSecretSet {
    pub fn populated_label_count(&self) -> usize {
        [
            &self.client_early,
            &self.client_handshake,
            &self.server_handshake,
            &self.client_application_0,
            &self.server_application_0,
            &self.exporter,
        ]
        .into_iter()
        .filter(|secret| secret.is_some())
        .count()
    }
}

impl fmt::Debug for TrafficSecretSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficSecretSet")
            .field("client_early_present", &self.client_early.is_some())
            .field("client_handshake_present", &self.client_handshake.is_some())
            .field("server_handshake_present", &self.server_handshake.is_some())
            .field(
                "client_application_0_present",
                &self.client_application_0.is_some(),
            )
            .field(
                "server_application_0_present",
                &self.server_application_0.is_some(),
            )
            .field("exporter_present", &self.exporter.is_some())
            .finish()
    }
}

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct TrafficSecrets {
    pub client_handshake_traffic_secret: Option<Vec<u8>>,
    pub server_handshake_traffic_secret: Option<Vec<u8>>,
    pub client_traffic_secret_0: Option<Vec<u8>>,
    pub server_traffic_secret_0: Option<Vec<u8>>,
    pub exporter_secret: Option<Vec<u8>>,
}

impl TrafficSecrets {
    pub fn populated_label_count(&self) -> usize {
        [
            &self.client_handshake_traffic_secret,
            &self.server_handshake_traffic_secret,
            &self.client_traffic_secret_0,
            &self.server_traffic_secret_0,
            &self.exporter_secret,
        ]
        .into_iter()
        .filter(|secret| secret.is_some())
        .count()
    }
}

impl fmt::Debug for TrafficSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficSecrets")
            .field(
                "client_handshake_traffic_secret_present",
                &self.client_handshake_traffic_secret.is_some(),
            )
            .field(
                "server_handshake_traffic_secret_present",
                &self.server_handshake_traffic_secret.is_some(),
            )
            .field(
                "client_traffic_secret_0_present",
                &self.client_traffic_secret_0.is_some(),
            )
            .field(
                "server_traffic_secret_0_present",
                &self.server_traffic_secret_0.is_some(),
            )
            .field("exporter_secret_present", &self.exporter_secret.is_some())
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct SecretStore {
    legacy_master: HashMap<ClientRandom, Zeroizing<Vec<u8>>>,
    traffic: HashMap<ClientRandom, TrafficSecretSet>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretStore")
            .field("legacy_master_count", &self.legacy_master.len())
            .field("traffic_secret_count", &self.traffic_secret_count())
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct TlsSecrets {
    pub client_randoms: HashMap<String, ClientSecrets>,
    pub traffic_secrets: HashMap<String, TrafficSecrets>,
}

impl fmt::Debug for TlsSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsSecrets")
            .field("legacy_master_count", &self.client_randoms.len())
            .field("traffic_secret_count", &self.traffic_secret_count())
            .finish()
    }
}

pub struct SecretParseResult {
    pub store: SecretStore,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Copy)]
enum SecretLabel {
    LegacyMaster,
    ClientEarly,
    ClientHandshake,
    ServerHandshake,
    ClientApplication0,
    ServerApplication0,
    Exporter,
}

impl SecretLabel {
    fn parse(label: &[u8]) -> Option<Self> {
        match label {
            b"CLIENT_RANDOM" => Some(Self::LegacyMaster),
            b"CLIENT_EARLY_TRAFFIC_SECRET" => Some(Self::ClientEarly),
            b"CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ClientHandshake),
            b"SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ServerHandshake),
            b"CLIENT_TRAFFIC_SECRET_0" => Some(Self::ClientApplication0),
            b"SERVER_TRAFFIC_SECRET_0" => Some(Self::ServerApplication0),
            b"EXPORTER_SECRET" => Some(Self::Exporter),
            _ => None,
        }
    }

    fn is_tls13(self) -> bool {
        !matches!(self, Self::LegacyMaster)
    }
}

impl SecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(data: &[u8]) -> SecretParseResult {
        let mut store = Self::new();
        let mut diagnostics = Vec::new();

        for line in data.split(|byte| *byte == b'\n') {
            let mut parts = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|part| !part.is_empty());
            let Some(label) = parts.next() else {
                continue;
            };
            if label.starts_with(b"#") {
                continue;
            }
            let Some(label) = SecretLabel::parse(label) else {
                continue;
            };
            let (Some(client_random), Some(secret), None) =
                (parts.next(), parts.next(), parts.next())
            else {
                diagnostics.push(malformed_keylog_entry("expected exactly three fields"));
                continue;
            };
            let Some(client_random) = decode_client_random(client_random) else {
                diagnostics.push(malformed_keylog_entry(
                    "client random must be 32 bytes of hex",
                ));
                continue;
            };
            let Ok(secret) = hex::decode(secret) else {
                diagnostics.push(malformed_keylog_entry("secret must be hexadecimal"));
                continue;
            };
            let secret = Zeroizing::new(secret);
            if label.is_tls13() && !matches!(secret.len(), 32 | 48) {
                diagnostics.push(malformed_keylog_entry(
                    "TLS 1.3 secret must be 32 or 48 bytes",
                ));
                continue;
            }
            if let Some(diagnostic) = store.insert(client_random, label, secret) {
                diagnostics.push(diagnostic);
            }
        }
        SecretParseResult { store, diagnostics }
    }

    pub fn merge(&mut self, other: SecretStore) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        for (client_random, secret) in other.legacy_master {
            if let Some(diagnostic) = self.insert(client_random, SecretLabel::LegacyMaster, secret)
            {
                diagnostics.push(diagnostic);
            }
        }
        for (client_random, mut traffic) in other.traffic {
            for (label, secret) in [
                (SecretLabel::ClientEarly, traffic.client_early.take()),
                (
                    SecretLabel::ClientHandshake,
                    traffic.client_handshake.take(),
                ),
                (
                    SecretLabel::ServerHandshake,
                    traffic.server_handshake.take(),
                ),
                (
                    SecretLabel::ClientApplication0,
                    traffic.client_application_0.take(),
                ),
                (
                    SecretLabel::ServerApplication0,
                    traffic.server_application_0.take(),
                ),
                (SecretLabel::Exporter, traffic.exporter.take()),
            ] {
                if let Some(secret) = secret {
                    if let Some(diagnostic) =
                        self.insert(client_random, label, Zeroizing::new(secret))
                    {
                        diagnostics.push(diagnostic);
                    }
                }
            }
        }
        diagnostics
    }

    pub fn traffic(&self, client_random: &ClientRandom) -> Option<&TrafficSecretSet> {
        self.traffic.get(client_random)
    }

    pub fn legacy_master(&self, client_random: &ClientRandom) -> Option<&[u8]> {
        self.legacy_master
            .get(client_random)
            .map(|secret| secret.as_slice())
    }

    pub fn traffic_secret_count(&self) -> usize {
        self.traffic
            .values()
            .map(TrafficSecretSet::populated_label_count)
            .sum()
    }

    pub(crate) fn checked_secret_entry_count(&self) -> Option<usize> {
        self.traffic
            .values()
            .try_fold(self.legacy_master.len(), |count, secrets| {
                count.checked_add(secrets.populated_label_count())
            })
    }

    fn insert(
        &mut self,
        client_random: ClientRandom,
        label: SecretLabel,
        secret: Zeroizing<Vec<u8>>,
    ) -> Option<Diagnostic> {
        let conflict = match label {
            SecretLabel::LegacyMaster => match self.legacy_master.entry(client_random) {
                Entry::Vacant(entry) => {
                    entry.insert(secret);
                    false
                }
                Entry::Occupied(entry) => entry.get().as_slice() != secret.as_slice(),
            },
            _ => {
                let traffic = self.traffic.entry(client_random).or_default();
                let slot = match label {
                    SecretLabel::ClientEarly => &mut traffic.client_early,
                    SecretLabel::ClientHandshake => &mut traffic.client_handshake,
                    SecretLabel::ServerHandshake => &mut traffic.server_handshake,
                    SecretLabel::ClientApplication0 => &mut traffic.client_application_0,
                    SecretLabel::ServerApplication0 => &mut traffic.server_application_0,
                    SecretLabel::Exporter => &mut traffic.exporter,
                    SecretLabel::LegacyMaster => return None,
                };
                match slot {
                    Some(existing) => existing.as_slice() != secret.as_slice(),
                    None => {
                        let mut secret = secret;
                        *slot = Some(std::mem::take(&mut *secret));
                        false
                    }
                }
            }
        };

        conflict.then(conflicting_secret)
    }

    pub(crate) fn into_tls_secrets(self) -> TlsSecrets {
        let mut tls_secrets = TlsSecrets::new();

        for (client_random, master_secret) in self.legacy_master {
            tls_secrets.client_randoms.insert(
                hex::encode(client_random),
                ClientSecrets {
                    master_secret: Some(master_secret.to_vec()),
                },
            );
        }
        for (client_random, mut traffic) in self.traffic {
            if let Some(mut early_secret) = traffic.client_early.take() {
                early_secret.zeroize();
            }
            if traffic.client_handshake.is_none()
                && traffic.server_handshake.is_none()
                && traffic.client_application_0.is_none()
                && traffic.server_application_0.is_none()
                && traffic.exporter.is_none()
            {
                continue;
            }

            tls_secrets.traffic_secrets.insert(
                hex::encode(client_random),
                TrafficSecrets {
                    client_handshake_traffic_secret: traffic.client_handshake.take(),
                    server_handshake_traffic_secret: traffic.server_handshake.take(),
                    client_traffic_secret_0: traffic.client_application_0.take(),
                    server_traffic_secret_0: traffic.server_application_0.take(),
                    exporter_secret: traffic.exporter.take(),
                },
            );
        }

        tls_secrets
    }
}

impl TlsSecrets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_keylog(&mut self, data: &[u8]) {
        let parsed = SecretStore::parse(data);
        self.merge_legacy(parsed.store.into_tls_secrets());
    }

    pub fn traffic(&self, client_random: &ClientRandom) -> Option<&TrafficSecrets> {
        self.traffic_secrets.get(&hex::encode(client_random))
    }

    pub fn legacy_master(&self, client_random: &ClientRandom) -> Option<&[u8]> {
        self.client_randoms
            .get(&hex::encode(client_random))
            .and_then(|secrets| secrets.master_secret.as_deref())
    }

    fn traffic_secret_count(&self) -> usize {
        self.traffic_secrets
            .values()
            .map(TrafficSecrets::populated_label_count)
            .sum()
    }

    fn merge_legacy(&mut self, other: Self) {
        for (client_random, mut secrets) in other.client_randoms {
            retain_first(
                &mut self
                    .client_randoms
                    .entry(client_random)
                    .or_default()
                    .master_secret,
                secrets.master_secret.take(),
            );
        }
        for (client_random, mut secrets) in other.traffic_secrets {
            let existing = self.traffic_secrets.entry(client_random).or_default();
            retain_first(
                &mut existing.client_handshake_traffic_secret,
                secrets.client_handshake_traffic_secret.take(),
            );
            retain_first(
                &mut existing.server_handshake_traffic_secret,
                secrets.server_handshake_traffic_secret.take(),
            );
            retain_first(
                &mut existing.client_traffic_secret_0,
                secrets.client_traffic_secret_0.take(),
            );
            retain_first(
                &mut existing.server_traffic_secret_0,
                secrets.server_traffic_secret_0.take(),
            );
            retain_first(
                &mut existing.exporter_secret,
                secrets.exporter_secret.take(),
            );
        }
    }
}

fn retain_first(existing: &mut Option<Vec<u8>>, candidate: Option<Vec<u8>>) {
    if existing.is_none() {
        *existing = candidate;
    } else if let Some(mut candidate) = candidate {
        candidate.zeroize();
    }
}

pub fn client_random_from_hex(value: &str) -> Option<ClientRandom> {
    decode_client_random(value.as_bytes())
}

fn decode_client_random(value: &[u8]) -> Option<ClientRandom> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

fn malformed_keylog_entry(reason: &'static str) -> Diagnostic {
    Diagnostic::warning(
        DiagnosticCode::MalformedDatagram,
        DiagnosticScope::Capture,
        format!("malformed NSS key log entry: {reason}"),
    )
}

fn conflicting_secret() -> Diagnostic {
    Diagnostic::warning(
        DiagnosticCode::MalformedDatagram,
        DiagnosticScope::Capture,
        "conflicting NSS key log secret; retained first value",
    )
}

#[cfg(test)]
mod tests {
    use super::{SecretStore, TrafficSecrets};
    use crate::DiagnosticCode;

    #[test]
    fn parses_all_quic_secret_labels() {
        let random = "11".repeat(32);
        let input = format!(
            "CLIENT_EARLY_TRAFFIC_SECRET {random} {}\n\
             CLIENT_HANDSHAKE_TRAFFIC_SECRET {random} {}\n\
             SERVER_HANDSHAKE_TRAFFIC_SECRET {random} {}\n\
             CLIENT_TRAFFIC_SECRET_0 {random} {}\n\
             SERVER_TRAFFIC_SECRET_0 {random} {}\n",
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "66".repeat(32),
        );

        let parsed = SecretStore::parse(input.as_bytes());

        assert!(parsed.diagnostics.is_empty());
        let traffic = parsed.store.traffic(&[0x11; 32]).unwrap();
        assert_eq!(traffic.client_early.as_deref(), Some(&[0x22; 32][..]));
        assert_eq!(
            traffic.server_application_0.as_deref(),
            Some(&[0x66; 32][..])
        );
    }

    #[test]
    fn conflicting_secret_is_reported_and_first_value_wins() {
        let random = "aa".repeat(32);
        let input = format!(
            "CLIENT_TRAFFIC_SECRET_0 {random} {}\nCLIENT_TRAFFIC_SECRET_0 {random} {}\n",
            "01".repeat(32),
            "02".repeat(32),
        );

        let parsed = SecretStore::parse(input.as_bytes());

        assert_eq!(parsed.diagnostics.len(), 1);
        assert_eq!(
            parsed.diagnostics[0].code,
            DiagnosticCode::MalformedDatagram
        );
        assert_eq!(
            parsed
                .store
                .traffic(&[0xaa; 32])
                .unwrap()
                .client_application_0
                .as_deref(),
            Some(&[1; 32][..])
        );
    }

    #[test]
    fn malformed_known_entries_are_rejected_without_storing_secrets() {
        let input = format!(
            "CLIENT_RANDOM 11zz 0011\n\
             CLIENT_TRAFFIC_SECRET_0 11 22\n\
             SERVER_TRAFFIC_SECRET_0 {} 22\n",
            "11".repeat(32),
        );

        let parsed = SecretStore::parse(input.as_bytes());

        assert_eq!(parsed.diagnostics.len(), 3);
        assert!(parsed.store.traffic(&[0x11; 32]).is_none());
        assert_eq!(parsed.store.traffic_secret_count(), 0);
    }

    #[test]
    fn merge_retains_first_conflicting_value_and_accepts_identical_values() {
        let random = "aa".repeat(32);
        let first = SecretStore::parse(
            format!("CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "01".repeat(32)).as_bytes(),
        )
        .store;
        let second = SecretStore::parse(
            format!(
                "CLIENT_TRAFFIC_SECRET_0 {random} {}\nSERVER_TRAFFIC_SECRET_0 {random} {}\n",
                "01".repeat(32),
                "02".repeat(32)
            )
            .as_bytes(),
        )
        .store;
        let conflicting = SecretStore::parse(
            format!("CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "03".repeat(32)).as_bytes(),
        )
        .store;
        let mut merged = first;

        assert!(merged.merge(second).is_empty());
        let diagnostics = merged.merge(conflicting);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagnosticCode::MalformedDatagram);
        let traffic = merged.traffic(&[0xaa; 32]).unwrap();
        assert_eq!(traffic.client_application_0.as_deref(), Some(&[1; 32][..]));
        assert_eq!(traffic.server_application_0.as_deref(), Some(&[2; 32][..]));
    }

    #[test]
    fn traffic_secret_count_counts_labels_not_client_randoms_or_legacy_secrets() {
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let input = format!(
            "CLIENT_RANDOM {first} {}\n\
             CLIENT_EARLY_TRAFFIC_SECRET {first} {}\n\
             CLIENT_HANDSHAKE_TRAFFIC_SECRET {first} {}\n\
             SERVER_TRAFFIC_SECRET_0 {second} {}\n",
            "10".repeat(48),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(48),
        );
        let parsed = SecretStore::parse(input.as_bytes());

        assert!(parsed.diagnostics.is_empty());
        assert_eq!(parsed.store.traffic_secret_count(), 3);
    }

    #[test]
    fn traffic_secrets_default_to_no_populated_labels() {
        assert_eq!(TrafficSecrets::default().populated_label_count(), 0);
    }

    #[allow(deprecated)]
    #[test]
    fn tls_secrets_keeps_legacy_public_maps_and_field_names() {
        let random = "ab".repeat(32);
        let input = format!(
            "CLIENT_RANDOM {random} {}\n\
             CLIENT_HANDSHAKE_TRAFFIC_SECRET {random} {}\n\
             SERVER_HANDSHAKE_TRAFFIC_SECRET {random} {}\n\
             CLIENT_TRAFFIC_SECRET_0 {random} {}\n\
             SERVER_TRAFFIC_SECRET_0 {random} {}\n\
             EXPORTER_SECRET {random} {}\n",
            "01".repeat(48),
            "02".repeat(32),
            "03".repeat(32),
            "04".repeat(32),
            "05".repeat(32),
            "06".repeat(32),
        );
        let mut secrets = crate::tls::TlsSecrets::new();

        secrets.parse_keylog(input.as_bytes());

        assert_eq!(
            secrets
                .client_randoms
                .get(&random)
                .unwrap()
                .master_secret
                .as_deref(),
            Some(&[0x01; 48][..])
        );
        let traffic = secrets.traffic_secrets.get(&random).unwrap();
        assert_eq!(
            traffic.client_handshake_traffic_secret.as_deref(),
            Some(&[0x02; 32][..])
        );
        assert_eq!(
            traffic.server_handshake_traffic_secret.as_deref(),
            Some(&[0x03; 32][..])
        );
        assert_eq!(
            traffic.client_traffic_secret_0.as_deref(),
            Some(&[0x04; 32][..])
        );
        assert_eq!(
            traffic.server_traffic_secret_0.as_deref(),
            Some(&[0x05; 32][..])
        );
        assert_eq!(traffic.exporter_secret.as_deref(), Some(&[0x06; 32][..]));
    }
}
