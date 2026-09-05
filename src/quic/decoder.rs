use super::connection::{ConnectionRegistry, NetworkPath, RegistryError};
use super::crypto::{
    ApplicationKeySet, DirectionalKeys, QuicCipherSuite, QuicCryptoProvider, RustCryptoProvider,
};
use super::frame::{decode_all, QuicFrame};
use super::packet::{
    inspect_long_header, AuthenticatedPacket, DefaultPacketCodec, LongHeaderInfo, PacketCodec,
    PacketDecodeError, ProtectedPacket,
};
use super::reassembly::{SharedBudget, SparseReassembler, StreamLimits};
use super::tls::{TlsHandshakeMetadata, TlsHandshakeParser};
use super::types::{ConnectionId, Direction, EncryptionLevel, EndpointRole, PacketType};
use super::version::QuicVersion;
use crate::capture::DatagramRecord;
use crate::diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope};
use crate::secrets::SecretStore;
use crate::DecodeLimits;
use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicEvent {
    CryptoData {
        connection: ConnectionId,
        direction: Direction,
        level: EncryptionLevel,
        data: Vec<u8>,
        timestamp_ns: u64,
    },
    StreamData {
        connection: ConnectionId,
        client: SocketAddr,
        server: SocketAddr,
        direction: Direction,
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
        timestamp_ns: u64,
    },
    StreamFinished {
        connection: ConnectionId,
        client: SocketAddr,
        server: SocketAddr,
        direction: Direction,
        stream_id: u64,
        timestamp_ns: u64,
    },
    ConnectionDiagnostic {
        connection: ConnectionId,
        diagnostic: Diagnostic,
    },
}

struct ConnectionRuntime {
    version: QuicVersion,
    initial: HashMap<EndpointRole, DirectionalKeys>,
    handshake: HashMap<EndpointRole, DirectionalKeys>,
    zero_rtt: Option<DirectionalKeys>,
    application: HashMap<EndpointRole, ApplicationKeySet>,
    application_phase: HashMap<EndpointRole, bool>,
    crypto_streams: BTreeMap<(Direction, EncryptionLevel), SparseReassembler>,
    tls_parsers: BTreeMap<(Direction, EncryptionLevel), TlsHandshakeParser>,
    metadata: TlsHandshakeMetadata,
    streams: BTreeMap<(Direction, u64), SparseReassembler>,
    finished_streams: BTreeSet<(Direction, u64)>,
    budget: SharedBudget,
}

impl ConnectionRuntime {
    fn new(
        version: QuicVersion,
        initial_dcid: &[u8],
        limits: &DecodeLimits,
        provider: &dyn QuicCryptoProvider,
    ) -> Result<Self, super::crypto::CryptoError> {
        let profile = version.profile();
        let initial = [EndpointRole::Client, EndpointRole::Server]
            .into_iter()
            .map(|role| {
                provider
                    .derive_initial_keys(profile, initial_dcid, role)
                    .map(|keys| (role, keys))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(Self {
            version,
            initial,
            handshake: HashMap::new(),
            zero_rtt: None,
            application: HashMap::new(),
            application_phase: HashMap::new(),
            crypto_streams: BTreeMap::new(),
            tls_parsers: BTreeMap::new(),
            metadata: TlsHandshakeMetadata::default(),
            streams: BTreeMap::new(),
            finished_streams: BTreeSet::new(),
            budget: SharedBudget::new(limits.max_connection_bytes),
        })
    }

    fn replace_initial_keys(
        &mut self,
        initial_dcid: &[u8],
        provider: &dyn QuicCryptoProvider,
    ) -> Result<(), super::crypto::CryptoError> {
        let profile = self.version.profile();
        for role in [EndpointRole::Client, EndpointRole::Server] {
            let keys = provider.derive_initial_keys(profile, initial_dcid, role)?;
            self.initial.insert(role, keys);
        }
        Ok(())
    }
}

pub struct QuicPassiveDecoder {
    limits: DecodeLimits,
    secrets: SecretStore,
    registry: ConnectionRegistry,
    crypto: RustCryptoProvider,
    codec: DefaultPacketCodec,
    runtimes: HashMap<ConnectionId, ConnectionRuntime>,
    events: Vec<QuicEvent>,
    diagnostics: Vec<Diagnostic>,
    pending: Vec<DatagramRecord>,
    pending_bytes: usize,
    pending_attempts: HashMap<u64, u8>,
    authenticated_packets: u64,
    event_bytes: usize,
    event_limit_reported: bool,
}

impl QuicPassiveDecoder {
    pub fn new(limits: DecodeLimits, secrets: SecretStore) -> Self {
        Self {
            registry: ConnectionRegistry::new(limits.clone()),
            limits,
            secrets,
            crypto: RustCryptoProvider,
            codec: DefaultPacketCodec,
            runtimes: HashMap::new(),
            events: Vec::new(),
            diagnostics: Vec::new(),
            pending: Vec::new(),
            pending_bytes: 0,
            pending_attempts: HashMap::new(),
            authenticated_packets: 0,
            event_bytes: 0,
            event_limit_reported: false,
        }
    }

    pub fn accepts(&self, datagram: &DatagramRecord) -> bool {
        let Some(first) = datagram.payload.first().copied() else {
            return false;
        };
        if first & 0x40 == 0 {
            return false;
        }
        if first & 0x80 != 0 {
            return inspect_long_header(&datagram.payload, 0).is_ok();
        }
        let path = NetworkPath::new(datagram.src, datagram.dst);
        !self
            .registry
            .short_header_candidates(
                &path,
                &datagram.payload[1..],
                self.limits.max_packet_key_attempts,
            )
            .is_empty()
    }

    pub fn ingest(&mut self, datagram: DatagramRecord) {
        let connections_before = self.runtimes.len();
        let authenticated_before = self.authenticated_packets;
        self.ingest_inner(&datagram);
        if self.runtimes.len() > connections_before {
            self.replay_pending();
        } else if self.authenticated_packets == authenticated_before {
            self.queue_pending(datagram);
        }
    }

    fn ingest_inner(&mut self, datagram: &DatagramRecord) {
        let Some(first) = datagram.payload.first().copied() else {
            return;
        };
        if first & 0x40 == 0 {
            return;
        }
        if first & 0x80 != 0 {
            self.ingest_long(datagram);
        } else {
            self.ingest_short(datagram);
        }
    }

    pub fn connection_count(&self) -> usize {
        self.runtimes.len()
    }

    pub fn take_events(&mut self) -> Vec<QuicEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub fn finish(&mut self) -> (Vec<QuicEvent>, Vec<Diagnostic>) {
        if !self.pending.is_empty() {
            self.push_diagnostic(Diagnostic::warning(
                DiagnosticCode::MissingSecret,
                DiagnosticScope::Capture,
                "some QUIC packets could not be decrypted with the available secrets",
            ));
        }
        self.runtimes.clear();
        self.pending.clear();
        self.pending_bytes = 0;
        (
            std::mem::take(&mut self.events),
            std::mem::take(&mut self.diagnostics),
        )
    }

    fn ingest_long(&mut self, datagram: &DatagramRecord) {
        let mut offset = 0usize;
        while offset < datagram.payload.len() {
            let header = match inspect_long_header(&datagram.payload, offset) {
                Ok(header) => header,
                Err(_) => {
                    self.datagram_diagnostic(
                        datagram.packet_index,
                        DiagnosticCode::MalformedDatagram,
                        "malformed or unsupported QUIC long header",
                    );
                    break;
                }
            };
            if header.packet_type == PacketType::Retry {
                self.handle_retry(datagram, &header, offset);
                break;
            }
            let consumed = header.packet_len;
            self.decrypt_long_packet(datagram, &header, offset);
            offset = match offset.checked_add(consumed) {
                Some(next) if next > offset => next,
                _ => break,
            };
            if datagram
                .payload
                .get(offset)
                .is_some_and(|byte| byte & 0x80 == 0)
            {
                self.ingest_short_at(datagram, offset);
                break;
            }
        }
    }

    fn decrypt_long_packet(
        &mut self,
        datagram: &DatagramRecord,
        header: &LongHeaderInfo,
        offset: usize,
    ) {
        let version = header.version;
        let level = match header.packet_type.encryption_level() {
            Some(level) => level,
            None => return,
        };
        let path = NetworkPath::new(datagram.src, datagram.dst);
        let resolved = self.registry.resolve_cid(&header.dcid).or_else(|| {
            self.registry
                .resolve_path(&path)
                .map(|(id, direction)| (id, direction.sender()))
        });
        if resolved.is_none() && header.packet_type != PacketType::Initial {
            return;
        }
        let (connection, sender, largest) = if let Some((id, sender)) = resolved {
            let largest = self.registry.get(id).and_then(|state| {
                state
                    .direction_state(sender.direction())
                    .packet_numbers(level)
                    .largest
            });
            (Some(id), sender, largest)
        } else {
            (None, EndpointRole::Client, None)
        };

        let decoded = if let Some(id) = connection {
            let Some(runtime) = self.runtimes.get(&id) else {
                return;
            };
            let keys = match level {
                EncryptionLevel::Initial => runtime.initial.get(&sender),
                EncryptionLevel::Handshake => runtime.handshake.get(&sender),
                EncryptionLevel::ZeroRtt => runtime.zero_rtt.as_ref(),
                EncryptionLevel::OneRtt => None,
            };
            let Some(keys) = keys else {
                self.queue_pending(datagram.clone());
                return;
            };
            self.codec.decode(
                ProtectedPacket {
                    datagram: &datagram.payload,
                    offset,
                    version: version.profile(),
                    dcid_len: None,
                    largest_packet_number: largest,
                },
                keys.header_key(),
                keys.packet_key(),
            )
        } else {
            let Ok(keys) = self.crypto.derive_initial_keys(
                version.profile(),
                &header.dcid,
                EndpointRole::Client,
            ) else {
                return;
            };
            self.codec.decode(
                ProtectedPacket {
                    datagram: &datagram.payload,
                    offset,
                    version: version.profile(),
                    dcid_len: None,
                    largest_packet_number: None,
                },
                keys.header_key(),
                keys.packet_key(),
            )
        };

        let authenticated = match decoded {
            Ok(packet) => packet,
            Err(
                PacketDecodeError::AuthenticationFailed | PacketDecodeError::InvalidReservedBits,
            ) => {
                if let Some(id) = connection {
                    self.connection_diagnostic(
                        id,
                        DiagnosticCode::AuthenticationFailed,
                        "QUIC packet authentication failed",
                    );
                }
                return;
            }
            Err(_) => return,
        };

        let id = if let Some(id) = connection {
            id
        } else {
            let path = NetworkPath::new(datagram.src, datagram.dst);
            let Ok(id) = self.registry.observe_client_initial(
                path,
                header.dcid.clone(),
                header.scid.clone(),
                version,
            ) else {
                self.datagram_diagnostic(
                    datagram.packet_index,
                    DiagnosticCode::ResourceLimit,
                    "QUIC connection registry limit exceeded",
                );
                return;
            };
            let Ok(runtime) =
                ConnectionRuntime::new(version, &header.dcid, &self.limits, &self.crypto)
            else {
                return;
            };
            self.runtimes.insert(id, runtime);
            id
        };
        self.commit_and_process(id, sender.direction(), level, authenticated, datagram);
    }

    fn ingest_short(&mut self, datagram: &DatagramRecord) {
        self.ingest_short_at(datagram, 0);
    }

    fn ingest_short_at(&mut self, datagram: &DatagramRecord, offset: usize) {
        let Some(after_first) = datagram.payload.get(offset + 1..) else {
            return;
        };
        let path = NetworkPath::new(datagram.src, datagram.dst);
        let candidates = self.registry.short_header_candidates(
            &path,
            after_first,
            self.limits.max_packet_key_attempts,
        );
        let mut attempts = 0usize;
        for (id, sender, dcid_len) in candidates {
            let direction = sender.direction();
            let largest = self
                .registry
                .get(id)
                .and_then(|state| state.direction_state(direction).application.largest);
            let Some(runtime) = self.runtimes.get(&id) else {
                continue;
            };
            let Some(keys) = runtime.application.get(&sender) else {
                self.queue_pending(datagram.clone());
                continue;
            };
            let key_candidates = [
                (KeyCandidate::Current, Some(keys.current().packet_key())),
                (KeyCandidate::Next, Some(keys.next().packet_key())),
                (
                    KeyCandidate::Previous,
                    keys.previous().map(|epoch| epoch.packet_key()),
                ),
            ];
            let mut success = None;
            for (candidate, packet_key) in key_candidates {
                let Some(packet_key) = packet_key else {
                    continue;
                };
                if attempts >= self.limits.max_packet_key_attempts {
                    break;
                }
                attempts += 1;
                let result = self.codec.decode(
                    ProtectedPacket {
                        datagram: &datagram.payload,
                        offset,
                        version: runtime.version.profile(),
                        dcid_len: Some(dcid_len),
                        largest_packet_number: largest,
                    },
                    keys.header_key(),
                    packet_key,
                );
                if let Ok(packet) = result {
                    success = Some((candidate, packet));
                    break;
                }
            }
            let Some((candidate, packet)) = success else {
                continue;
            };
            if candidate == KeyCandidate::Next
                && largest.is_none_or(|value| packet.packet_number > value)
            {
                let runtime = self.runtimes.get_mut(&id).unwrap();
                let suite = packet_key_suite(runtime, sender);
                let profile = runtime.version.profile();
                let phase = runtime.application_phase.entry(sender).or_insert(false);
                if packet.key_phase != *phase
                    && runtime
                        .application
                        .get_mut(&sender)
                        .unwrap()
                        .rotate(&self.crypto, profile, suite)
                        .is_ok()
                {
                    *phase = packet.key_phase;
                }
            }
            let _ = self
                .registry
                .bind_authenticated_path(id, path.clone(), direction);
            self.commit_and_process(id, direction, EncryptionLevel::OneRtt, packet, datagram);
            return;
        }
    }

    fn handle_retry(&mut self, datagram: &DatagramRecord, header: &LongHeaderInfo, offset: usize) {
        let Some((id, sender)) = self.registry.resolve_cid(&header.dcid) else {
            return;
        };
        if sender != EndpointRole::Server {
            return;
        }
        let Some(state) = self.registry.get(id) else {
            return;
        };
        let packet_end = offset.saturating_add(header.packet_len);
        let Some(packet) = datagram.payload.get(offset..packet_end) else {
            return;
        };
        if self
            .codec
            .verify_retry(header.version.profile(), &state.original_dcid, packet)
            .is_err()
        {
            self.connection_diagnostic(
                id,
                DiagnosticCode::AuthenticationFailed,
                "QUIC Retry integrity validation failed",
            );
            return;
        }
        if self
            .registry
            .apply_verified_retry(id, header.scid.clone())
            .is_err()
        {
            self.connection_diagnostic(
                id,
                DiagnosticCode::ResourceLimit,
                "QUIC Retry exceeded connection limits",
            );
            return;
        }
        if let Some(runtime) = self.runtimes.get_mut(&id) {
            let _ = runtime.replace_initial_keys(&header.scid, &self.crypto);
        }
    }

    fn commit_and_process(
        &mut self,
        id: ConnectionId,
        direction: Direction,
        level: EncryptionLevel,
        packet: AuthenticatedPacket,
        datagram: &DatagramRecord,
    ) {
        let Some(state) = self.registry.get_mut(id) else {
            return;
        };
        if !state
            .direction_state_mut(direction)
            .packet_numbers_mut(level)
            .commit_authenticated(packet.packet_number)
        {
            return;
        }
        self.authenticated_packets = self.authenticated_packets.saturating_add(1);
        self.pending_attempts.remove(&datagram.packet_index);
        let _ = self
            .registry
            .add_authenticated_alias(id, direction.sender(), packet.scid.clone());
        let limits = self.limits.clone();
        let frames = match decode_all(&packet.payload, &limits) {
            Ok(frames) => frames,
            Err(_) => {
                self.connection_diagnostic(
                    id,
                    DiagnosticCode::MalformedDatagram,
                    "authenticated QUIC packet contains malformed frames",
                );
                return;
            }
        };
        for frame in frames {
            match frame {
                QuicFrame::Crypto { offset, data } => {
                    self.process_crypto(id, direction, level, offset, data, datagram.timestamp_ns);
                }
                QuicFrame::Stream {
                    id: stream_id,
                    offset,
                    fin,
                    data,
                } => self.process_stream(
                    id,
                    direction,
                    stream_id,
                    offset,
                    data,
                    fin,
                    datagram.timestamp_ns,
                ),
                QuicFrame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    connection_id,
                    reset_token,
                } => {
                    let owner = direction.sender();
                    for retired in 0..retire_prior_to {
                        let _ = self.registry.retire_authenticated_cid(id, owner, retired);
                    }
                    if let Err(error) = self.registry.add_authenticated_cid(
                        id,
                        owner,
                        sequence,
                        connection_id.to_vec(),
                        reset_token,
                    ) {
                        self.registry_error(id, error);
                    }
                }
                QuicFrame::RetireConnectionId(sequence) => {
                    let _ = self.registry.retire_authenticated_cid(
                        id,
                        direction.sender().peer(),
                        sequence,
                    );
                }
                _ => {}
            }
        }
    }

    fn process_crypto(
        &mut self,
        id: ConnectionId,
        direction: Direction,
        level: EncryptionLevel,
        offset: u64,
        data: &[u8],
        timestamp_ns: u64,
    ) {
        let Some(runtime) = self.runtimes.get_mut(&id) else {
            return;
        };
        let limits = StreamLimits::from_decode_limits(&self.limits, runtime.budget.clone());
        let reassembler = runtime
            .crypto_streams
            .entry((direction, level))
            .or_insert_with(|| SparseReassembler::new(limits));
        let contiguous = match reassembler.insert(offset, data, false) {
            Ok(data) => data,
            Err(_) => {
                self.connection_diagnostic(
                    id,
                    DiagnosticCode::ResourceLimit,
                    "QUIC CRYPTO stream reassembly failed or exceeded limits",
                );
                return;
            }
        };
        if contiguous.is_empty() {
            return;
        }
        let parser = runtime
            .tls_parsers
            .entry((direction, level))
            .or_insert_with(|| TlsHandshakeParser::new(self.limits.max_header_section_bytes));
        if parser.ingest(&contiguous).is_err() {
            self.connection_diagnostic(
                id,
                DiagnosticCode::MalformedDatagram,
                "QUIC TLS handshake metadata is malformed",
            );
            return;
        }
        merge_metadata(&mut runtime.metadata, parser.metadata());
        self.push_event(
            QuicEvent::CryptoData {
                connection: id,
                direction,
                level,
                data: contiguous.clone(),
                timestamp_ns,
            },
            contiguous.len(),
        );
        self.refresh_traffic_keys(id);
    }

    #[allow(clippy::too_many_arguments)]
    fn process_stream(
        &mut self,
        id: ConnectionId,
        direction: Direction,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
        timestamp_ns: u64,
    ) {
        let Some(state) = self.registry.get(id) else {
            return;
        };
        let (client, server) = (state.client, state.server);
        let Some(runtime) = self.runtimes.get_mut(&id) else {
            return;
        };
        if !runtime.streams.contains_key(&(direction, stream_id))
            && runtime.streams.len() >= self.limits.max_streams_per_connection
        {
            self.connection_diagnostic(
                id,
                DiagnosticCode::ResourceLimit,
                "QUIC stream count limit exceeded",
            );
            return;
        }
        let limits = StreamLimits::from_decode_limits(&self.limits, runtime.budget.clone());
        let reassembler = runtime
            .streams
            .entry((direction, stream_id))
            .or_insert_with(|| SparseReassembler::new(limits));
        let contiguous = match reassembler.insert(offset, data, fin) {
            Ok(data) => data,
            Err(_) => {
                self.connection_diagnostic(
                    id,
                    DiagnosticCode::ResourceLimit,
                    "QUIC stream reassembly failed or exceeded limits",
                );
                return;
            }
        };
        let finished = reassembler.is_finished();
        let newly_finished = finished && runtime.finished_streams.insert((direction, stream_id));
        if !contiguous.is_empty() {
            let charge = contiguous.len();
            self.push_event(
                QuicEvent::StreamData {
                    connection: id,
                    client,
                    server,
                    direction,
                    stream_id,
                    data: contiguous,
                    fin: finished,
                    timestamp_ns,
                },
                charge,
            );
        }
        if newly_finished {
            self.push_event(
                QuicEvent::StreamFinished {
                    connection: id,
                    client,
                    server,
                    direction,
                    stream_id,
                    timestamp_ns,
                },
                0,
            );
        }
    }

    fn refresh_traffic_keys(&mut self, id: ConnectionId) {
        let Some(runtime) = self.runtimes.get_mut(&id) else {
            return;
        };
        let (Some(random), Some(suite)) = (
            runtime.metadata.client_random,
            runtime.metadata.cipher_suite,
        ) else {
            return;
        };
        let Some(secrets) = self.secrets.traffic(&random) else {
            return;
        };
        let profile = runtime.version.profile();
        let mut changed = false;
        for (role, secret) in [
            (EndpointRole::Client, secrets.client_handshake.as_deref()),
            (EndpointRole::Server, secrets.server_handshake.as_deref()),
        ] {
            if let Entry::Vacant(entry) = runtime.handshake.entry(role) {
                if let Some(secret) = secret {
                    if let Ok(keys) = self.crypto.derive_traffic_keys(profile, suite, secret) {
                        entry.insert(keys);
                        changed = true;
                    }
                }
            }
        }
        if runtime.zero_rtt.is_none() {
            if let Some(secret) = secrets.client_early.as_deref() {
                runtime.zero_rtt = self.crypto.derive_traffic_keys(profile, suite, secret).ok();
                changed |= runtime.zero_rtt.is_some();
            }
        }
        for (role, secret) in [
            (
                EndpointRole::Client,
                secrets.client_application_0.as_deref(),
            ),
            (
                EndpointRole::Server,
                secrets.server_application_0.as_deref(),
            ),
        ] {
            if let Entry::Vacant(entry) = runtime.application.entry(role) {
                if let Some(secret) = secret {
                    if let Ok(keys) = ApplicationKeySet::new(&self.crypto, profile, suite, secret) {
                        entry.insert(keys);
                        runtime.application_phase.insert(role, false);
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.replay_pending();
        }
    }

    fn datagram_diagnostic(
        &mut self,
        packet_index: u64,
        code: DiagnosticCode,
        message: &'static str,
    ) {
        self.push_diagnostic(Diagnostic::warning(
            code,
            DiagnosticScope::Datagram {
                index: packet_index,
            },
            message,
        ));
    }

    fn connection_diagnostic(
        &mut self,
        id: ConnectionId,
        code: DiagnosticCode,
        message: &'static str,
    ) {
        let diagnostic = Diagnostic::warning(
            code,
            DiagnosticScope::Connection { connection: id.0 },
            message,
        );
        self.push_event(
            QuicEvent::ConnectionDiagnostic {
                connection: id,
                diagnostic: diagnostic.clone(),
            },
            128,
        );
        self.push_diagnostic(diagnostic);
    }

    fn registry_error(&mut self, id: ConnectionId, error: RegistryError) {
        let code = if error == RegistryError::ResourceLimit {
            DiagnosticCode::ResourceLimit
        } else {
            DiagnosticCode::MalformedDatagram
        };
        self.connection_diagnostic(id, code, "authenticated QUIC CID update was rejected");
    }

    fn queue_pending(&mut self, datagram: DatagramRecord) {
        let attempts = self
            .pending_attempts
            .entry(datagram.packet_index)
            .or_default();
        if *attempts >= 2
            || self
                .pending
                .iter()
                .any(|queued| queued.packet_index == datagram.packet_index)
        {
            return;
        }
        let Some(next) = self.pending_bytes.checked_add(datagram.payload.len()) else {
            return;
        };
        if next > self.limits.max_connection_bytes {
            return;
        }
        *attempts += 1;
        self.pending_bytes = next;
        self.pending.push(datagram);
    }

    fn replay_pending(&mut self) {
        let mut pending = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        pending.sort_by_key(|packet| (packet.timestamp_ns, packet.packet_index));
        for packet in pending {
            self.ingest_inner(&packet);
        }
    }

    fn push_event(&mut self, event: QuicEvent, bytes: usize) -> bool {
        let Some(next) = self.event_bytes.checked_add(bytes) else {
            self.note_event_limit();
            return false;
        };
        if next > self.limits.max_total_buffered_bytes {
            self.note_event_limit();
            return false;
        }
        self.event_bytes = next;
        self.events.push(event);
        true
    }

    fn note_event_limit(&mut self) {
        if self.event_limit_reported {
            return;
        }
        self.event_limit_reported = true;
        self.push_diagnostic(Diagnostic::warning(
            DiagnosticCode::ResourceLimit,
            DiagnosticScope::Capture,
            "QUIC decoded event buffer exceeded the configured total limit",
        ));
    }

    fn push_diagnostic(&mut self, diagnostic: Diagnostic) {
        const DIAGNOSTIC_BUDGET_BYTES: usize = 128;
        let maximum = self
            .limits
            .max_total_buffered_bytes
            .checked_div(DIAGNOSTIC_BUDGET_BYTES)
            .unwrap_or_default();
        if self.diagnostics.len() < maximum {
            self.diagnostics.push(diagnostic);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCandidate {
    Previous,
    Current,
    Next,
}

fn packet_key_suite(runtime: &ConnectionRuntime, sender: EndpointRole) -> QuicCipherSuite {
    runtime
        .application
        .get(&sender)
        .expect("application keys exist")
        .current()
        .packet_key()
        .suite()
}

fn merge_metadata(target: &mut TlsHandshakeMetadata, source: &TlsHandshakeMetadata) {
    if source.client_random.is_some() {
        target.client_random = source.client_random;
    }
    if source.cipher_suite.is_some() {
        target.cipher_suite = source.cipher_suite;
    }
    if !source.offered_alpns.is_empty() {
        target.offered_alpns.clone_from(&source.offered_alpns);
    }
    if source.selected_alpn.is_some() {
        target.selected_alpn.clone_from(&source.selected_alpn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn datagram(payload: Vec<u8>) -> DatagramRecord {
        DatagramRecord {
            packet_index: 1,
            timestamp_ns: 2,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55_555),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            payload,
        }
    }

    #[test]
    fn does_not_select_udp_by_port() {
        let decoder = QuicPassiveDecoder::new(DecodeLimits::testing(), SecretStore::new());
        assert!(!decoder.accepts(&datagram(b"not quic".to_vec())));
        assert!(!decoder.accepts(&datagram(vec![0x40, 0, 0, 0])));
    }
}
