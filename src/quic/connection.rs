use super::types::{ConnectionId, Direction, EncryptionLevel, EndpointRole};
use super::version::QuicVersion;
use crate::DecodeLimits;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;

const PACKET_NUMBER_WINDOW: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkPath {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl NetworkPath {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }

    fn reversed(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketNumberState {
    pub largest: Option<u64>,
    seen: BTreeSet<u64>,
}

impl PacketNumberState {
    pub fn reconstruct(&self, truncated: u64, packet_number_len: usize) -> Option<u64> {
        reconstruct_packet_number(self.largest, truncated, packet_number_len)
    }

    pub fn contains(&self, packet_number: u64) -> bool {
        self.seen.contains(&packet_number)
    }

    pub fn commit_authenticated(&mut self, packet_number: u64) -> bool {
        if !self.seen.insert(packet_number) {
            return false;
        }
        self.largest = Some(
            self.largest
                .map_or(packet_number, |value| value.max(packet_number)),
        );
        if self.seen.len() > PACKET_NUMBER_WINDOW {
            let retain_from = self
                .largest
                .unwrap_or_default()
                .saturating_sub(PACKET_NUMBER_WINDOW as u64);
            self.seen = self.seen.split_off(&retain_from);
        }
        true
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectionState {
    pub initial: PacketNumberState,
    pub handshake: PacketNumberState,
    pub application: PacketNumberState,
}

impl DirectionState {
    pub fn packet_numbers(&self, level: EncryptionLevel) -> &PacketNumberState {
        match level {
            EncryptionLevel::Initial => &self.initial,
            EncryptionLevel::Handshake => &self.handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &self.application,
        }
    }

    pub fn packet_numbers_mut(&mut self, level: EncryptionLevel) -> &mut PacketNumberState {
        match level {
            EncryptionLevel::Initial => &mut self.initial,
            EncryptionLevel::Handshake => &mut self.handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &mut self.application,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuicConnectionState {
    pub id: ConnectionId,
    pub version: QuicVersion,
    pub original_dcid: Vec<u8>,
    pub current_initial_dcid: Vec<u8>,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub client_to_server: DirectionState,
    pub server_to_client: DirectionState,
    cids: BTreeMap<(EndpointRole, u64), Vec<u8>>,
    largest_cid_sequence: HashMap<EndpointRole, u64>,
    paths: BTreeSet<(SocketAddr, SocketAddr)>,
}

impl QuicConnectionState {
    pub fn direction_state(&self, direction: Direction) -> &DirectionState {
        match direction {
            Direction::ClientToServer => &self.client_to_server,
            Direction::ServerToClient => &self.server_to_client,
        }
    }

    pub fn direction_state_mut(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::ClientToServer => &mut self.client_to_server,
            Direction::ServerToClient => &mut self.server_to_client,
        }
    }
}

#[derive(Debug, Clone)]
struct CidBinding {
    connection: ConnectionId,
    owner: EndpointRole,
    sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("QUIC connection or CID limit exceeded")]
    ResourceLimit,
    #[error("unknown QUIC connection")]
    UnknownConnection,
    #[error("QUIC connection ID sequence regressed")]
    SequenceRegression,
    #[error("invalid QUIC connection ID")]
    InvalidCid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshot {
    connection_count: usize,
    cid_count: usize,
    path_count: usize,
    next_id: u64,
}

pub struct ConnectionRegistry {
    limits: DecodeLimits,
    next_id: u64,
    connections: HashMap<ConnectionId, QuicConnectionState>,
    cid_index: HashMap<Vec<u8>, CidBinding>,
    path_index: HashMap<NetworkPath, (ConnectionId, Direction)>,
    creation_order: VecDeque<ConnectionId>,
}

impl ConnectionRegistry {
    pub fn new(limits: DecodeLimits) -> Self {
        Self {
            limits,
            next_id: 1,
            connections: HashMap::new(),
            cid_index: HashMap::new(),
            path_index: HashMap::new(),
            creation_order: VecDeque::new(),
        }
    }

    pub fn observe_client_initial(
        &mut self,
        path: NetworkPath,
        dcid: Vec<u8>,
        scid: Vec<u8>,
        version: QuicVersion,
    ) -> Result<ConnectionId, RegistryError> {
        if dcid.len() > 20 || scid.len() > 20 {
            return Err(RegistryError::InvalidCid);
        }
        if let Some(binding) = self.cid_index.get(&dcid) {
            return Ok(binding.connection);
        }
        if self.connections.len() >= self.limits.max_connections {
            return Err(RegistryError::ResourceLimit);
        }
        let id = ConnectionId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(RegistryError::ResourceLimit)?;
        let mut connection = QuicConnectionState {
            id,
            version,
            original_dcid: dcid.clone(),
            current_initial_dcid: dcid.clone(),
            client: path.src,
            server: path.dst,
            client_to_server: DirectionState::default(),
            server_to_client: DirectionState::default(),
            cids: BTreeMap::new(),
            largest_cid_sequence: HashMap::new(),
            paths: BTreeSet::new(),
        };
        connection.paths.insert((path.src, path.dst));
        connection
            .cids
            .insert((EndpointRole::Server, 0), dcid.clone());
        if !dcid.is_empty() {
            connection
                .largest_cid_sequence
                .insert(EndpointRole::Server, 0);
            self.cid_index.insert(
                dcid,
                CidBinding {
                    connection: id,
                    owner: EndpointRole::Server,
                    sequence: 0,
                },
            );
        }
        connection
            .cids
            .insert((EndpointRole::Client, 0), scid.clone());
        if !scid.is_empty() {
            connection
                .largest_cid_sequence
                .insert(EndpointRole::Client, 0);
            self.cid_index.insert(
                scid,
                CidBinding {
                    connection: id,
                    owner: EndpointRole::Client,
                    sequence: 0,
                },
            );
        }
        self.path_index
            .insert(path.clone(), (id, Direction::ClientToServer));
        self.path_index
            .insert(path.reversed(), (id, Direction::ServerToClient));
        self.creation_order.push_back(id);
        self.connections.insert(id, connection);
        Ok(id)
    }

    pub fn add_authenticated_cid(
        &mut self,
        id: ConnectionId,
        owner: EndpointRole,
        sequence: u64,
        cid: Vec<u8>,
        _reset_token: [u8; 16],
    ) -> Result<(), RegistryError> {
        if cid.is_empty() || cid.len() > 20 {
            return Err(RegistryError::InvalidCid);
        }
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(RegistryError::UnknownConnection)?;
        if connection.cids.len() >= self.limits.max_cids_per_connection {
            return Err(RegistryError::ResourceLimit);
        }
        if let Some(largest) = connection.largest_cid_sequence.get(&owner) {
            if sequence < *largest {
                return Err(RegistryError::SequenceRegression);
            }
        }
        if let Some(existing) = self.cid_index.get(&cid) {
            if existing.connection != id || existing.owner != owner || existing.sequence != sequence
            {
                return Err(RegistryError::InvalidCid);
            }
            return Ok(());
        }
        connection.cids.insert((owner, sequence), cid.clone());
        connection.largest_cid_sequence.insert(owner, sequence);
        self.cid_index.insert(
            cid,
            CidBinding {
                connection: id,
                owner,
                sequence,
            },
        );
        Ok(())
    }

    pub fn retire_authenticated_cid(
        &mut self,
        id: ConnectionId,
        owner: EndpointRole,
        sequence: u64,
    ) -> Result<(), RegistryError> {
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(RegistryError::UnknownConnection)?;
        if let Some(cid) = connection.cids.remove(&(owner, sequence)) {
            self.cid_index.remove(&cid);
        }
        Ok(())
    }

    pub fn resolve_short(
        &self,
        path: &NetworkPath,
        dcid: &[u8],
    ) -> Option<(ConnectionId, EndpointRole)> {
        let binding = self.cid_index.get(dcid)?;
        let sender = binding.owner.peer();
        let expected_direction = sender.direction();
        if let Some((path_connection, direction)) = self.path_index.get(path) {
            if *path_connection != binding.connection || *direction != expected_direction {
                return None;
            }
        }
        Some((binding.connection, sender))
    }

    pub fn resolve_cid(&self, dcid: &[u8]) -> Option<(ConnectionId, EndpointRole)> {
        let binding = self.cid_index.get(dcid)?;
        Some((binding.connection, binding.owner.peer()))
    }

    pub fn resolve_path(&self, path: &NetworkPath) -> Option<(ConnectionId, Direction)> {
        self.path_index.get(path).copied()
    }

    pub fn cid_lengths_for_path(&self, path: &NetworkPath) -> Vec<usize> {
        let Some((connection, _)) = self.path_index.get(path) else {
            return Vec::new();
        };
        let mut lengths: Vec<_> = self
            .connections
            .get(connection)
            .into_iter()
            .flat_map(|state| state.cids.values().map(Vec::len))
            .collect();
        lengths.sort_unstable();
        lengths.dedup();
        lengths
    }

    pub fn short_header_candidates(
        &self,
        path: &NetworkPath,
        bytes_after_first: &[u8],
        limit: usize,
    ) -> Vec<(ConnectionId, EndpointRole, usize)> {
        let mut candidates = Vec::new();
        if let Some((connection, direction)) = self.path_index.get(path) {
            let sender = direction.sender();
            let receiver = sender.peer();
            if self.connections.get(connection).is_some_and(|state| {
                state
                    .cids
                    .iter()
                    .any(|((owner, _), cid)| *owner == receiver && cid.is_empty())
            }) {
                candidates.push((*connection, sender, 0));
            }
        }
        for (cid, binding) in &self.cid_index {
            if candidates.len() >= limit {
                break;
            }
            if bytes_after_first.starts_with(cid) {
                let sender = binding.owner.peer();
                if let Some((path_connection, direction)) = self.path_index.get(path) {
                    if *path_connection != binding.connection || direction.sender() != sender {
                        continue;
                    }
                }
                candidates.push((binding.connection, sender, cid.len()));
            }
        }
        candidates.sort_unstable_by_key(|(connection, _, length)| (*connection, *length));
        candidates
    }

    pub fn add_authenticated_alias(
        &mut self,
        id: ConnectionId,
        owner: EndpointRole,
        cid: Vec<u8>,
    ) -> Result<(), RegistryError> {
        if cid.is_empty() {
            return Ok(());
        }
        if let Some(existing) = self.cid_index.get(&cid) {
            return (existing.connection == id && existing.owner == owner)
                .then_some(())
                .ok_or(RegistryError::InvalidCid);
        }
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(RegistryError::UnknownConnection)?;
        if connection.cids.len() >= self.limits.max_cids_per_connection {
            return Err(RegistryError::ResourceLimit);
        }
        let sequence = u64::MAX
            .checked_sub(connection.cids.len() as u64)
            .ok_or(RegistryError::ResourceLimit)?;
        connection.cids.insert((owner, sequence), cid.clone());
        self.cid_index.insert(
            cid,
            CidBinding {
                connection: id,
                owner,
                sequence,
            },
        );
        Ok(())
    }

    pub fn bind_authenticated_path(
        &mut self,
        id: ConnectionId,
        path: NetworkPath,
        direction: Direction,
    ) -> Result<(), RegistryError> {
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(RegistryError::UnknownConnection)?;
        connection.paths.insert((path.src, path.dst));
        self.path_index.insert(path, (id, direction));
        Ok(())
    }

    pub fn apply_verified_retry(
        &mut self,
        id: ConnectionId,
        new_initial_dcid: Vec<u8>,
    ) -> Result<(), RegistryError> {
        if new_initial_dcid.is_empty() || new_initial_dcid.len() > 20 {
            return Err(RegistryError::InvalidCid);
        }
        let connection = self
            .connections
            .get_mut(&id)
            .ok_or(RegistryError::UnknownConnection)?;
        if connection.cids.len() >= self.limits.max_cids_per_connection {
            return Err(RegistryError::ResourceLimit);
        }
        connection.current_initial_dcid = new_initial_dcid.clone();
        connection
            .cids
            .insert((EndpointRole::Server, u64::MAX), new_initial_dcid.clone());
        self.cid_index.insert(
            new_initial_dcid,
            CidBinding {
                connection: id,
                owner: EndpointRole::Server,
                sequence: u64::MAX,
            },
        );
        Ok(())
    }

    pub fn get(&self, id: ConnectionId) -> Option<&QuicConnectionState> {
        self.connections.get(&id)
    }

    pub fn get_mut(&mut self, id: ConnectionId) -> Option<&mut QuicConnectionState> {
        self.connections.get_mut(&id)
    }

    pub fn note_authentication_failure(&mut self, _path: NetworkPath, _dcid: &[u8]) {}

    pub fn snapshot(&self) -> RegistrySnapshot {
        RegistrySnapshot {
            connection_count: self.connections.len(),
            cid_count: self.cid_index.len(),
            path_count: self.path_index.len(),
            next_id: self.next_id,
        }
    }
}

pub fn reconstruct_packet_number(
    largest: Option<u64>,
    truncated: u64,
    packet_number_len: usize,
) -> Option<u64> {
    if !(1..=4).contains(&packet_number_len) {
        return None;
    }
    let expected = largest.map_or(0, |value| value.saturating_add(1));
    let bits = packet_number_len.checked_mul(8)?;
    let window = 1u64.checked_shl(u32::try_from(bits).ok()?)?;
    let half_window = window / 2;
    let mask = window - 1;
    let mut candidate = (expected & !mask) | truncated;
    if candidate.saturating_add(half_window) <= expected
        && candidate < (1u64 << 62).saturating_sub(window)
    {
        candidate += window;
    } else if candidate > expected.saturating_add(half_window) && candidate >= window {
        candidate -= window;
    }
    (candidate < (1u64 << 62)).then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn path(suffix: u8) -> NetworkPath {
        NetworkPath::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, suffix)), 50_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 443),
        )
    }

    #[test]
    fn authenticated_new_cid_allows_tuple_migration() {
        let mut registry = ConnectionRegistry::new(DecodeLimits::default());
        let id = registry
            .observe_client_initial(path(1), vec![1], vec![2], QuicVersion::V1)
            .unwrap();
        registry
            .add_authenticated_cid(id, EndpointRole::Server, 7, vec![9], [0; 16])
            .unwrap();
        assert_eq!(
            registry.resolve_short(&path(2), &[9]),
            Some((id, EndpointRole::Client))
        );
    }

    #[test]
    fn authentication_failure_does_not_mutate_registry() {
        let mut registry = ConnectionRegistry::new(DecodeLimits::default());
        registry
            .observe_client_initial(path(1), vec![1], vec![2], QuicVersion::V1)
            .unwrap();
        let before = registry.snapshot();
        registry.note_authentication_failure(path(2), &[9]);
        assert_eq!(registry.snapshot(), before);
    }

    #[test]
    fn reconstructs_packet_number_nearest_expected() {
        assert_eq!(
            reconstruct_packet_number(Some(0xa82f30ea), 0x9b32, 2),
            Some(0xa82f9b32)
        );
    }
}
