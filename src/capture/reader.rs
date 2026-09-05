use crate::diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope};
use crate::options::DecodeLimits;
use crate::secrets::SecretStore;
use pcap_parser::pcapng::{Block, InterfaceDescriptionBlock, OptionCode, SecretsType};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::{create_reader, Linktype, PcapBlockOwned, PcapError};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

// Fixed charges reserve headroom for container capacity; variable secret/message bytes are added separately.
const INTERFACE_ENTRY_BUDGET_BYTES: usize = 256;
const SECRET_ENTRY_BUDGET_BYTES: usize = 1_024;
const DIAGNOSTIC_ENTRY_BUDGET_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    LinuxSll,
    LinuxSll2,
    RawIp,
    Unsupported(u32),
}

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub index: u64,
    pub interface_id: u32,
    pub timestamp_ns: u64,
    pub link_type: LinkType,
    pub original_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CaptureInterface {
    pub id: u32,
    pub link_type: LinkType,
    pub snaplen: u32,
    pub timestamp_resolution: u64,
    pub timestamp_offset_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct CaptureIndex {
    pub packet_count: u64,
    pub interfaces: Vec<CaptureInterface>,
    pub secrets: SecretStore,
    pub diagnostics: Vec<Diagnostic>,
}

impl Default for CaptureIndex {
    fn default() -> Self {
        Self {
            packet_count: 0,
            interfaces: Vec::new(),
            secrets: SecretStore::new(),
            diagnostics: Vec::new(),
        }
    }
}

pub struct CaptureReader {
    path: PathBuf,
    limits: DecodeLimits,
    index: CaptureIndex,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("unable to read capture")]
    Read(#[source] io::Error),
    #[error("capture format is not recognized")]
    UnrecognizedFormat,
    #[error("capture ended before a complete block")]
    Truncated,
    #[error("capture parser rejected a block")]
    Malformed,
    #[error("capture exceeds configured buffer limit")]
    BufferLimit,
    #[error("capture contains an invalid interface reference")]
    InvalidInterface,
    #[error("capture timestamp cannot be represented as nanoseconds")]
    TimestampOverflow,
}

impl CaptureReader {
    pub fn open(path: &Path, limits: DecodeLimits) -> Result<Self, CaptureError> {
        Self::open_with_keylog(path, limits, None)
    }

    pub fn open_with_keylog(
        path: &Path,
        limits: DecodeLimits,
        keylog_path: Option<&Path>,
    ) -> Result<Self, CaptureError> {
        validate_limits(&limits)?;
        let (mut index, mut resource_budget) = build_index(path, &limits)?;
        if let Some(keylog_path) = keylog_path {
            let keylog = read_bounded(keylog_path, resource_budget.remaining()?)?;
            parse_keylog_into(&mut index, &keylog, &mut resource_budget)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            limits,
            index,
        })
    }

    pub fn index(&self) -> &CaptureIndex {
        &self.index
    }

    pub fn for_each_packet(
        &self,
        visitor: &mut dyn FnMut(CapturedPacket) -> Result<(), CaptureError>,
    ) -> Result<(), CaptureError> {
        let mut state = PacketPassState::default();
        let mut packet_index = 0u64;
        stream_capture(&self.path, &self.limits, |block| match block {
            PcapBlockOwned::LegacyHeader(_) => {
                state.legacy_interface = Some(0);
                Ok(())
            }
            PcapBlockOwned::Legacy(packet) => {
                let interface_id = state
                    .legacy_interface
                    .ok_or(CaptureError::InvalidInterface)?;
                let interface = interface_for(&self.index, interface_id)?;
                let timestamp_ns = legacy_timestamp_ns(
                    packet.ts_sec,
                    packet.ts_usec,
                    interface.timestamp_resolution == 1_000_000_000,
                )?;
                let captured = CapturedPacket {
                    index: packet_index,
                    interface_id,
                    timestamp_ns,
                    link_type: interface.link_type,
                    original_len: packet.origlen,
                    data: packet.data.to_vec(),
                };
                packet_index = packet_index
                    .checked_add(1)
                    .ok_or(CaptureError::BufferLimit)?;
                visitor(captured)
            }
            PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                state.local_interfaces.clear();
                Ok(())
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(_)) => {
                let global_id = state.next_interface_id;
                interface_for(&self.index, global_id)?;
                state.local_interfaces.push(global_id);
                state.next_interface_id = state
                    .next_interface_id
                    .checked_add(1)
                    .ok_or(CaptureError::BufferLimit)?;
                Ok(())
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                let interface_id = state.interface_id(packet.if_id)?;
                let interface = interface_for(&self.index, interface_id)?;
                let timestamp_ns = pcapng_timestamp_ns(
                    packet.ts_high,
                    packet.ts_low,
                    interface.timestamp_resolution,
                    interface.timestamp_offset_seconds,
                )?;
                let captured = CapturedPacket {
                    index: packet_index,
                    interface_id,
                    timestamp_ns,
                    link_type: interface.link_type,
                    original_len: packet.origlen,
                    data: packet.packet_data().to_vec(),
                };
                packet_index = packet_index
                    .checked_add(1)
                    .ok_or(CaptureError::BufferLimit)?;
                visitor(captured)
            }
            PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
                let interface_id = state.interface_id(0)?;
                let interface = interface_for(&self.index, interface_id)?;
                let captured_len = usize::try_from(packet.origlen.min(interface.snaplen))
                    .map_err(|_| CaptureError::Malformed)?;
                let data = packet
                    .raw_packet_data()
                    .get(..captured_len)
                    .ok_or(CaptureError::Malformed)?
                    .to_vec();
                let captured = CapturedPacket {
                    index: packet_index,
                    interface_id,
                    timestamp_ns: 0,
                    link_type: interface.link_type,
                    original_len: packet.origlen,
                    data,
                };
                packet_index = packet_index
                    .checked_add(1)
                    .ok_or(CaptureError::BufferLimit)?;
                visitor(captured)
            }
            PcapBlockOwned::NG(_) => Ok(()),
        })
    }
}

#[derive(Default)]
struct IndexPassState {
    local_interfaces: Vec<u32>,
    legacy_header_seen: bool,
    section_big_endian: bool,
}

impl IndexPassState {
    fn interface_id(&self, local_id: u32) -> Result<u32, CaptureError> {
        self.local_interfaces
            .get(usize::try_from(local_id).map_err(|_| CaptureError::InvalidInterface)?)
            .copied()
            .ok_or(CaptureError::InvalidInterface)
    }
}

#[derive(Default)]
struct PacketPassState {
    local_interfaces: Vec<u32>,
    legacy_interface: Option<u32>,
    next_interface_id: u32,
}

impl PacketPassState {
    fn interface_id(&self, local_id: u32) -> Result<u32, CaptureError> {
        self.local_interfaces
            .get(usize::try_from(local_id).map_err(|_| CaptureError::InvalidInterface)?)
            .copied()
            .ok_or(CaptureError::InvalidInterface)
    }
}

fn build_index(
    path: &Path,
    limits: &DecodeLimits,
) -> Result<(CaptureIndex, CaptureResourceBudget), CaptureError> {
    let mut index = CaptureIndex::default();
    let mut state = IndexPassState::default();
    let mut resource_budget = CaptureResourceBudget::new(limits.max_total_buffered_bytes);
    stream_capture(path, limits, |block| match block {
        PcapBlockOwned::LegacyHeader(header) => {
            if state.legacy_header_seen {
                return Err(CaptureError::Malformed);
            }
            state.legacy_header_seen = true;
            add_interface(
                &mut index,
                header.network,
                header.snaplen,
                if header.is_nanosecond_precision() {
                    1_000_000_000
                } else {
                    1_000_000
                },
                0,
                &mut resource_budget,
            )?;
            Ok(())
        }
        PcapBlockOwned::Legacy(_) => increment_packet_count(&mut index),
        PcapBlockOwned::NG(Block::SectionHeader(section)) => {
            state.local_interfaces.clear();
            state.section_big_endian = section.big_endian();
            Ok(())
        }
        PcapBlockOwned::NG(Block::InterfaceDescription(interface)) => {
            let id = add_interface(
                &mut index,
                interface.linktype,
                interface.snaplen,
                interface
                    .ts_resolution()
                    .ok_or(CaptureError::TimestampOverflow)?,
                interface_timestamp_offset(&interface, state.section_big_endian)?,
                &mut resource_budget,
            )?;
            state.local_interfaces.push(id);
            Ok(())
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
            state.interface_id(packet.if_id)?;
            increment_packet_count(&mut index)
        }
        PcapBlockOwned::NG(Block::SimplePacket(_)) => {
            state.interface_id(0)?;
            increment_packet_count(&mut index)
        }
        PcapBlockOwned::NG(Block::DecryptionSecrets(dsb)) => {
            if dsb.secrets_type != SecretsType::TlsKeyLog {
                push_diagnostic(
                    &mut index,
                    &mut resource_budget,
                    Diagnostic::warning(
                        DiagnosticCode::UnsupportedProtocol,
                        DiagnosticScope::Capture,
                        "unsupported decryption secrets block type",
                    ),
                )?;
                return Ok(());
            }
            let secrets_len =
                usize::try_from(dsb.secrets_len).map_err(|_| CaptureError::Malformed)?;
            let payload = dsb.data.get(..secrets_len).ok_or(CaptureError::Malformed)?;
            parse_keylog_into(&mut index, payload, &mut resource_budget)
        }
        PcapBlockOwned::NG(_) => Ok(()),
    })?;
    Ok((index, resource_budget))
}

fn add_interface(
    index: &mut CaptureIndex,
    parser_link_type: Linktype,
    snaplen: u32,
    timestamp_resolution: u64,
    timestamp_offset_seconds: i64,
    resource_budget: &mut CaptureResourceBudget,
) -> Result<u32, CaptureError> {
    resource_budget.charge(interface_resource_bytes()?)?;
    let id = u32::try_from(index.interfaces.len()).map_err(|_| CaptureError::BufferLimit)?;
    let link_type = map_link_type(parser_link_type);
    if matches!(link_type, LinkType::Unsupported(_)) {
        push_diagnostic(
            index,
            resource_budget,
            Diagnostic::warning(
                DiagnosticCode::UnsupportedLinkType,
                DiagnosticScope::Capture,
                "unsupported capture link type",
            ),
        )?;
    }
    index.interfaces.push(CaptureInterface {
        id,
        link_type,
        snaplen,
        timestamp_resolution,
        timestamp_offset_seconds,
    });
    Ok(id)
}

struct CaptureResourceBudget {
    used: usize,
    limit: usize,
}

impl CaptureResourceBudget {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), CaptureError> {
        let used = self
            .used
            .checked_add(bytes)
            .ok_or(CaptureError::BufferLimit)?;
        if used > self.limit {
            return Err(CaptureError::BufferLimit);
        }
        self.used = used;
        Ok(())
    }

    fn remaining(&self) -> Result<usize, CaptureError> {
        self.limit
            .checked_sub(self.used)
            .ok_or(CaptureError::BufferLimit)
    }
}

fn interface_resource_bytes() -> Result<usize, CaptureError> {
    Ok(INTERFACE_ENTRY_BUDGET_BYTES)
}

fn diagnostic_resource_bytes(diagnostic: &Diagnostic) -> Result<usize, CaptureError> {
    DIAGNOSTIC_ENTRY_BUDGET_BYTES
        .checked_add(diagnostic.message.len())
        .ok_or(CaptureError::BufferLimit)
}

fn push_diagnostic(
    index: &mut CaptureIndex,
    resource_budget: &mut CaptureResourceBudget,
    diagnostic: Diagnostic,
) -> Result<(), CaptureError> {
    resource_budget.charge(diagnostic_resource_bytes(&diagnostic)?)?;
    index.diagnostics.push(diagnostic);
    Ok(())
}

fn parse_keylog_into(
    index: &mut CaptureIndex,
    data: &[u8],
    resource_budget: &mut CaptureResourceBudget,
) -> Result<(), CaptureError> {
    for line in data.split_inclusive(|byte| *byte == b'\n') {
        let parsed = SecretStore::parse(line);
        let secret_entries = parsed
            .store
            .checked_secret_entry_count()
            .ok_or(CaptureError::BufferLimit)?;
        let secret_bytes = secret_entries
            .checked_mul(SECRET_ENTRY_BUDGET_BYTES)
            .and_then(|bytes| {
                if secret_entries == 0 {
                    Some(bytes)
                } else {
                    bytes.checked_add(line.len())
                }
            })
            .ok_or(CaptureError::BufferLimit)?;
        resource_budget.charge(secret_bytes)?;
        for diagnostic in parsed.diagnostics {
            push_diagnostic(index, resource_budget, diagnostic)?;
        }
        for diagnostic in index.secrets.merge(parsed.store) {
            push_diagnostic(index, resource_budget, diagnostic)?;
        }
    }
    Ok(())
}

fn increment_packet_count(index: &mut CaptureIndex) -> Result<(), CaptureError> {
    index.packet_count = index
        .packet_count
        .checked_add(1)
        .ok_or(CaptureError::BufferLimit)?;
    Ok(())
}

fn interface_for(
    index: &CaptureIndex,
    interface_id: u32,
) -> Result<&CaptureInterface, CaptureError> {
    index
        .interfaces
        .get(usize::try_from(interface_id).map_err(|_| CaptureError::InvalidInterface)?)
        .ok_or(CaptureError::InvalidInterface)
}

fn map_link_type(link_type: Linktype) -> LinkType {
    match link_type.0 {
        1 => LinkType::Ethernet,
        101 | 228 | 229 => LinkType::RawIp,
        113 => LinkType::LinuxSll,
        276 => LinkType::LinuxSll2,
        value => LinkType::Unsupported(value as u32),
    }
}

fn interface_timestamp_offset(
    interface: &InterfaceDescriptionBlock<'_>,
    big_endian: bool,
) -> Result<i64, CaptureError> {
    let Some(option) = interface
        .options
        .iter()
        .find(|option| option.code == OptionCode::IfTsoffset)
    else {
        return Ok(0);
    };
    let bytes: [u8; 8] = option
        .as_bytes()
        .map_err(|_| CaptureError::Malformed)?
        .try_into()
        .map_err(|_| CaptureError::Malformed)?;
    Ok(if big_endian {
        i64::from_be_bytes(bytes)
    } else {
        i64::from_le_bytes(bytes)
    })
}

fn legacy_timestamp_ns(
    seconds: u32,
    fraction: u32,
    nanosecond_precision: bool,
) -> Result<u64, CaptureError> {
    let fraction_ns = if nanosecond_precision {
        u64::from(fraction)
    } else {
        u64::from(fraction)
            .checked_mul(1_000)
            .ok_or(CaptureError::TimestampOverflow)?
    };
    u64::from(seconds)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction_ns))
        .ok_or(CaptureError::TimestampOverflow)
}

fn pcapng_timestamp_ns(
    high: u32,
    low: u32,
    resolution: u64,
    offset_seconds: i64,
) -> Result<u64, CaptureError> {
    if resolution == 0 {
        return Err(CaptureError::TimestampOverflow);
    }
    let raw = (u64::from(high) << 32) | u64::from(low);
    let seconds = i128::from(raw / resolution) + i128::from(offset_seconds);
    let fractional_ns = (u128::from(raw % resolution) * 1_000_000_000u128) / u128::from(resolution);
    let total = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(i128::try_from(fractional_ns).ok()?))
        .ok_or(CaptureError::TimestampOverflow)?;
    u64::try_from(total).map_err(|_| CaptureError::TimestampOverflow)
}

fn validate_limits(limits: &DecodeLimits) -> Result<(), CaptureError> {
    if limits.capture_buffer_bytes == 0
        || limits.capture_buffer_bytes > limits.max_total_buffered_bytes
    {
        return Err(CaptureError::BufferLimit);
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, CaptureError> {
    let max_plus_one = max_bytes.checked_add(1).ok_or(CaptureError::BufferLimit)?;
    let max_plus_one = u64::try_from(max_plus_one).map_err(|_| CaptureError::BufferLimit)?;
    let mut data = Vec::new();
    File::open(path)
        .map_err(CaptureError::Read)?
        .take(max_plus_one)
        .read_to_end(&mut data)
        .map_err(CaptureError::Read)?;
    if data.len() > max_bytes {
        return Err(CaptureError::BufferLimit);
    }
    Ok(data)
}

fn stream_capture<F>(path: &Path, limits: &DecodeLimits, mut handle: F) -> Result<(), CaptureError>
where
    F: for<'a> FnMut(PcapBlockOwned<'a>) -> Result<(), CaptureError>,
{
    let (mut reader, mut buffer_capacity) = create_stream_reader(path, limits)?;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                handle(block)?;
                reader.consume(offset);
            }
            Err(PcapError::Eof) => return Ok(()),
            Err(PcapError::Incomplete(_)) => reader.refill().map_err(map_parser_error)?,
            Err(PcapError::BufferTooSmall) => {
                grow_reader(
                    &mut *reader,
                    &mut buffer_capacity,
                    limits.max_total_buffered_bytes,
                )?;
                reader.refill().map_err(map_parser_error)?;
            }
            Err(error) => return Err(map_parser_error(error)),
        }
    }
}

fn create_stream_reader(
    path: &Path,
    limits: &DecodeLimits,
) -> Result<(Box<dyn PcapReaderIterator + Send>, usize), CaptureError> {
    let mut capacity = limits.capture_buffer_bytes;
    loop {
        let file = File::open(path).map_err(CaptureError::Read)?;
        let file_len = usize::try_from(file.metadata().map_err(CaptureError::Read)?.len())
            .map_err(|_| CaptureError::BufferLimit)?;
        match create_reader(capacity, file) {
            Ok(reader) => return Ok((reader, capacity)),
            Err(PcapError::Incomplete(_)) if file_len <= capacity => {
                return Err(CaptureError::Truncated);
            }
            Err(PcapError::Incomplete(_)) | Err(PcapError::BufferTooSmall) => {
                capacity = next_buffer_capacity(capacity, limits.max_total_buffered_bytes)?;
            }
            // create_reader probes pcapng before its full 28-byte section header is buffered,
            // then reports the incomplete probe as an unrecognized legacy header.
            Err(PcapError::HeaderNotRecognized) if capacity < 28 => {
                capacity = next_buffer_capacity(capacity, limits.max_total_buffered_bytes)?;
            }
            Err(error) => return Err(map_parser_error(error)),
        }
    }
}

fn grow_reader(
    reader: &mut dyn PcapReaderIterator,
    current_capacity: &mut usize,
    max_bytes: usize,
) -> Result<(), CaptureError> {
    let requested = next_buffer_capacity(*current_capacity, max_bytes)?;
    if !reader.grow(requested) {
        return Err(CaptureError::BufferLimit);
    }
    *current_capacity = requested;
    Ok(())
}

fn next_buffer_capacity(current: usize, max_bytes: usize) -> Result<usize, CaptureError> {
    if current >= max_bytes {
        return Err(CaptureError::BufferLimit);
    }
    let doubled = match current.checked_mul(2) {
        Some(doubled) => doubled,
        None => max_bytes,
    };
    Ok(doubled.min(max_bytes))
}

fn map_parser_error<I>(error: PcapError<I>) -> CaptureError {
    match error {
        PcapError::Eof | PcapError::UnexpectedEof => CaptureError::Truncated,
        PcapError::ReadError => CaptureError::Read(io::Error::other("capture read failed")),
        PcapError::HeaderNotRecognized => CaptureError::UnrecognizedFormat,
        PcapError::BufferTooSmall | PcapError::Incomplete(_) => CaptureError::BufferLimit,
        PcapError::NomError(_, _) | PcapError::OwnedNomError(_, _) => CaptureError::Malformed,
    }
}
