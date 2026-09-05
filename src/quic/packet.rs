use super::crypto::{QuicHeaderKey, QuicPacketKey};
use super::types::PacketType;
use super::version::{QuicVersion, QuicVersionError, QuicVersionProfile};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use rustls::quic::{HeaderProtectionKey, PacketKey};

const MAX_CID_LEN: usize = 20;
const RETRY_TAG_LEN: usize = 16;

pub struct ProtectedPacket<'a> {
    pub datagram: &'a [u8],
    pub offset: usize,
    pub version: &'static QuicVersionProfile,
    pub dcid_len: Option<usize>,
    pub largest_packet_number: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPacket {
    pub packet_type: PacketType,
    pub packet_number: u64,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub key_phase: bool,
    /// Bytes consumed starting at `ProtectedPacket::offset`.
    pub consumed: usize,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeaderInfo {
    pub packet_type: PacketType,
    pub version: QuicVersion,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_len: usize,
    pub packet_number_offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketDecodeError {
    #[error("truncated QUIC packet")]
    Truncated,
    #[error("datagram does not have a QUIC header")]
    NotQuic,
    #[error("invalid QUIC connection ID length {0}")]
    InvalidCidLength(usize),
    #[error("short-header decoding requires a known destination CID length")]
    MissingDcidLength,
    #[error("packet carries version 0x{actual:08x}, expected 0x{expected:08x}")]
    VersionMismatch { expected: u32, actual: u32 },
    #[error(transparent)]
    Version(#[from] QuicVersionError),
    #[error("packet type {0:?} is not protected by packet keys")]
    UnsupportedPacketType(PacketType),
    #[error("invalid protected packet length")]
    InvalidLength,
    #[error("invalid QUIC reserved bits")]
    InvalidReservedBits,
    #[error("QUIC packet authentication failed")]
    AuthenticationFailed,
    #[error("invalid Retry integrity tag")]
    InvalidRetry,
}

pub trait PacketCodec: Send + Sync {
    fn decode(
        &self,
        packet: ProtectedPacket<'_>,
        header_key: &QuicHeaderKey,
        packet_key: &QuicPacketKey,
    ) -> Result<AuthenticatedPacket, PacketDecodeError>;

    fn verify_retry(
        &self,
        version: &'static QuicVersionProfile,
        original_dcid: &[u8],
        packet: &[u8],
    ) -> Result<(), PacketDecodeError>;
}

/// Packet codec selected after the OxiQUIC 0.2.1 v2 admission test failed.
///
/// OxiQUIC's public packet parser is retained as a pinned dependency for
/// differential testing, but its v2 long-header mapping uses the v1 table.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultPacketCodec;

pub type InternalPacketCodec = DefaultPacketCodec;

impl PacketCodec for DefaultPacketCodec {
    fn decode(
        &self,
        packet: ProtectedPacket<'_>,
        header_key: &QuicHeaderKey,
        packet_key: &QuicPacketKey,
    ) -> Result<AuthenticatedPacket, PacketDecodeError> {
        let first = *packet
            .datagram
            .get(packet.offset)
            .ok_or(PacketDecodeError::Truncated)?;
        if first & 0x40 == 0 {
            return Err(PacketDecodeError::NotQuic);
        }
        if first & 0x80 != 0 {
            decode_long(packet, header_key, packet_key)
        } else {
            decode_short(packet, header_key, packet_key)
        }
    }

    fn verify_retry(
        &self,
        version: &'static QuicVersionProfile,
        original_dcid: &[u8],
        packet: &[u8],
    ) -> Result<(), PacketDecodeError> {
        if original_dcid.len() > MAX_CID_LEN || packet.len() < RETRY_TAG_LEN {
            return Err(PacketDecodeError::InvalidRetry);
        }
        let header = inspect_long_header(packet, 0)?;
        if header.version.profile() != version || header.packet_type != PacketType::Retry {
            return Err(PacketDecodeError::InvalidRetry);
        }
        let (without_tag, received_tag) = packet.split_at(packet.len() - RETRY_TAG_LEN);
        let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + without_tag.len());
        pseudo.push(original_dcid.len() as u8);
        pseudo.extend_from_slice(original_dcid);
        pseudo.extend_from_slice(without_tag);

        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&version.retry_key)
            .map_err(|_| PacketDecodeError::InvalidRetry)?;
        let mut empty = [];
        let expected = cipher
            .encrypt_in_place_detached((&version.retry_nonce).into(), &pseudo, &mut empty)
            .map_err(|_| PacketDecodeError::InvalidRetry)?;
        let difference = expected
            .iter()
            .zip(received_tag)
            .fold(0u8, |acc, (expected, actual)| acc | (expected ^ actual));
        if difference != 0 || received_tag.len() != expected.len() {
            return Err(PacketDecodeError::InvalidRetry);
        }
        Ok(())
    }
}

pub fn inspect_long_header(
    datagram: &[u8],
    offset: usize,
) -> Result<LongHeaderInfo, PacketDecodeError> {
    let first = *datagram.get(offset).ok_or(PacketDecodeError::Truncated)?;
    if first & 0xc0 != 0xc0 {
        return Err(PacketDecodeError::NotQuic);
    }
    let mut cursor = offset.checked_add(1).ok_or(PacketDecodeError::Truncated)?;
    let version_wire = read_u32(datagram, &mut cursor)?;
    let version = QuicVersion::try_from(version_wire)?;
    let profile = version.profile();
    let packet_type = profile
        .packet_type_from_first_byte(first)
        .ok_or(PacketDecodeError::NotQuic)?;
    let dcid = read_cid(datagram, &mut cursor)?;
    let scid = read_cid(datagram, &mut cursor)?;

    if packet_type == PacketType::Retry {
        let token_end = datagram
            .len()
            .checked_sub(RETRY_TAG_LEN)
            .ok_or(PacketDecodeError::Truncated)?;
        if cursor > token_end {
            return Err(PacketDecodeError::Truncated);
        }
        return Ok(LongHeaderInfo {
            packet_type,
            version,
            dcid,
            scid,
            token: datagram[cursor..token_end].to_vec(),
            packet_len: datagram.len() - offset,
            packet_number_offset: None,
        });
    }

    let token = if packet_type == PacketType::Initial {
        let token_len = read_varint(datagram, &mut cursor)?;
        let token_len = usize::try_from(token_len).map_err(|_| PacketDecodeError::InvalidLength)?;
        take(datagram, &mut cursor, token_len)?.to_vec()
    } else {
        Vec::new()
    };
    let protected_len = read_varint(datagram, &mut cursor)?;
    let protected_len =
        usize::try_from(protected_len).map_err(|_| PacketDecodeError::InvalidLength)?;
    let packet_end = cursor
        .checked_add(protected_len)
        .ok_or(PacketDecodeError::InvalidLength)?;
    if packet_end > datagram.len() {
        return Err(PacketDecodeError::Truncated);
    }
    Ok(LongHeaderInfo {
        packet_type,
        version,
        dcid,
        scid,
        token,
        packet_len: packet_end - offset,
        packet_number_offset: Some(cursor - offset),
    })
}

fn decode_long(
    packet: ProtectedPacket<'_>,
    header_key: &QuicHeaderKey,
    packet_key: &QuicPacketKey,
) -> Result<AuthenticatedPacket, PacketDecodeError> {
    let header = inspect_long_header(packet.datagram, packet.offset)?;
    if header.version.profile() != packet.version {
        return Err(PacketDecodeError::VersionMismatch {
            expected: packet.version.wire,
            actual: header.version.profile().wire,
        });
    }
    if header.packet_type == PacketType::Retry {
        return Err(PacketDecodeError::UnsupportedPacketType(PacketType::Retry));
    }
    let pn_offset = header
        .packet_number_offset
        .ok_or(PacketDecodeError::InvalidLength)?;
    decrypt_protected(
        &packet,
        header.packet_type,
        header.dcid,
        header.scid,
        pn_offset,
        header.packet_len,
        header_key,
        packet_key,
    )
}

fn decode_short(
    packet: ProtectedPacket<'_>,
    header_key: &QuicHeaderKey,
    packet_key: &QuicPacketKey,
) -> Result<AuthenticatedPacket, PacketDecodeError> {
    let dcid_len = packet
        .dcid_len
        .ok_or(PacketDecodeError::MissingDcidLength)?;
    if dcid_len > MAX_CID_LEN {
        return Err(PacketDecodeError::InvalidCidLength(dcid_len));
    }
    let packet_len = packet.datagram.len() - packet.offset;
    let dcid_start = packet
        .offset
        .checked_add(1)
        .ok_or(PacketDecodeError::Truncated)?;
    let dcid_end = dcid_start
        .checked_add(dcid_len)
        .ok_or(PacketDecodeError::Truncated)?;
    let dcid = packet
        .datagram
        .get(dcid_start..dcid_end)
        .ok_or(PacketDecodeError::Truncated)?
        .to_vec();
    decrypt_protected(
        &packet,
        PacketType::OneRtt,
        dcid,
        Vec::new(),
        1 + dcid_len,
        packet_len,
        header_key,
        packet_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn decrypt_protected(
    packet: &ProtectedPacket<'_>,
    packet_type: PacketType,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    pn_offset: usize,
    packet_len: usize,
    header_key: &QuicHeaderKey,
    packet_key: &QuicPacketKey,
) -> Result<AuthenticatedPacket, PacketDecodeError> {
    let candidate_end = packet
        .offset
        .checked_add(packet_len)
        .ok_or(PacketDecodeError::InvalidLength)?;
    let mut candidate = packet
        .datagram
        .get(packet.offset..candidate_end)
        .ok_or(PacketDecodeError::Truncated)?
        .to_vec();
    let sample_start = pn_offset
        .checked_add(4)
        .ok_or(PacketDecodeError::InvalidLength)?;
    let sample_end = sample_start
        .checked_add(header_key.sample_len())
        .ok_or(PacketDecodeError::InvalidLength)?;
    let sample = candidate
        .get(sample_start..sample_end)
        .ok_or(PacketDecodeError::Truncated)?
        .to_vec();
    let mut first = candidate[0];
    let mut protected_pn: [u8; 4] = candidate
        .get(pn_offset..pn_offset + 4)
        .ok_or(PacketDecodeError::Truncated)?
        .try_into()
        .expect("four-byte slice");
    header_key
        .decrypt_in_place(&sample, &mut first, &mut protected_pn)
        .map_err(|_| PacketDecodeError::AuthenticationFailed)?;

    let pn_len = usize::from((first & 0x03) + 1);
    let reserved_mask = if first & 0x80 != 0 { 0x0c } else { 0x18 };
    if first & reserved_mask != 0 {
        return Err(PacketDecodeError::InvalidReservedBits);
    }
    candidate[0] = first;
    candidate[pn_offset..pn_offset + pn_len].copy_from_slice(&protected_pn[..pn_len]);
    let truncated = protected_pn[..pn_len]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let packet_number = reconstruct_packet_number(packet.largest_packet_number, truncated, pn_len);
    let payload_start = pn_offset
        .checked_add(pn_len)
        .ok_or(PacketDecodeError::InvalidLength)?;
    let header_bytes = candidate[..payload_start].to_vec();
    let encrypted_payload = candidate
        .get_mut(payload_start..)
        .ok_or(PacketDecodeError::Truncated)?;
    let plaintext = packet_key
        .decrypt_in_place(packet_number, &header_bytes, encrypted_payload)
        .map_err(|_| PacketDecodeError::AuthenticationFailed)?
        .to_vec();

    Ok(AuthenticatedPacket {
        packet_type,
        packet_number,
        dcid,
        scid,
        key_phase: packet_type == PacketType::OneRtt && first & 0x04 != 0,
        consumed: packet_len,
        payload: plaintext,
    })
}

#[must_use]
pub fn reconstruct_packet_number(
    largest: Option<u64>,
    truncated: u64,
    packet_number_len: usize,
) -> u64 {
    let expected = largest.map_or(0, |value| value.saturating_add(1));
    let bits = (packet_number_len * 8) as u32;
    let window = 1u64 << bits;
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
    candidate
}

fn read_cid(datagram: &[u8], cursor: &mut usize) -> Result<Vec<u8>, PacketDecodeError> {
    let length = usize::from(
        *take(datagram, cursor, 1)?
            .first()
            .ok_or(PacketDecodeError::Truncated)?,
    );
    if length > MAX_CID_LEN {
        return Err(PacketDecodeError::InvalidCidLength(length));
    }
    Ok(take(datagram, cursor, length)?.to_vec())
}

fn read_u32(datagram: &[u8], cursor: &mut usize) -> Result<u32, PacketDecodeError> {
    let bytes: [u8; 4] = take(datagram, cursor, 4)?
        .try_into()
        .expect("four-byte slice");
    Ok(u32::from_be_bytes(bytes))
}

fn read_varint(datagram: &[u8], cursor: &mut usize) -> Result<u64, PacketDecodeError> {
    let first = *datagram.get(*cursor).ok_or(PacketDecodeError::Truncated)?;
    let length = 1usize << (first >> 6);
    let bytes = take(datagram, cursor, length)?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn take<'a>(
    datagram: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], PacketDecodeError> {
    let end = cursor
        .checked_add(length)
        .ok_or(PacketDecodeError::Truncated)?;
    let value = datagram
        .get(*cursor..end)
        .ok_or(PacketDecodeError::Truncated)?;
    *cursor = end;
    Ok(value)
}
