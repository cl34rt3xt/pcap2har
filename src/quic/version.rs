use super::types::PacketType;
use hex_literal::hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    #[must_use]
    pub const fn profile(self) -> &'static QuicVersionProfile {
        match self {
            Self::V1 => &V1,
            Self::V2 => &V2,
        }
    }
}

impl TryFrom<u32> for QuicVersion {
    type Error = QuicVersionError;

    fn try_from(wire: u32) -> Result<Self, Self::Error> {
        match wire {
            0 => Err(QuicVersionError::VersionNegotiation),
            value if value == V1.wire => Ok(Self::V1),
            value if value == V2.wire => Ok(Self::V2),
            value => Err(QuicVersionError::Unsupported(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuicVersionError {
    #[error("QUIC version negotiation packet")]
    VersionNegotiation,
    #[error("unsupported QUIC version 0x{0:08x}")]
    Unsupported(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicVersionProfile {
    pub version: QuicVersion,
    pub wire: u32,
    pub initial_salt: [u8; 20],
    pub key_label: &'static [u8],
    pub iv_label: &'static [u8],
    pub hp_label: &'static [u8],
    pub update_label: &'static [u8],
    pub retry_key: [u8; 16],
    pub retry_nonce: [u8; 12],
    type_map: [PacketType; 4],
}

impl QuicVersionProfile {
    #[must_use]
    pub const fn packet_type(&self, type_bits: u8) -> Option<PacketType> {
        if type_bits > 0b11 {
            return None;
        }
        Some(self.type_map[type_bits as usize])
    }

    #[must_use]
    pub const fn packet_type_from_first_byte(&self, first: u8) -> Option<PacketType> {
        if first & 0x80 == 0 {
            return Some(PacketType::OneRtt);
        }
        self.packet_type((first >> 4) & 0x03)
    }
}

pub const V1: QuicVersionProfile = QuicVersionProfile {
    version: QuicVersion::V1,
    wire: 0x0000_0001,
    initial_salt: hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    key_label: b"quic key",
    iv_label: b"quic iv",
    hp_label: b"quic hp",
    update_label: b"quic ku",
    retry_key: hex!("be0c690b9f66575a1d766b54e368c84e"),
    retry_nonce: hex!("461599d35d632bf2239825bb"),
    type_map: [
        PacketType::Initial,
        PacketType::ZeroRtt,
        PacketType::Handshake,
        PacketType::Retry,
    ],
};

pub const V2: QuicVersionProfile = QuicVersionProfile {
    version: QuicVersion::V2,
    wire: 0x6b33_43cf,
    initial_salt: hex!("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    key_label: b"quicv2 key",
    iv_label: b"quicv2 iv",
    hp_label: b"quicv2 hp",
    update_label: b"quicv2 ku",
    retry_key: hex!("8fb4b01b56ac48e260fbcbcead7ccc92"),
    retry_nonce: hex!("d86969bc2d7c6d9990efb04a"),
    type_map: [
        PacketType::Retry,
        PacketType::Initial,
        PacketType::ZeroRtt,
        PacketType::Handshake,
    ],
};
