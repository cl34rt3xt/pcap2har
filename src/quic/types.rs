#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EndpointRole {
    Client,
    Server,
}

impl EndpointRole {
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }

    #[must_use]
    pub const fn direction(self) -> Direction {
        match self {
            Self::Client => Direction::ClientToServer,
            Self::Server => Direction::ServerToClient,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    #[must_use]
    pub const fn sender(self) -> EndpointRole {
        match self {
            Self::ClientToServer => EndpointRole::Client,
            Self::ServerToClient => EndpointRole::Server,
        }
    }

    #[must_use]
    pub const fn reverse(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EncryptionLevel {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
}

impl PacketType {
    #[must_use]
    pub const fn encryption_level(self) -> Option<EncryptionLevel> {
        match self {
            Self::Initial => Some(EncryptionLevel::Initial),
            Self::ZeroRtt => Some(EncryptionLevel::ZeroRtt),
            Self::Handshake => Some(EncryptionLevel::Handshake),
            Self::Retry => None,
            Self::OneRtt => Some(EncryptionLevel::OneRtt),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u64);
