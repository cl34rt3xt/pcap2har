use std::net::SocketAddr;

pub type HeaderFields = Vec<(String, String)>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedRequest {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub version: String,
    pub headers: HeaderFields,
    pub trailers: HeaderFields,
    pub body: Vec<u8>,
    pub header_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: HeaderFields,
    pub trailers: HeaderFields,
    pub body: Vec<u8>,
    pub header_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedExchange {
    pub connection_sequence: u64,
    pub stream_id: u64,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub request: NormalizedRequest,
    pub response: Option<NormalizedResponse>,
    pub request_started_ns: u64,
    pub response_started_ns: Option<u64>,
    pub ended_ns: u64,
}
