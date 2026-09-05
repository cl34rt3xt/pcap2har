use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ConversionOptions {
    pub keylog: Option<PathBuf>,
    pub strict: bool,
    pub limits: DecodeLimits,
}

#[derive(Debug, Clone)]
pub struct DecodeLimits {
    pub capture_buffer_bytes: usize,
    pub max_connections: usize,
    pub max_cids_per_connection: usize,
    pub max_streams_per_connection: usize,
    pub max_ranges_per_stream: usize,
    pub max_stream_bytes: usize,
    pub max_connection_bytes: usize,
    pub max_total_buffered_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_header_section_bytes: usize,
    pub max_body_bytes: usize,
    pub max_qpack_table_bytes: usize,
    pub max_blocked_header_sections: usize,
    pub max_packet_key_attempts: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            capture_buffer_bytes: 1 << 20,
            max_connections: 16_384,
            max_cids_per_connection: 32,
            max_streams_per_connection: 4_096,
            max_ranges_per_stream: 1_024,
            max_stream_bytes: 16 << 20,
            max_connection_bytes: 64 << 20,
            max_total_buffered_bytes: 256 << 20,
            max_frame_bytes: 16 << 20,
            max_header_section_bytes: 1 << 20,
            max_body_bytes: 16 << 20,
            max_qpack_table_bytes: 4 << 20,
            max_blocked_header_sections: 128,
            max_packet_key_attempts: 12,
        }
    }
}

impl DecodeLimits {
    #[doc(hidden)]
    pub fn testing() -> Self {
        Self {
            capture_buffer_bytes: 1 << 10,
            max_connections: 4,
            max_cids_per_connection: 2,
            max_streams_per_connection: 8,
            max_ranges_per_stream: 4,
            max_stream_bytes: 1 << 10,
            max_connection_bytes: 4 << 10,
            max_total_buffered_bytes: 16 << 10,
            max_frame_bytes: 1 << 10,
            max_header_section_bytes: 1 << 10,
            max_body_bytes: 4 << 10,
            max_qpack_table_bytes: 1 << 10,
            max_blocked_header_sections: 4,
            max_packet_key_attempts: 2,
        }
    }
}
