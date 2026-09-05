pub mod capture;
pub mod converter;
pub mod diagnostic;
pub mod exchange;
pub mod fcgi;
pub mod har;
pub mod http;
pub mod http2;
pub mod http3;
pub mod options;
mod pipeline;
pub mod quic;
pub mod report;
pub mod secrets;
pub mod tcp;
pub mod tls;

pub use capture::{
    CaptureError, CaptureIndex, CaptureInterface, CaptureReader, CapturedPacket, DatagramRecord,
    LinkDecoder, LinkError, LinkType, NormalizedTcpPacket, TransportPacket,
};
pub use converter::{convert_pcap_to_har, normalized_exchanges_to_har};
pub use diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope, Severity};
pub use exchange::{HeaderFields, NormalizedExchange, NormalizedRequest, NormalizedResponse};
pub use har::Har;
pub use options::{ConversionOptions, DecodeLimits};
pub use pipeline::{convert_capture, ConversionError};
pub use report::{ConversionReport, ConversionStats};

#[cfg(test)]
mod model_tests {
    use super::*;

    #[test]
    fn default_limits_are_bounded() {
        let limits = DecodeLimits::default();
        assert_eq!(limits.capture_buffer_bytes, 1 << 20);
        assert_eq!(limits.max_connections, 16_384);
        assert_eq!(limits.max_streams_per_connection, 4_096);
        assert_eq!(limits.max_ranges_per_stream, 1_024);
        assert_eq!(limits.max_stream_bytes, 16 << 20);
        assert_eq!(limits.max_connection_bytes, 64 << 20);
        assert_eq!(limits.max_total_buffered_bytes, 256 << 20);
        assert_eq!(limits.max_qpack_table_bytes, 4 << 20);
        assert_eq!(limits.max_blocked_header_sections, 128);
        assert_eq!(limits.max_packet_key_attempts, 12);
    }

    #[test]
    fn strict_report_fails_on_warning() {
        let mut report = ConversionReport::new(Har::new());
        report.diagnostics.push(Diagnostic::warning(
            DiagnosticCode::IncompleteStream,
            DiagnosticScope::Stream {
                connection: 7,
                stream: 4,
            },
            "missing range 12..24",
        ));
        assert!(report.strict_failure());
    }
}
