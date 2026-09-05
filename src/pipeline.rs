use crate::capture::{CaptureError, CaptureReader, LinkDecoder, LinkError, TransportPacket};
use crate::converter::Converter;
use crate::diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope};
use crate::http3::Http3Session;
use crate::options::ConversionOptions;
use crate::quic::{ConnectionId, QuicEvent, QuicPassiveDecoder};
use crate::report::{ConversionReport, ConversionStats};
use crate::secrets::{SecretStore, TlsSecrets};
use crate::tcp::{TcpError, TcpReassembler};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("capture conversion failed: {0}")]
    Capture(#[from] CaptureError),
}

pub fn convert_capture(
    path: &Path,
    options: ConversionOptions,
) -> Result<ConversionReport, ConversionError> {
    let reader =
        CaptureReader::open_with_keylog(path, options.limits.clone(), options.keylog.as_deref())?;
    let diagnostics = reader.index().diagnostics.clone();
    let secret_store = reader.index().secrets.clone();
    let tls_secrets = secret_store.clone().into_tls_secrets();
    let mut pipeline = ConversionPipeline::new(options, diagnostics, secret_store);

    reader.for_each_packet(&mut |packet| {
        let packet_index = packet.index;
        if !pipeline.observe_datagram(packet_index) {
            return Ok(());
        }
        match LinkDecoder::decode(&packet) {
            Ok(transport) => pipeline.ingest(transport),
            Err(error) => pipeline.drop_link_packet(packet_index, error),
        }
        Ok(())
    })?;

    Ok(pipeline.finish(tls_secrets))
}

struct ConversionPipeline {
    options: ConversionOptions,
    tcp: TcpReassembler,
    quic: QuicPassiveDecoder,
    diagnostics: Vec<Diagnostic>,
    stats: ConversionStats,
}

impl ConversionPipeline {
    fn new(options: ConversionOptions, diagnostics: Vec<Diagnostic>, secrets: SecretStore) -> Self {
        let tcp = TcpReassembler::with_limits(options.limits.clone());
        let quic = QuicPassiveDecoder::new(options.limits.clone(), secrets);
        Self {
            options,
            tcp,
            quic,
            diagnostics,
            stats: ConversionStats::default(),
        }
    }

    fn observe_datagram(&mut self, packet_index: u64) -> bool {
        if increment(&mut self.stats.datagrams_seen) {
            true
        } else {
            self.drop_packet(
                packet_index,
                DiagnosticCode::ResourceLimit,
                "conversion statistics limit reached",
            );
            false
        }
    }

    fn ingest(&mut self, packet: TransportPacket) {
        match packet {
            TransportPacket::Tcp(packet) => {
                let packet_index = packet.packet_index;
                match self.tcp.ingest(packet) {
                    Ok(new_connection) => {
                        increment(&mut self.stats.tcp_packets_seen);
                        if new_connection {
                            increment(&mut self.stats.connections_seen);
                        }
                    }
                    Err(TcpError::TimestampOutOfRange) => self.drop_packet(
                        packet_index,
                        DiagnosticCode::MalformedDatagram,
                        "packet timestamp is outside the supported range",
                    ),
                    Err(TcpError::ResourceLimit) => self.drop_packet(
                        packet_index,
                        DiagnosticCode::ResourceLimit,
                        "TCP reassembly limit exceeded",
                    ),
                    Err(TcpError::Parse(_)) => self.drop_packet(
                        packet_index,
                        DiagnosticCode::MalformedDatagram,
                        "TCP packet could not be processed",
                    ),
                }
            }
            TransportPacket::Udp(packet) => {
                increment(&mut self.stats.udp_packets_seen);
                let previous_connections = self.quic.connection_count();
                self.quic.ingest(packet);
                let new_connections = self
                    .quic
                    .connection_count()
                    .saturating_sub(previous_connections);
                for _ in 0..new_connections {
                    increment(&mut self.stats.connections_seen);
                }
            }
        }
    }

    fn drop_link_packet(&mut self, packet_index: u64, error: LinkError) {
        let (code, message) = match error {
            LinkError::UnsupportedLink(_) => (
                DiagnosticCode::UnsupportedLinkType,
                "packet uses an unsupported capture link type",
            ),
            LinkError::Truncated | LinkError::Malformed => (
                DiagnosticCode::MalformedDatagram,
                "packet has malformed or truncated headers",
            ),
            LinkError::UnsupportedNetwork(_)
            | LinkError::UnsupportedTransport
            | LinkError::UnsupportedFragment => (
                DiagnosticCode::UnsupportedProtocol,
                "packet uses an unsupported network or transport feature",
            ),
        };
        self.drop_packet(packet_index, code, message);
    }

    fn drop_packet(&mut self, packet_index: u64, code: DiagnosticCode, message: &'static str) {
        increment(&mut self.stats.packets_dropped);
        self.push_diagnostic(Diagnostic::warning(
            code,
            DiagnosticScope::Datagram {
                index: packet_index,
            },
            message,
        ));
    }

    fn push_diagnostic(&mut self, diagnostic: Diagnostic) {
        const DIAGNOSTIC_BUDGET_BYTES: usize = 128;
        let max_diagnostics = self
            .options
            .limits
            .max_total_buffered_bytes
            .checked_div(DIAGNOSTIC_BUDGET_BYTES)
            .unwrap_or_default();
        if self.diagnostics.len() < max_diagnostics {
            self.diagnostics.push(diagnostic);
        }
    }

    fn finish(mut self, tls_secrets: TlsSecrets) -> ConversionReport {
        let (quic_events, quic_diagnostics) = self.quic.finish();
        for diagnostic in quic_diagnostics {
            self.push_diagnostic(diagnostic);
        }
        let mut http3_sessions: BTreeMap<ConnectionId, Http3Session> = BTreeMap::new();
        for event in &quic_events {
            let endpoint = match event {
                QuicEvent::StreamData {
                    connection,
                    client,
                    server,
                    ..
                }
                | QuicEvent::StreamFinished {
                    connection,
                    client,
                    server,
                    ..
                } => Some((*connection, *client, *server)),
                _ => None,
            };
            if let Some((connection, client, server)) = endpoint {
                http3_sessions
                    .entry(connection)
                    .or_insert_with(|| {
                        Http3Session::new(connection, client, server, self.options.limits.clone())
                    })
                    .ingest(event);
            }
        }
        let mut converter = Converter::with_limits(&self.options.limits);
        for (_, session) in http3_sessions {
            let output = session.finish();
            for exchange in output.exchanges {
                converter.add_exchange(exchange);
            }
            for diagnostic in output.diagnostics {
                self.push_diagnostic(diagnostic);
            }
        }
        let streams = self.tcp.get_streams();
        converter.process_streams_with_tls(streams, &tls_secrets);
        if converter.body_limit_exceeded() {
            const DIAGNOSTIC_BUDGET_BYTES: usize = 128;
            let max_diagnostics = self
                .options
                .limits
                .max_total_buffered_bytes
                .checked_div(DIAGNOSTIC_BUDGET_BYTES)
                .unwrap_or_default();
            if self.diagnostics.len() < max_diagnostics {
                self.diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::ResourceLimit,
                    DiagnosticScope::Capture,
                    "decoded HTTP body exceeded the configured limit and was truncated",
                ));
            }
        }
        let har = converter.to_har();
        self.stats.exchanges_emitted = u64::try_from(har.log.entries.len()).unwrap_or(u64::MAX);

        ConversionReport {
            har,
            diagnostics: self.diagnostics,
            stats: self.stats,
        }
    }
}

fn increment(counter: &mut u64) -> bool {
    let Some(next) = counter.checked_add(1) else {
        return false;
    };
    *counter = next;
    true
}
