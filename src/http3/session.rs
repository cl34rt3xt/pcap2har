use super::frame::{Http3Frame, Http3FrameDecoder};
use super::message::RequestStreamState;
use super::qpack::{CompcolQpackCodec, QpackCodec, QpackDecode};
use super::settings::PeerSettings;
use super::stream::{StreamEvent, StreamRouter};
use crate::diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope};
use crate::exchange::NormalizedExchange;
use crate::quic::{ConnectionId, Direction, QuicEvent};
use crate::DecodeLimits;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

struct BlockedSection {
    stream_id: u64,
    direction: Direction,
    ordinal: u64,
    required_insert_count: usize,
    field_section: Vec<u8>,
    timestamp_ns: u64,
}

pub struct Http3Output {
    pub exchanges: Vec<NormalizedExchange>,
    pub diagnostics: Vec<Diagnostic>,
}

pub struct Http3Session {
    connection: ConnectionId,
    client: SocketAddr,
    server: SocketAddr,
    limits: DecodeLimits,
    router: StreamRouter,
    control: BTreeMap<Direction, Http3FrameDecoder>,
    control_seen_settings: BTreeSet<Direction>,
    peer_settings: BTreeMap<Direction, PeerSettings>,
    request_frames: BTreeMap<(Direction, u64), Http3FrameDecoder>,
    qpack: BTreeMap<Direction, CompcolQpackCodec>,
    messages: BTreeMap<u64, RequestStreamState>,
    blocked: Vec<BlockedSection>,
    ordinal: u64,
    exchanges: Vec<NormalizedExchange>,
    diagnostics: Vec<Diagnostic>,
}

impl Http3Session {
    pub fn new(
        connection: ConnectionId,
        client: SocketAddr,
        server: SocketAddr,
        limits: DecodeLimits,
    ) -> Self {
        let qpack = [Direction::ClientToServer, Direction::ServerToClient]
            .into_iter()
            .map(|direction| {
                (
                    direction,
                    CompcolQpackCodec::new(limits.max_qpack_table_bytes, &limits),
                )
            })
            .collect();
        Self {
            connection,
            client,
            server,
            router: StreamRouter::new(limits.clone()),
            limits,
            control: BTreeMap::new(),
            control_seen_settings: BTreeSet::new(),
            peer_settings: BTreeMap::new(),
            request_frames: BTreeMap::new(),
            qpack,
            messages: BTreeMap::new(),
            blocked: Vec::new(),
            ordinal: 0,
            exchanges: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn ingest(&mut self, event: &QuicEvent) {
        match event {
            QuicEvent::StreamData {
                connection,
                direction,
                stream_id,
                data,
                fin,
                timestamp_ns,
                ..
            } if *connection == self.connection => {
                self.route_stream(*direction, *stream_id, data, *fin, *timestamp_ns);
            }
            QuicEvent::StreamFinished {
                connection,
                direction,
                stream_id,
                timestamp_ns,
                ..
            } if *connection == self.connection => {
                self.route_stream(*direction, *stream_id, &[], true, *timestamp_ns);
            }
            _ => {}
        }
    }

    pub fn finish(mut self) -> Http3Output {
        let messages = std::mem::take(&mut self.messages);
        for (_, message) in messages {
            if let Ok(exchange) = message.into_exchange() {
                self.exchanges.push(exchange);
            }
        }
        self.exchanges.sort_by_key(|exchange| {
            (
                exchange.request_started_ns,
                exchange.connection_sequence,
                exchange.stream_id,
            )
        });
        Http3Output {
            exchanges: self.exchanges,
            diagnostics: self.diagnostics,
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.router.buffered_bytes()
            + self
                .request_frames
                .values()
                .map(Http3FrameDecoder::buffered_bytes)
                .sum::<usize>()
            + self
                .control
                .values()
                .map(Http3FrameDecoder::buffered_bytes)
                .sum::<usize>()
            + self
                .messages
                .values()
                .map(RequestStreamState::buffered_bytes)
                .sum::<usize>()
            + self
                .blocked
                .iter()
                .map(|section| section.field_section.len())
                .sum::<usize>()
            + self
                .qpack
                .values()
                .map(CompcolQpackCodec::buffered_encoder_bytes)
                .sum::<usize>()
    }

    pub fn blocked_sections(&self) -> usize {
        self.blocked.len()
    }

    fn route_stream(
        &mut self,
        direction: Direction,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        timestamp_ns: u64,
    ) {
        let events = match self
            .router
            .push(direction, stream_id, data, fin, timestamp_ns)
        {
            Ok(events) => events,
            Err(_) => {
                self.stream_diagnostic(
                    stream_id,
                    DiagnosticCode::UnsupportedProtocol,
                    "invalid HTTP/3 stream layout",
                );
                return;
            }
        };
        for event in events {
            match event {
                StreamEvent::Control {
                    direction,
                    data,
                    fin,
                    timestamp_ns,
                } => self.process_control(direction, &data, fin, timestamp_ns),
                StreamEvent::QpackEncoder {
                    direction, data, ..
                } => self.process_encoder(direction, &data),
                StreamEvent::Request {
                    direction,
                    stream_id,
                    data,
                    fin,
                    timestamp_ns,
                } => self.process_request(direction, stream_id, &data, fin, timestamp_ns),
                StreamEvent::Push { stream_id, .. } => self.stream_diagnostic(
                    stream_id,
                    DiagnosticCode::UnsupportedProtocol,
                    "HTTP/3 server push is not associated with a PUSH_PROMISE",
                ),
                StreamEvent::QpackDecoder { .. } => {}
            }
        }
    }

    fn process_control(
        &mut self,
        direction: Direction,
        data: &[u8],
        fin: bool,
        _timestamp_ns: u64,
    ) {
        let decoder = self
            .control
            .entry(direction)
            .or_insert_with(|| Http3FrameDecoder::new(self.limits.clone()));
        let frames = match decoder.push(data) {
            Ok(frames) => frames,
            Err(_) => {
                self.connection_diagnostic("malformed HTTP/3 control stream");
                return;
            }
        };
        for frame in frames {
            if !self.control_seen_settings.contains(&direction) {
                let Http3Frame::Settings(values) = frame else {
                    self.connection_diagnostic("SETTINGS is not the first HTTP/3 control frame");
                    return;
                };
                match PeerSettings::decode(&values, &self.limits) {
                    Ok(settings) => {
                        let sending_direction = direction.reverse();
                        self.qpack.insert(
                            sending_direction,
                            CompcolQpackCodec::new(settings.qpack_max_table_capacity, &self.limits),
                        );
                        self.peer_settings.insert(direction, settings);
                        self.control_seen_settings.insert(direction);
                    }
                    Err(_) => {
                        self.connection_diagnostic("invalid HTTP/3 SETTINGS frame");
                        return;
                    }
                }
            } else if matches!(frame, Http3Frame::Settings(_)) {
                self.connection_diagnostic("duplicate HTTP/3 SETTINGS frame");
                return;
            }
        }
        if fin {
            self.connection_diagnostic("HTTP/3 critical control stream was closed");
        }
    }

    fn process_encoder(&mut self, direction: Direction, data: &[u8]) {
        let Some(qpack) = self.qpack.get_mut(&direction) else {
            return;
        };
        if qpack.apply_encoder_instructions(data).is_err() {
            self.connection_diagnostic("malformed QPACK encoder stream");
            return;
        }
        self.release_blocked(direction);
    }

    fn process_request(
        &mut self,
        direction: Direction,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        timestamp_ns: u64,
    ) {
        let decoder = self
            .request_frames
            .entry((direction, stream_id))
            .or_insert_with(|| Http3FrameDecoder::new(self.limits.clone()));
        let frames = match decoder.push(data) {
            Ok(frames) => frames,
            Err(_) => {
                self.stream_diagnostic(
                    stream_id,
                    DiagnosticCode::MalformedDatagram,
                    "malformed HTTP/3 request stream frame",
                );
                return;
            }
        };
        self.messages.entry(stream_id).or_insert_with(|| {
            RequestStreamState::new(
                self.connection.0,
                stream_id,
                self.client,
                self.server,
                timestamp_ns,
                self.limits.clone(),
            )
        });
        for frame in frames {
            match frame {
                Http3Frame::Headers(block) => {
                    self.decode_headers(direction, stream_id, block, timestamp_ns)
                }
                Http3Frame::Data(data) => {
                    let result = self.messages.get_mut(&stream_id).unwrap().apply_data(
                        direction,
                        &data,
                        timestamp_ns,
                    );
                    if result.is_err() {
                        self.stream_diagnostic(
                            stream_id,
                            DiagnosticCode::ResourceLimit,
                            "HTTP/3 DATA is invalid or exceeds limits",
                        );
                    }
                }
                Http3Frame::PushPromise { .. } => {}
                _ => self.stream_diagnostic(
                    stream_id,
                    DiagnosticCode::UnsupportedProtocol,
                    "HTTP/3 frame is not valid on a request stream",
                ),
            }
        }
        if fin {
            if let Some(message) = self.messages.get_mut(&stream_id) {
                message.finish_direction(direction, timestamp_ns);
            }
            self.emit_if_complete(stream_id);
        }
    }

    fn decode_headers(
        &mut self,
        direction: Direction,
        stream_id: u64,
        block: Vec<u8>,
        timestamp_ns: u64,
    ) {
        self.ordinal = self.ordinal.saturating_add(1);
        let Some(qpack) = self.qpack.get_mut(&direction) else {
            return;
        };
        match qpack.decode_header_block(stream_id, &block) {
            Ok(QpackDecode::Headers(fields)) => {
                if self
                    .messages
                    .get_mut(&stream_id)
                    .unwrap()
                    .apply_headers(direction, fields, timestamp_ns)
                    .is_err()
                {
                    self.stream_diagnostic(
                        stream_id,
                        DiagnosticCode::MalformedDatagram,
                        "invalid HTTP/3 pseudo-header or field ordering",
                    );
                }
            }
            Ok(QpackDecode::Blocked {
                required_insert_count,
            }) => {
                let peer_limit = self
                    .peer_settings
                    .get(&direction.reverse())
                    .map(|settings| settings.qpack_blocked_streams)
                    .unwrap_or_default();
                let local_limit = self.limits.max_blocked_header_sections;
                let blocked_in_direction = self
                    .blocked
                    .iter()
                    .filter(|section| section.direction == direction)
                    .count();
                if blocked_in_direction >= peer_limit.min(local_limit) {
                    self.stream_diagnostic(
                        stream_id,
                        DiagnosticCode::ResourceLimit,
                        "QPACK blocked section limit exceeded",
                    );
                    return;
                }
                self.blocked.push(BlockedSection {
                    stream_id,
                    direction,
                    ordinal: self.ordinal,
                    required_insert_count,
                    field_section: block,
                    timestamp_ns,
                });
            }
            Err(_) => self.stream_diagnostic(
                stream_id,
                DiagnosticCode::MalformedDatagram,
                "QPACK field section could not be decoded",
            ),
        }
    }

    fn release_blocked(&mut self, direction: Direction) {
        let insert_count = self
            .qpack
            .get(&direction)
            .map(QpackCodec::insert_count)
            .unwrap_or_default();
        let mut ready = Vec::new();
        let mut waiting = Vec::new();
        for section in std::mem::take(&mut self.blocked) {
            if section.direction == direction && section.required_insert_count <= insert_count {
                ready.push(section);
            } else {
                waiting.push(section);
            }
        }
        ready.sort_by_key(|section| section.ordinal);
        self.blocked = waiting;
        for section in ready {
            self.decode_headers(
                section.direction,
                section.stream_id,
                section.field_section,
                section.timestamp_ns,
            );
        }
    }

    fn emit_if_complete(&mut self, stream_id: u64) {
        if !self
            .messages
            .get(&stream_id)
            .is_some_and(RequestStreamState::is_complete)
        {
            return;
        }
        if let Some(message) = self.messages.remove(&stream_id) {
            if let Ok(exchange) = message.into_exchange() {
                self.exchanges.push(exchange);
            }
        }
    }

    fn stream_diagnostic(&mut self, stream: u64, code: DiagnosticCode, message: &'static str) {
        self.diagnostics.push(Diagnostic::warning(
            code,
            DiagnosticScope::Stream {
                connection: self.connection.0,
                stream,
            },
            message,
        ));
    }

    fn connection_diagnostic(&mut self, message: &'static str) {
        self.diagnostics.push(Diagnostic::warning(
            DiagnosticCode::MalformedDatagram,
            DiagnosticScope::Connection {
                connection: self.connection.0,
            },
            message,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn empty_session_finishes_without_exchange() {
        let output = Http3Session::new(
            ConnectionId(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            DecodeLimits::testing(),
        )
        .finish();
        assert!(output.exchanges.is_empty());
    }
}
