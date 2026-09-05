use crate::{DecodeLimits, NormalizedTcpPacket};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TcpError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("packet timestamp is outside the supported range")]
    TimestampOutOfRange,
    #[error("TCP reassembly exceeds configured limits")]
    ResourceLimit,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl StreamKey {
    pub fn reverse(&self) -> StreamKey {
        StreamKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub fin: bool,
}

#[derive(Debug)]
pub struct TcpStream {
    pub key: StreamKey,
    pub segments: Vec<TcpSegment>,
}

impl TcpStream {
    pub fn new(key: StreamKey) -> Self {
        TcpStream {
            key,
            segments: Vec::new(),
        }
    }

    pub fn add_segment(&mut self, segment: TcpSegment) {
        self.segments.push(segment);
    }

    pub fn reassemble(&self) -> (Vec<u8>, Vec<DateTime<Utc>>) {
        if self.segments.is_empty() {
            return (Vec::new(), Vec::new());
        }

        let mut sorted_segments = self.segments.clone();
        sorted_segments.sort_by_key(|s| s.seq);

        let mut data = Vec::new();
        let mut timestamps = Vec::new();
        let mut next_seq: Option<u32> = None;

        for segment in sorted_segments {
            if segment.data.is_empty() {
                continue;
            }

            let seg_end = segment.seq.wrapping_add(segment.data.len() as u32);

            match next_seq {
                None => {
                    data.extend_from_slice(&segment.data);
                    timestamps.push(segment.timestamp);
                    next_seq = Some(seg_end);
                }
                Some(expected) => {
                    if segment.seq >= expected {
                        data.extend_from_slice(&segment.data);
                        timestamps.push(segment.timestamp);
                        next_seq = Some(seg_end);
                    } else if seg_end > expected {
                        let overlap = (expected - segment.seq) as usize;
                        if overlap < segment.data.len() {
                            data.extend_from_slice(&segment.data[overlap..]);
                            timestamps.push(segment.timestamp);
                            next_seq = Some(seg_end);
                        }
                    }
                    // completely retransmitted segment, skip it
                }
            }
        }

        (data, timestamps)
    }

    pub fn first_timestamp(&self) -> Option<DateTime<Utc>> {
        self.segments.iter().map(|s| s.timestamp).min()
    }

    pub fn last_timestamp(&self) -> Option<DateTime<Utc>> {
        self.segments.iter().map(|s| s.timestamp).max()
    }
}

pub struct TcpReassembler {
    streams: HashMap<StreamKey, TcpStream>,
    stream_usage: HashMap<StreamKey, StreamUsage>,
    connections: HashMap<ConnectionKey, usize>,
    total_buffered_bytes: usize,
    limits: DecodeLimits,
}

#[derive(Debug, Clone, Copy, Default)]
struct StreamUsage {
    bytes: usize,
    segments: usize,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct ConnectionKey {
    first: SocketAddr,
    second: SocketAddr,
}

impl ConnectionKey {
    fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        if src <= dst {
            Self {
                first: src,
                second: dst,
            }
        } else {
            Self {
                first: dst,
                second: src,
            }
        }
    }
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::with_limits(DecodeLimits::default())
    }

    pub(crate) fn with_limits(limits: DecodeLimits) -> Self {
        Self {
            streams: HashMap::new(),
            stream_usage: HashMap::new(),
            connections: HashMap::new(),
            total_buffered_bytes: 0,
            limits,
        }
    }

    pub fn ingest(&mut self, packet: NormalizedTcpPacket) -> Result<bool, TcpError> {
        let timestamp_ns =
            i64::try_from(packet.timestamp_ns).map_err(|_| TcpError::TimestampOutOfRange)?;
        let timestamp = DateTime::<Utc>::from_timestamp_nanos(timestamp_ns);
        let key = StreamKey {
            src_ip: packet.src.ip(),
            dst_ip: packet.dst.ip(),
            src_port: packet.src.port(),
            dst_port: packet.dst.port(),
        };
        let connection_key = ConnectionKey::new(packet.src, packet.dst);
        let new_connection = !self.connections.contains_key(&connection_key);
        if new_connection && self.connections.len() >= self.limits.max_connections {
            return Err(TcpError::ResourceLimit);
        }

        let payload_len = packet.payload.len();
        let usage = self.stream_usage.get(&key).copied().unwrap_or_default();
        let stream_bytes = usage
            .bytes
            .checked_add(payload_len)
            .filter(|bytes| *bytes <= self.limits.max_stream_bytes)
            .ok_or(TcpError::ResourceLimit)?;
        let stream_segments = usage
            .segments
            .checked_add(1)
            .filter(|segments| *segments <= self.limits.max_ranges_per_stream)
            .ok_or(TcpError::ResourceLimit)?;
        let connection_bytes = self
            .connections
            .get(&connection_key)
            .copied()
            .unwrap_or_default()
            .checked_add(payload_len)
            .filter(|bytes| *bytes <= self.limits.max_connection_bytes)
            .ok_or(TcpError::ResourceLimit)?;
        let total_buffered_bytes = self
            .total_buffered_bytes
            .checked_add(payload_len)
            .filter(|bytes| *bytes <= self.limits.max_total_buffered_bytes)
            .ok_or(TcpError::ResourceLimit)?;

        let segment = TcpSegment {
            seq: packet.sequence,
            data: packet.payload,
            timestamp,
            fin: packet.fin,
        };
        self.stream_usage.insert(
            key.clone(),
            StreamUsage {
                bytes: stream_bytes,
                segments: stream_segments,
            },
        );
        self.connections.insert(connection_key, connection_bytes);
        self.total_buffered_bytes = total_buffered_bytes;
        let stream = self
            .streams
            .entry(key.clone())
            .or_insert_with(|| TcpStream::new(key));
        stream.add_segment(segment);
        Ok(new_connection)
    }

    pub fn get_streams(self) -> HashMap<StreamKey, TcpStream> {
        self.streams
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_stream_key_creation() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
    }

    #[test]
    fn test_stream_key_reverse() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let reversed = key.reverse();

        assert_eq!(reversed.src_ip, key.dst_ip);
        assert_eq!(reversed.dst_ip, key.src_ip);
        assert_eq!(reversed.src_port, key.dst_port);
        assert_eq!(reversed.dst_port, key.src_port);
    }

    #[test]
    fn test_stream_key_equality() {
        let key1 = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let key2 = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_tcp_stream_new() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let stream = TcpStream::new(key.clone());

        assert_eq!(stream.key, key);
        assert!(stream.segments.is_empty());
    }

    #[test]
    fn test_tcp_stream_add_segment() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);

        let segment = TcpSegment {
            seq: 100,
            data: b"Hello".to_vec(),
            timestamp: Utc::now(),
            fin: false,
        };

        stream.add_segment(segment);

        assert_eq!(stream.segments.len(), 1);
        assert_eq!(stream.segments[0].seq, 100);
        assert_eq!(stream.segments[0].data, b"Hello");
    }

    #[test]
    fn test_tcp_stream_reassemble_empty() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let stream = TcpStream::new(key);
        let (data, timestamps) = stream.reassemble();

        assert!(data.is_empty());
        assert!(timestamps.is_empty());
    }

    #[test]
    fn test_tcp_stream_reassemble_single_segment() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello World".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, timestamps) = stream.reassemble();

        assert_eq!(data, b"Hello World");
        assert_eq!(timestamps.len(), 1);
        assert_eq!(timestamps[0], now);
    }

    #[test]
    fn test_tcp_stream_reassemble_multiple_segments_in_order() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello ".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 106,
            data: b"World".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, timestamps) = stream.reassemble();

        assert_eq!(data, b"Hello World");
        assert_eq!(timestamps.len(), 2);
    }

    #[test]
    fn test_tcp_stream_reassemble_out_of_order() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 200,
            data: b"World".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello ".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, _) = stream.reassemble();

        assert_eq!(data, b"Hello World");
    }

    #[test]
    fn test_tcp_stream_reassemble_skips_empty_segments() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 105,
            data: vec![],
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 106,
            data: b"World".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, timestamps) = stream.reassemble();

        assert_eq!(data, b"HelloWorld");
        assert_eq!(timestamps.len(), 2);
    }

    #[test]
    fn test_tcp_stream_first_timestamp() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);

        use chrono::Duration;
        let now = Utc::now();
        let later = now + Duration::seconds(1);

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"First".to_vec(),
            timestamp: later,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 200,
            data: b"Second".to_vec(),
            timestamp: now,
            fin: false,
        });

        let first = stream.first_timestamp();
        assert_eq!(first, Some(now));
    }

    #[test]
    fn test_tcp_stream_last_timestamp() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);

        use chrono::Duration;
        let now = Utc::now();
        let later = now + Duration::seconds(1);

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"First".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 200,
            data: b"Second".to_vec(),
            timestamp: later,
            fin: false,
        });

        let last = stream.last_timestamp();
        assert_eq!(last, Some(later));
    }

    #[test]
    fn test_tcp_reassembler_new() {
        let reassembler = TcpReassembler::new();
        let streams = reassembler.get_streams();

        assert!(streams.is_empty());
    }

    #[test]
    fn test_tcp_reassembler_default() {
        let reassembler = TcpReassembler::default();
        let streams = reassembler.get_streams();

        assert!(streams.is_empty());
    }

    #[test]
    fn test_tcp_segment_with_fin_flag() {
        let segment = TcpSegment {
            seq: 100,
            data: b"FIN".to_vec(),
            timestamp: Utc::now(),
            fin: true,
        };

        assert!(segment.fin);
        assert_eq!(segment.data, b"FIN");
    }
}
