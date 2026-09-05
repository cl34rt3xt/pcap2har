use super::varint::{decode_varint, VarIntError};
use crate::quic::Direction;
use crate::DecodeLimits;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Control {
        direction: Direction,
        data: Vec<u8>,
        fin: bool,
        timestamp_ns: u64,
    },
    Push {
        direction: Direction,
        stream_id: u64,
        push_id: u64,
        data: Vec<u8>,
        fin: bool,
        timestamp_ns: u64,
    },
    QpackEncoder {
        direction: Direction,
        data: Vec<u8>,
        fin: bool,
        timestamp_ns: u64,
    },
    QpackDecoder {
        direction: Direction,
        data: Vec<u8>,
        fin: bool,
        timestamp_ns: u64,
    },
    Request {
        direction: Direction,
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
        timestamp_ns: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("server-initiated bidirectional stream is invalid for HTTP/3")]
    ServerBidirectional,
    #[error("duplicate HTTP/3 critical stream")]
    DuplicateCritical,
    #[error("HTTP/3 stream prefix is truncated")]
    TruncatedPrefix,
    #[error("HTTP/3 stream prefix exceeds configured limits")]
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UniKind {
    Control,
    Push(u64),
    QpackEncoder,
    QpackDecoder,
    Unknown,
}

#[derive(Debug, Default)]
struct UniState {
    prefix: Vec<u8>,
    kind: Option<UniKind>,
}

pub struct StreamRouter {
    limits: DecodeLimits,
    uni: BTreeMap<(Direction, u64), UniState>,
    critical: BTreeSet<(Direction, u64)>,
}

impl StreamRouter {
    pub fn new(limits: DecodeLimits) -> Self {
        Self {
            limits,
            uni: BTreeMap::new(),
            critical: BTreeSet::new(),
        }
    }

    pub fn push(
        &mut self,
        direction: Direction,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        timestamp_ns: u64,
    ) -> Result<Vec<StreamEvent>, StreamError> {
        let server_initiated = stream_id & 0x01 != 0;
        let unidirectional = stream_id & 0x02 != 0;
        if !unidirectional {
            if server_initiated {
                return Err(StreamError::ServerBidirectional);
            }
            return Ok(vec![StreamEvent::Request {
                direction,
                stream_id,
                data: data.to_vec(),
                fin,
                timestamp_ns,
            }]);
        }

        let state = self.uni.entry((direction, stream_id)).or_default();
        let body = if state.kind.is_some() {
            data.to_vec()
        } else {
            let next = state
                .prefix
                .len()
                .checked_add(data.len())
                .ok_or(StreamError::LimitExceeded)?;
            if next > self.limits.max_stream_bytes {
                return Err(StreamError::LimitExceeded);
            }
            let mut combined = Vec::with_capacity(next);
            combined.extend_from_slice(&state.prefix);
            combined.extend_from_slice(data);
            let (stream_type, consumed) = match decode_varint(&combined) {
                Ok(value) => value,
                Err(VarIntError::Incomplete) if !fin => {
                    if combined.len() > 8 {
                        return Err(StreamError::LimitExceeded);
                    }
                    state.prefix = combined;
                    return Ok(Vec::new());
                }
                Err(_) => return Err(StreamError::TruncatedPrefix),
            };
            let (kind, prefix_len) = if stream_type == 0x01 {
                let (push_id, push_len) = match decode_varint(&combined[consumed..]) {
                    Ok(value) => value,
                    Err(VarIntError::Incomplete) if !fin => {
                        if combined.len() > 16 {
                            return Err(StreamError::LimitExceeded);
                        }
                        state.prefix = combined;
                        return Ok(Vec::new());
                    }
                    Err(_) => return Err(StreamError::TruncatedPrefix),
                };
                (UniKind::Push(push_id), consumed + push_len)
            } else {
                (
                    match stream_type {
                        0x00 => UniKind::Control,
                        0x02 => UniKind::QpackEncoder,
                        0x03 => UniKind::QpackDecoder,
                        _ => UniKind::Unknown,
                    },
                    consumed,
                )
            };
            if let Some(critical_type) = match kind {
                UniKind::Control => Some(0),
                UniKind::QpackEncoder => Some(2),
                UniKind::QpackDecoder => Some(3),
                _ => None,
            } {
                if !self.critical.insert((direction, critical_type)) {
                    return Err(StreamError::DuplicateCritical);
                }
            }
            state.kind = Some(kind);
            let body = combined[prefix_len..].to_vec();
            state.prefix.clear();
            body
        };

        let event = match state.kind.as_ref().expect("classified stream") {
            UniKind::Control => Some(StreamEvent::Control {
                direction,
                data: body,
                fin,
                timestamp_ns,
            }),
            UniKind::Push(push_id) => Some(StreamEvent::Push {
                direction,
                stream_id,
                push_id: *push_id,
                data: body,
                fin,
                timestamp_ns,
            }),
            UniKind::QpackEncoder => Some(StreamEvent::QpackEncoder {
                direction,
                data: body,
                fin,
                timestamp_ns,
            }),
            UniKind::QpackDecoder => Some(StreamEvent::QpackDecoder {
                direction,
                data: body,
                fin,
                timestamp_ns,
            }),
            UniKind::Unknown => None,
        };
        Ok(event.into_iter().collect())
    }

    pub fn buffered_bytes(&self) -> usize {
        self.uni.values().map(|state| state.prefix.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_fragmented_unidirectional_prefix() {
        let mut router = StreamRouter::new(DecodeLimits::default());
        assert!(router
            .push(Direction::ServerToClient, 3, &[0x40], false, 10)
            .unwrap()
            .is_empty());
        assert!(matches!(
            &router
                .push(Direction::ServerToClient, 3, &[0x02], false, 11)
                .unwrap()[0],
            StreamEvent::QpackEncoder { data, .. } if data.is_empty()
        ));
    }

    #[test]
    fn client_bidi_stream_is_request_stream() {
        let mut router = StreamRouter::new(DecodeLimits::default());
        assert!(matches!(
            &router
                .push(Direction::ClientToServer, 4, b"abc", false, 10)
                .unwrap()[0],
            StreamEvent::Request { data, .. } if data == b"abc"
        ));
    }

    #[test]
    fn keeps_control_classification_across_chunks() {
        let mut router = StreamRouter::new(DecodeLimits::default());
        let first = hex::decode(
            "00041b018001000006800400000740643301c000000a6286fa20bc62e6c7c00000124cce87a70258ab",
        )
        .unwrap();
        let second = hex::decode("800f07000700753d302c2069").unwrap();
        assert!(matches!(
            &router
                .push(Direction::ClientToServer, 2, &first, false, 10)
                .unwrap()[0],
            StreamEvent::Control { .. }
        ));
        assert!(matches!(
            &router
                .push(Direction::ClientToServer, 2, &second, false, 11)
                .unwrap()[0],
            StreamEvent::Control { .. }
        ));
    }
}
