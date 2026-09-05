use super::varint::{decode_varint, VarIntError};
use crate::DecodeLimits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http3Frame {
    Data(Vec<u8>),
    Headers(Vec<u8>),
    CancelPush(u64),
    Settings(Vec<(u64, u64)>),
    PushPromise {
        push_id: u64,
        field_section: Vec<u8>,
    },
    Goaway(u64),
    MaxPushId(u64),
    PriorityUpdate {
        element_type: u64,
        element_id: u64,
        value: Vec<u8>,
    },
    Unknown {
        frame_type: u64,
        payload_len: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Http3FrameError {
    #[error("HTTP/3 frame exceeds configured limits")]
    LimitExceeded,
    #[error("malformed HTTP/3 frame")]
    Malformed,
}

pub struct Http3FrameDecoder {
    buffer: Vec<u8>,
    limits: DecodeLimits,
}

impl Http3FrameDecoder {
    pub fn new(limits: DecodeLimits) -> Self {
        Self {
            buffer: Vec::new(),
            limits,
        }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Http3Frame>, Http3FrameError> {
        let next = self
            .buffer
            .len()
            .checked_add(data.len())
            .ok_or(Http3FrameError::LimitExceeded)?;
        let maximum = self
            .limits
            .max_frame_bytes
            .checked_add(16)
            .ok_or(Http3FrameError::LimitExceeded)?;
        if next > maximum {
            return Err(Http3FrameError::LimitExceeded);
        }
        self.buffer.extend_from_slice(data);
        let mut frames = Vec::new();
        let mut consumed = 0usize;
        loop {
            let available = &self.buffer[consumed..];
            let Ok((frame_type, type_len)) = decode_varint(available) else {
                break;
            };
            let Ok((payload_len, length_len)) = decode_varint(&available[type_len..]) else {
                break;
            };
            let payload_len =
                usize::try_from(payload_len).map_err(|_| Http3FrameError::LimitExceeded)?;
            if payload_len > self.limits.max_frame_bytes {
                return Err(Http3FrameError::LimitExceeded);
            }
            let header_len = type_len
                .checked_add(length_len)
                .ok_or(Http3FrameError::LimitExceeded)?;
            let total_len = header_len
                .checked_add(payload_len)
                .ok_or(Http3FrameError::LimitExceeded)?;
            if available.len() < total_len {
                break;
            }
            let payload = &available[header_len..total_len];
            frames.push(decode_payload(frame_type, payload)?);
            consumed = consumed
                .checked_add(total_len)
                .ok_or(Http3FrameError::LimitExceeded)?;
        }
        if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        Ok(frames)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
}

fn decode_payload(frame_type: u64, payload: &[u8]) -> Result<Http3Frame, Http3FrameError> {
    Ok(match frame_type {
        0x00 => Http3Frame::Data(payload.to_vec()),
        0x01 => Http3Frame::Headers(payload.to_vec()),
        0x03 => Http3Frame::CancelPush(exact_varint(payload)?),
        0x04 => Http3Frame::Settings(varint_pairs(payload)?),
        0x05 => {
            let (push_id, consumed) =
                decode_varint(payload).map_err(|_| Http3FrameError::Malformed)?;
            Http3Frame::PushPromise {
                push_id,
                field_section: payload[consumed..].to_vec(),
            }
        }
        0x07 => Http3Frame::Goaway(exact_varint(payload)?),
        0x0d => Http3Frame::MaxPushId(exact_varint(payload)?),
        0xf0700 | 0xf0701 => {
            let (element_id, consumed) =
                decode_varint(payload).map_err(|_| Http3FrameError::Malformed)?;
            Http3Frame::PriorityUpdate {
                element_type: frame_type,
                element_id,
                value: payload[consumed..].to_vec(),
            }
        }
        _ => Http3Frame::Unknown {
            frame_type,
            payload_len: payload.len(),
        },
    })
}

fn exact_varint(payload: &[u8]) -> Result<u64, Http3FrameError> {
    let (value, consumed) = decode_varint(payload).map_err(|_| Http3FrameError::Malformed)?;
    if consumed != payload.len() {
        return Err(Http3FrameError::Malformed);
    }
    Ok(value)
}

fn varint_pairs(mut payload: &[u8]) -> Result<Vec<(u64, u64)>, Http3FrameError> {
    let mut values = Vec::new();
    while !payload.is_empty() {
        let (identifier, first) = decode_varint(payload).map_err(|_| Http3FrameError::Malformed)?;
        payload = &payload[first..];
        let (value, second) = decode_varint(payload).map_err(|_| Http3FrameError::Malformed)?;
        payload = &payload[second..];
        values.push((identifier, value));
    }
    Ok(values)
}

impl From<VarIntError> for Http3FrameError {
    fn from(_: VarIntError) -> Self {
        Self::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_fragmented_payload() {
        let mut decoder = Http3FrameDecoder::new(DecodeLimits::default());
        assert!(decoder.push(&[0x00, 0x05, b'h', b'e']).unwrap().is_empty());
        assert_eq!(
            decoder.push(b"llo").unwrap(),
            vec![Http3Frame::Data(b"hello".to_vec())]
        );
    }

    #[test]
    fn parses_multiple_frames_in_one_chunk() {
        let mut decoder = Http3FrameDecoder::new(DecodeLimits::default());
        assert_eq!(
            decoder.push(&[0, 1, b'a', 1, 1, b'b']).unwrap(),
            vec![
                Http3Frame::Data(vec![b'a']),
                Http3Frame::Headers(vec![b'b'])
            ]
        );
    }
}
