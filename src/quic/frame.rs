use crate::DecodeLimits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicFrame<'a> {
    Padding {
        count: usize,
    },
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        range_count: u64,
        first_range: u64,
        ecn: Option<[u64; 3]>,
    },
    ResetStream {
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        application_error_code: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken(&'a [u8]),
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    MaxData(u64),
    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },
    MaxStreams {
        bidirectional: bool,
        maximum: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },
    StreamsBlocked {
        bidirectional: bool,
        limit: u64,
    },
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        connection_id: &'a [u8],
        reset_token: [u8; 16],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        application: bool,
        error_code: u64,
        frame_type: Option<u64>,
        reason: &'a [u8],
    },
    HandshakeDone,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("truncated QUIC frame")]
    Truncated,
    #[error("invalid QUIC variable-length integer")]
    InvalidVarint,
    #[error("QUIC frame type {0} is unsupported")]
    UnknownType(u64),
    #[error("QUIC frame exceeds configured limits")]
    LimitExceeded,
    #[error("invalid QUIC frame")]
    Invalid,
}

pub struct FrameDecoder<'a> {
    remaining: &'a [u8],
    limits: &'a DecodeLimits,
    failed: bool,
}

impl<'a> FrameDecoder<'a> {
    pub fn new(payload: &'a [u8], limits: &'a DecodeLimits) -> Self {
        Self {
            remaining: payload,
            limits,
            failed: false,
        }
    }
}

impl<'a> Iterator for FrameDecoder<'a> {
    type Item = Result<QuicFrame<'a>, FrameError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        match decode_one(self.remaining, self.limits) {
            Ok((frame, consumed)) if consumed > 0 => {
                self.remaining = &self.remaining[consumed..];
                Some(Ok(frame))
            }
            Ok(_) => {
                self.failed = true;
                Some(Err(FrameError::Invalid))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

pub fn decode_all<'a>(
    payload: &'a [u8],
    limits: &'a DecodeLimits,
) -> Result<Vec<QuicFrame<'a>>, FrameError> {
    FrameDecoder::new(payload, limits).collect()
}

pub fn decode_one<'a>(
    input: &'a [u8],
    limits: &DecodeLimits,
) -> Result<(QuicFrame<'a>, usize), FrameError> {
    if input.len() > limits.max_frame_bytes {
        return Err(FrameError::LimitExceeded);
    }
    if input.first() == Some(&0) {
        let count = input.iter().take_while(|byte| **byte == 0).count();
        return Ok((QuicFrame::Padding { count }, count));
    }

    let mut cursor = Cursor::new(input);
    let frame_type = cursor.varint()?;
    let frame = match frame_type {
        0x01 => QuicFrame::Ping,
        0x02 | 0x03 => decode_ack(&mut cursor, frame_type == 0x03)?,
        0x04 => QuicFrame::ResetStream {
            stream_id: cursor.varint()?,
            application_error_code: cursor.varint()?,
            final_size: cursor.varint()?,
        },
        0x05 => QuicFrame::StopSending {
            stream_id: cursor.varint()?,
            application_error_code: cursor.varint()?,
        },
        0x06 => {
            let offset = cursor.varint()?;
            let data = cursor.length_prefixed(limits.max_frame_bytes)?;
            QuicFrame::Crypto { offset, data }
        }
        0x07 => QuicFrame::NewToken(cursor.length_prefixed(limits.max_frame_bytes)?),
        0x08..=0x0f => {
            let id = cursor.varint()?;
            let offset = if frame_type & 0x04 != 0 {
                cursor.varint()?
            } else {
                0
            };
            let data = if frame_type & 0x02 != 0 {
                cursor.length_prefixed(limits.max_frame_bytes)?
            } else {
                cursor.rest(limits.max_frame_bytes)?
            };
            QuicFrame::Stream {
                id,
                offset,
                fin: frame_type & 0x01 != 0,
                data,
            }
        }
        0x10 => QuicFrame::MaxData(cursor.varint()?),
        0x11 => QuicFrame::MaxStreamData {
            stream_id: cursor.varint()?,
            maximum: cursor.varint()?,
        },
        0x12 | 0x13 => QuicFrame::MaxStreams {
            bidirectional: frame_type == 0x12,
            maximum: cursor.varint()?,
        },
        0x14 => QuicFrame::DataBlocked(cursor.varint()?),
        0x15 => QuicFrame::StreamDataBlocked {
            stream_id: cursor.varint()?,
            limit: cursor.varint()?,
        },
        0x16 | 0x17 => QuicFrame::StreamsBlocked {
            bidirectional: frame_type == 0x16,
            limit: cursor.varint()?,
        },
        0x18 => {
            let sequence = cursor.varint()?;
            let retire_prior_to = cursor.varint()?;
            if retire_prior_to > sequence {
                return Err(FrameError::Invalid);
            }
            let cid_len = usize::from(cursor.byte()?);
            if !(1..=20).contains(&cid_len) {
                return Err(FrameError::Invalid);
            }
            let connection_id = cursor.take(cid_len)?;
            let reset_token = cursor
                .take(16)?
                .try_into()
                .map_err(|_| FrameError::Truncated)?;
            QuicFrame::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                reset_token,
            }
        }
        0x19 => QuicFrame::RetireConnectionId(cursor.varint()?),
        0x1a => QuicFrame::PathChallenge(cursor.take(8)?.try_into().unwrap()),
        0x1b => QuicFrame::PathResponse(cursor.take(8)?.try_into().unwrap()),
        0x1c | 0x1d => {
            let error_code = cursor.varint()?;
            let frame = (frame_type == 0x1c).then(|| cursor.varint()).transpose()?;
            let reason = cursor.length_prefixed(limits.max_frame_bytes)?;
            QuicFrame::ConnectionClose {
                application: frame_type == 0x1d,
                error_code,
                frame_type: frame,
                reason,
            }
        }
        0x1e => QuicFrame::HandshakeDone,
        value => return Err(FrameError::UnknownType(value)),
    };
    Ok((frame, cursor.position()))
}

fn decode_ack<'a>(cursor: &mut Cursor<'a>, has_ecn: bool) -> Result<QuicFrame<'a>, FrameError> {
    let largest = cursor.varint()?;
    let delay = cursor.varint()?;
    let range_count = cursor.varint()?;
    let first_range = cursor.varint()?;
    if first_range > largest {
        return Err(FrameError::Invalid);
    }
    for _ in 0..range_count {
        let _gap = cursor.varint()?;
        let _range = cursor.varint()?;
    }
    let ecn = has_ecn
        .then(|| Ok([cursor.varint()?, cursor.varint()?, cursor.varint()?]))
        .transpose()?;
    Ok(QuicFrame::Ack {
        largest,
        delay,
        range_count,
        first_range,
        ecn,
    })
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn byte(&mut self) -> Result<u8, FrameError> {
        let byte = *self.input.get(self.offset).ok_or(FrameError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FrameError> {
        let end = self.offset.checked_add(len).ok_or(FrameError::Truncated)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(FrameError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn rest(&mut self, limit: usize) -> Result<&'a [u8], FrameError> {
        let len = self.input.len().saturating_sub(self.offset);
        if len > limit {
            return Err(FrameError::LimitExceeded);
        }
        self.take(len)
    }

    fn length_prefixed(&mut self, limit: usize) -> Result<&'a [u8], FrameError> {
        let len = usize::try_from(self.varint()?).map_err(|_| FrameError::LimitExceeded)?;
        if len > limit {
            return Err(FrameError::LimitExceeded);
        }
        self.take(len)
    }

    fn varint(&mut self) -> Result<u64, FrameError> {
        let first = self.byte()?;
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(len - 1)? {
            value = value.checked_shl(8).ok_or(FrameError::InvalidVarint)? | u64::from(*byte);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_stream_offset_length_and_fin() {
        let bytes = hex::decode("0f0403056162636465").unwrap();
        let limits = DecodeLimits::default();
        let frames = decode_all(&bytes, &limits).unwrap();
        assert_eq!(
            frames,
            vec![QuicFrame::Stream {
                id: 4,
                offset: 3,
                fin: true,
                data: b"abcde"
            }]
        );
    }

    #[test]
    fn declared_frame_length_is_checked_before_slicing() {
        let bytes = hex::decode("0a00056162636465").unwrap();
        let limits = DecodeLimits {
            max_frame_bytes: 4,
            ..DecodeLimits::default()
        };
        assert_eq!(decode_one(&bytes, &limits), Err(FrameError::LimitExceeded));
    }

    #[test]
    fn malformed_new_connection_id_is_rejected() {
        let limits = DecodeLimits::default();
        assert_eq!(
            decode_one(&[0x18, 1, 2, 1, 9], &limits),
            Err(FrameError::Invalid)
        );
    }
}
