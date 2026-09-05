use crate::DecodeLimits;
use compcol::qpack::QpackDecoder;

const MIN_ENCODER_BUFFER_BYTES: usize = 16;
const FIELD_ENTRY_OVERHEAD: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QpackDecode {
    Headers(Vec<(Vec<u8>, Vec<u8>)>),
    Blocked { required_insert_count: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QpackError {
    #[error("QPACK decoder direction is disabled")]
    Disabled,
    #[error("QPACK encoder instruction exceeds the {limit}-byte buffer limit")]
    EncoderStreamLimitExceeded { limit: usize },
    #[error("malformed QPACK encoder stream")]
    MalformedEncoderStream,
    #[error("invalid QPACK required insert count on stream {stream_id}")]
    InvalidRequiredInsertCount { stream_id: u64 },
    #[error("malformed QPACK field section on stream {stream_id}")]
    MalformedHeaderBlock { stream_id: u64 },
    #[error("QPACK field section on stream {stream_id} exceeds the {limit}-byte limit")]
    HeaderSectionLimitExceeded { stream_id: u64, limit: usize },
}

pub trait QpackCodec {
    fn apply_encoder_instructions(&mut self, data: &[u8]) -> Result<(), QpackError>;

    fn decode_header_block(
        &mut self,
        stream_id: u64,
        block: &[u8],
    ) -> Result<QpackDecode, QpackError>;

    fn insert_count(&self) -> usize;
}

#[derive(Debug)]
pub struct CompcolQpackCodec {
    decoder: QpackDecoder,
    max_table_capacity: usize,
    max_encoder_buffer_bytes: usize,
    max_header_section_bytes: usize,
    encoder_buffer: Vec<u8>,
    disabled: bool,
}

impl CompcolQpackCodec {
    #[must_use]
    pub fn new(peer_max_table_capacity: usize, limits: &DecodeLimits) -> Self {
        let max_table_capacity = peer_max_table_capacity.min(limits.max_qpack_table_bytes);
        Self {
            decoder: QpackDecoder::with_max_table_capacity(max_table_capacity),
            max_table_capacity,
            max_encoder_buffer_bytes: max_table_capacity.max(MIN_ENCODER_BUFFER_BYTES),
            max_header_section_bytes: limits.max_header_section_bytes,
            encoder_buffer: Vec::new(),
            disabled: false,
        }
    }

    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    #[must_use]
    pub fn buffered_encoder_bytes(&self) -> usize {
        self.encoder_buffer.len()
    }

    fn encoder_error(&mut self, error: QpackError) -> QpackError {
        self.disabled = true;
        self.encoder_buffer.clear();
        error
    }

    fn feed_instruction(&mut self, instruction: &[u8]) -> Result<(), QpackError> {
        self.decoder
            .feed_encoder_stream(instruction)
            .map_err(|_| self.encoder_error(QpackError::MalformedEncoderStream))
    }

    fn check_incomplete_instruction(
        &mut self,
        required_bytes: Option<usize>,
    ) -> Result<(), QpackError> {
        if required_bytes.is_some_and(|required| required > self.max_encoder_buffer_bytes)
            || self.encoder_buffer.len() > self.max_encoder_buffer_bytes
        {
            let limit = self.max_encoder_buffer_bytes;
            return Err(self.encoder_error(QpackError::EncoderStreamLimitExceeded { limit }));
        }
        Ok(())
    }
}

impl QpackCodec for CompcolQpackCodec {
    fn apply_encoder_instructions(&mut self, data: &[u8]) -> Result<(), QpackError> {
        if self.disabled {
            return Err(QpackError::Disabled);
        }

        let mut input_offset = 0;
        loop {
            if self.encoder_buffer.is_empty() {
                if input_offset == data.len() {
                    return Ok(());
                }

                match scan_encoder_instruction(&data[input_offset..]) {
                    Ok(instruction_len) => {
                        if instruction_len > self.max_encoder_buffer_bytes {
                            let limit = self.max_encoder_buffer_bytes;
                            return Err(self
                                .encoder_error(QpackError::EncoderStreamLimitExceeded { limit }));
                        }
                        let end = input_offset.checked_add(instruction_len).ok_or_else(|| {
                            self.encoder_error(QpackError::MalformedEncoderStream)
                        })?;
                        self.feed_instruction(&data[input_offset..end])?;
                        input_offset = end;
                    }
                    Err(ScanError::Incomplete { required_bytes }) => {
                        if required_bytes
                            .is_some_and(|required| required > self.max_encoder_buffer_bytes)
                            || data.len() - input_offset > self.max_encoder_buffer_bytes
                        {
                            let limit = self.max_encoder_buffer_bytes;
                            return Err(self
                                .encoder_error(QpackError::EncoderStreamLimitExceeded { limit }));
                        }
                        self.encoder_buffer.extend_from_slice(&data[input_offset..]);
                        return Ok(());
                    }
                    Err(ScanError::Malformed) => {
                        return Err(self.encoder_error(QpackError::MalformedEncoderStream));
                    }
                }
                continue;
            }

            match scan_encoder_instruction(&self.encoder_buffer) {
                Ok(instruction_len) => {
                    if instruction_len > self.max_encoder_buffer_bytes {
                        let limit = self.max_encoder_buffer_bytes;
                        return Err(
                            self.encoder_error(QpackError::EncoderStreamLimitExceeded { limit })
                        );
                    }
                    let tail = self.encoder_buffer.split_off(instruction_len);
                    let instruction = std::mem::replace(&mut self.encoder_buffer, tail);
                    self.feed_instruction(&instruction)?;
                }
                Err(ScanError::Incomplete { required_bytes }) => {
                    self.check_incomplete_instruction(required_bytes)?;
                    if input_offset == data.len() {
                        return Ok(());
                    }

                    let detect_limit = self.max_encoder_buffer_bytes.saturating_add(1);
                    let room = detect_limit.saturating_sub(self.encoder_buffer.len());
                    if room == 0 {
                        let limit = self.max_encoder_buffer_bytes;
                        return Err(
                            self.encoder_error(QpackError::EncoderStreamLimitExceeded { limit })
                        );
                    }
                    let take = room.min(data.len() - input_offset);
                    self.encoder_buffer
                        .extend_from_slice(&data[input_offset..input_offset + take]);
                    input_offset += take;
                }
                Err(ScanError::Malformed) => {
                    return Err(self.encoder_error(QpackError::MalformedEncoderStream));
                }
            }
        }
    }

    fn decode_header_block(
        &mut self,
        stream_id: u64,
        block: &[u8],
    ) -> Result<QpackDecode, QpackError> {
        if self.disabled {
            return Err(QpackError::Disabled);
        }
        if block.len() > self.max_header_section_bytes {
            return Err(QpackError::HeaderSectionLimitExceeded {
                stream_id,
                limit: self.max_header_section_bytes,
            });
        }

        let (required_insert_count, prefix_len) =
            required_insert_count(block, self.decoder.insert_count(), self.max_table_capacity)
                .map_err(|error| match error {
                    RequiredInsertCountError::Invalid => {
                        QpackError::InvalidRequiredInsertCount { stream_id }
                    }
                    RequiredInsertCountError::Malformed => {
                        QpackError::MalformedHeaderBlock { stream_id }
                    }
                })?;
        scan_prefixed_integer(block, prefix_len, 7)
            .map_err(|_| QpackError::MalformedHeaderBlock { stream_id })?;

        if required_insert_count > self.decoder.insert_count() {
            return Ok(QpackDecode::Blocked {
                required_insert_count,
            });
        }

        let fields = self
            .decoder
            .decode_field_section(block)
            .map_err(|_| QpackError::MalformedHeaderBlock { stream_id })?;
        let mut decoded_bytes = 0usize;
        for field in &fields {
            decoded_bytes = decoded_bytes
                .checked_add(field.name.len())
                .and_then(|size| size.checked_add(field.value.len()))
                .and_then(|size| size.checked_add(FIELD_ENTRY_OVERHEAD))
                .ok_or(QpackError::HeaderSectionLimitExceeded {
                    stream_id,
                    limit: self.max_header_section_bytes,
                })?;
            if decoded_bytes > self.max_header_section_bytes {
                return Err(QpackError::HeaderSectionLimitExceeded {
                    stream_id,
                    limit: self.max_header_section_bytes,
                });
            }
        }

        Ok(QpackDecode::Headers(
            fields
                .into_iter()
                .map(|field| (field.name, field.value))
                .collect(),
        ))
    }

    fn insert_count(&self) -> usize {
        self.decoder.insert_count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanError {
    Incomplete { required_bytes: Option<usize> },
    Malformed,
}

fn scan_encoder_instruction(data: &[u8]) -> Result<usize, ScanError> {
    let first = *data.first().ok_or(ScanError::Incomplete {
        required_bytes: None,
    })?;
    if first & 0x80 != 0 {
        let (_, value_offset) = scan_prefixed_integer(data, 0, 6)?;
        scan_string(data, value_offset, 7)
    } else if first & 0x40 != 0 {
        let value_offset = scan_string(data, 0, 5)?;
        scan_string(data, value_offset, 7)
    } else {
        scan_prefixed_integer(data, 0, 5).map(|(_, end)| end)
    }
}

fn scan_string(data: &[u8], offset: usize, prefix_bits: u32) -> Result<usize, ScanError> {
    let (length, value_offset) = scan_prefixed_integer(data, offset, prefix_bits)?;
    let end = value_offset
        .checked_add(length)
        .ok_or(ScanError::Malformed)?;
    if end > data.len() {
        return Err(ScanError::Incomplete {
            required_bytes: Some(end),
        });
    }
    Ok(end)
}

fn scan_prefixed_integer(
    data: &[u8],
    offset: usize,
    prefix_bits: u32,
) -> Result<(usize, usize), ScanError> {
    let first = *data.get(offset).ok_or(ScanError::Incomplete {
        required_bytes: None,
    })? as usize;
    let max_prefix = (1usize << prefix_bits) - 1;
    let mut value = first & max_prefix;
    let mut position = offset + 1;
    if value < max_prefix {
        return Ok((value, position));
    }

    let mut shift = 0u32;
    loop {
        let byte = *data.get(position).ok_or(ScanError::Incomplete {
            required_bytes: None,
        })? as usize;
        position += 1;
        if shift >= usize::BITS {
            return Err(ScanError::Malformed);
        }
        let payload = byte & 0x7f;
        if payload > (usize::MAX >> shift) {
            return Err(ScanError::Malformed);
        }
        let addition = payload << shift;
        value = value.checked_add(addition).ok_or(ScanError::Malformed)?;
        if byte & 0x80 == 0 {
            return Ok((value, position));
        }
        shift += 7;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequiredInsertCountError {
    Invalid,
    Malformed,
}

fn required_insert_count(
    block: &[u8],
    total_inserts: usize,
    max_table_capacity: usize,
) -> Result<(usize, usize), RequiredInsertCountError> {
    let (encoded, prefix_len) =
        scan_prefixed_integer(block, 0, 8).map_err(|error| match error {
            ScanError::Incomplete { .. } => RequiredInsertCountError::Malformed,
            ScanError::Malformed => RequiredInsertCountError::Invalid,
        })?;
    if encoded == 0 {
        return Ok((0, prefix_len));
    }

    let max_entries = max_table_capacity / FIELD_ENTRY_OVERHEAD;
    let full_range = max_entries
        .checked_mul(2)
        .ok_or(RequiredInsertCountError::Invalid)?;
    if full_range == 0 || encoded > full_range {
        return Err(RequiredInsertCountError::Invalid);
    }

    let max_value = total_inserts
        .checked_add(max_entries)
        .ok_or(RequiredInsertCountError::Invalid)?;
    let max_wrapped = (max_value / full_range)
        .checked_mul(full_range)
        .ok_or(RequiredInsertCountError::Invalid)?;
    let mut required = max_wrapped
        .checked_add(encoded - 1)
        .ok_or(RequiredInsertCountError::Invalid)?;
    if required > max_value {
        if required <= full_range {
            return Err(RequiredInsertCountError::Invalid);
        }
        required = required
            .checked_sub(full_range)
            .ok_or(RequiredInsertCountError::Invalid)?;
    }
    if required == 0 {
        return Err(RequiredInsertCountError::Invalid);
    }
    Ok((required, prefix_len))
}
