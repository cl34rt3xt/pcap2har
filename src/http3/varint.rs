#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VarIntError {
    #[error("incomplete QUIC variable-length integer")]
    Incomplete,
}

pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), VarIntError> {
    let first = *input.first().ok_or(VarIntError::Incomplete)?;
    let length = 1usize << (first >> 6);
    let bytes = input.get(..length).ok_or(VarIntError::Incomplete)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_all_widths() {
        assert_eq!(decode_varint(&[0x25]), Ok((37, 1)));
        assert_eq!(decode_varint(&[0x7b, 0xbd]), Ok((15_293, 2)));
        assert_eq!(
            decode_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Ok((494_878_333, 4))
        );
        assert_eq!(
            decode_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Ok((151_288_809_941_952_652, 8))
        );
    }
}
