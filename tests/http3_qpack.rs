use compcol::hpack::HeaderField;
use compcol::qpack::QpackEncoder;
use pcap2har::http3::qpack::{CompcolQpackCodec, QpackCodec, QpackDecode, QpackError};
use pcap2har::DecodeLimits;

fn codec(capacity: usize) -> CompcolQpackCodec {
    CompcolQpackCodec::new(capacity, &DecodeLimits::testing())
}

fn appendix_b_encoder_stream() -> Vec<u8> {
    let mut bytes = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
    bytes.extend_from_slice(b"www.example.com");
    bytes.extend_from_slice(&[0xc1, 0x0c]);
    bytes.extend_from_slice(b"/sample/path");
    bytes
}

#[test]
fn decodes_static_and_huffman_fields() {
    let mut decoder = codec(220);
    let static_block = [
        0x00, 0x00, 0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l',
    ];
    assert_eq!(
        decoder.decode_header_block(0, &static_block).unwrap(),
        QpackDecode::Headers(vec![(b":path".to_vec(), b"/index.html".to_vec())])
    );

    let fields = [
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b"x-compressible-header", b"www.example.com/index.html"),
    ];
    let huffman_block = QpackEncoder::new().encode_field_section(&fields);
    assert_eq!(
        decoder.decode_header_block(4, &huffman_block).unwrap(),
        QpackDecode::Headers(
            fields
                .iter()
                .map(|field| (field.name.clone(), field.value.clone()))
                .collect()
        )
    );
}

#[test]
fn blocks_until_required_encoder_instructions_arrive() {
    let mut decoder = codec(220);
    let block = [0x03, 0x81, 0x10, 0x11];

    assert_eq!(
        decoder.decode_header_block(4, &block).unwrap(),
        QpackDecode::Blocked {
            required_insert_count: 2,
        }
    );

    decoder
        .apply_encoder_instructions(&appendix_b_encoder_stream())
        .unwrap();
    assert_eq!(decoder.insert_count(), 2);
    assert_eq!(
        decoder.decode_header_block(4, &block).unwrap(),
        QpackDecode::Headers(vec![
            (b":authority".to_vec(), b"www.example.com".to_vec()),
            (b":path".to_vec(), b"/sample/path".to_vec()),
        ])
    );
}

#[test]
fn applies_fragmented_rfc_encoder_instructions_exactly_once() {
    let mut decoder = codec(220);
    let mut encoder = appendix_b_encoder_stream();
    encoder.push(0x4a);
    encoder.extend_from_slice(b"custom-key");
    encoder.push(0x0c);
    encoder.extend_from_slice(b"custom-value");
    encoder.push(0x02);

    for byte in encoder {
        decoder.apply_encoder_instructions(&[byte]).unwrap();
        assert!(decoder.buffered_encoder_bytes() <= 220);
    }

    assert_eq!(decoder.insert_count(), 4);
    assert_eq!(
        decoder
            .decode_header_block(8, &[0x05, 0x00, 0x80, 0xc1, 0x81])
            .unwrap(),
        QpackDecode::Headers(vec![
            (b":authority".to_vec(), b"www.example.com".to_vec()),
            (b":path".to_vec(), b"/".to_vec()),
            (b"custom-key".to_vec(), b"custom-value".to_vec()),
        ])
    );
}

#[test]
fn supports_dynamic_name_reference_and_eviction() {
    let mut decoder = codec(220);
    let mut encoder = appendix_b_encoder_stream();
    encoder.push(0x4a);
    encoder.extend_from_slice(b"custom-key");
    encoder.push(0x0c);
    encoder.extend_from_slice(b"custom-value");
    encoder.push(0x02);
    decoder.apply_encoder_instructions(&encoder).unwrap();

    let mut next = vec![0x81, 0x0d];
    next.extend_from_slice(b"custom-value2");
    decoder.apply_encoder_instructions(&next).unwrap();

    assert_eq!(decoder.insert_count(), 5);
    assert_eq!(
        decoder
            .decode_header_block(12, &[0x06, 0x00, 0x80])
            .unwrap(),
        QpackDecode::Headers(vec![(b"custom-key".to_vec(), b"custom-value2".to_vec(),)])
    );
}

#[test]
fn rejects_invalid_required_insert_count() {
    let mut decoder = codec(64);
    assert_eq!(
        decoder.decode_header_block(0, &[0x06, 0x00]).unwrap_err(),
        QpackError::InvalidRequiredInsertCount { stream_id: 0 }
    );

    let mut large_limits = DecodeLimits::testing();
    large_limits.max_qpack_table_bytes = 8_192;
    let mut large_decoder = CompcolQpackCodec::new(8_192, &large_limits);
    let mut overflowing = vec![0xff];
    overflowing.extend(std::iter::repeat_n(
        0x80,
        usize::BITS.div_ceil(7) as usize - 1,
    ));
    overflowing.push(0x02);
    overflowing.push(0x00);
    assert_eq!(
        large_decoder
            .decode_header_block(1, &overflowing)
            .unwrap_err(),
        QpackError::InvalidRequiredInsertCount { stream_id: 1 }
    );
}

#[test]
fn bounds_partial_encoder_instructions_and_disables_the_direction() {
    let mut limits = DecodeLimits::testing();
    limits.max_qpack_table_bytes = 64;
    let mut decoder = CompcolQpackCodec::new(64, &limits);

    assert_eq!(
        decoder
            .apply_encoder_instructions(&[0x5f, 0x45])
            .unwrap_err(),
        QpackError::EncoderStreamLimitExceeded { limit: 64 }
    );
    assert!(decoder.is_disabled());
    assert_eq!(
        decoder.apply_encoder_instructions(&[0x20]).unwrap_err(),
        QpackError::Disabled
    );

    let mut complete = CompcolQpackCodec::new(64, &limits);
    let mut oversized_instruction = vec![0x5f, 0x45];
    oversized_instruction.extend(std::iter::repeat_n(b'x', 100));
    oversized_instruction.push(0x00);
    assert_eq!(
        complete
            .apply_encoder_instructions(&oversized_instruction)
            .unwrap_err(),
        QpackError::EncoderStreamLimitExceeded { limit: 64 }
    );
}

#[test]
fn malformed_encoder_stream_permanently_disables_only_this_codec() {
    let mut broken = codec(220);
    let mut healthy = codec(220);

    broken
        .apply_encoder_instructions(&[0x3f, 0xbd, 0x01])
        .unwrap();
    assert_eq!(
        broken.apply_encoder_instructions(&[0x00]).unwrap_err(),
        QpackError::MalformedEncoderStream
    );
    assert_eq!(
        broken.decode_header_block(0, &[0x00, 0x00]).unwrap_err(),
        QpackError::Disabled
    );

    assert_eq!(
        healthy.decode_header_block(0, &[0x00, 0x00, 0xc1]).unwrap(),
        QpackDecode::Headers(vec![(b":path".to_vec(), b"/".to_vec())])
    );
}

#[test]
fn bounds_encoded_and_decoded_header_sections() {
    let mut limits = DecodeLimits::testing();
    limits.max_header_section_bytes = 8;
    let mut decoder = CompcolQpackCodec::new(64, &limits);
    let oversized = vec![0; 9];

    assert_eq!(
        decoder.decode_header_block(7, &oversized).unwrap_err(),
        QpackError::HeaderSectionLimitExceeded {
            stream_id: 7,
            limit: 8,
        }
    );
    assert_eq!(
        decoder
            .decode_header_block(8, &[0x00, 0x00, 0xc1])
            .unwrap_err(),
        QpackError::HeaderSectionLimitExceeded {
            stream_id: 8,
            limit: 8,
        }
    );
}
