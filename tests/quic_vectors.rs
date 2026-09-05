use pcap2har::quic::{
    ApplicationKeySet, DefaultPacketCodec, EndpointRole, PacketCodec, PacketDecodeError,
    PacketType, ProtectedPacket, QuicCipherSuite, QuicCryptoProvider, QuicHeaderKey, QuicPacketKey,
    QuicVersion, QuicVersionProfile, RustCryptoProvider, V1, V2,
};
use rustls::quic::{HeaderProtectionKey, PacketKey};

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid test vector")
}

fn decode_fixture(value: &str) -> Vec<u8> {
    let compact: String = value
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    decode_hex(&compact)
}

#[test]
fn maps_v1_and_v2_long_header_types() {
    assert_eq!(V1.packet_type(0b00), Some(PacketType::Initial));
    assert_eq!(V1.packet_type(0b01), Some(PacketType::ZeroRtt));
    assert_eq!(V1.packet_type(0b10), Some(PacketType::Handshake));
    assert_eq!(V1.packet_type(0b11), Some(PacketType::Retry));
    assert_eq!(V2.packet_type(0b01), Some(PacketType::Initial));
    assert_eq!(V2.packet_type(0b10), Some(PacketType::ZeroRtt));
    assert_eq!(V2.packet_type(0b11), Some(PacketType::Handshake));
    assert_eq!(V2.packet_type(0b00), Some(PacketType::Retry));
}

#[test]
fn version_specific_labels_are_exact() {
    assert_eq!(V1.key_label, b"quic key");
    assert_eq!(V1.update_label, b"quic ku");
    assert_eq!(V2.key_label, b"quicv2 key");
    assert_eq!(V2.update_label, b"quicv2 ku");
    assert_eq!(QuicVersion::try_from(V1.wire).unwrap(), QuicVersion::V1);
    assert_eq!(QuicVersion::try_from(V2.wire).unwrap(), QuicVersion::V2);
}

#[test]
fn derives_rfc9001_client_initial_keys() {
    let keys = RustCryptoProvider
        .derive_initial_keys(&V1, &decode_hex("8394c8f03e515708"), EndpointRole::Client)
        .unwrap();
    assert_eq!(
        keys.packet_key_bytes(),
        decode_hex("1f369613dd76d5467730efcbe3b1a22d")
    );
    assert_eq!(keys.iv_bytes(), decode_hex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(
        keys.header_key_bytes(),
        decode_hex("9f50449e04a0e810283a1e9933adedd2")
    );
}

#[test]
fn derives_rfc9369_client_initial_keys() {
    let keys = RustCryptoProvider
        .derive_initial_keys(&V2, &decode_hex("8394c8f03e515708"), EndpointRole::Client)
        .unwrap();
    assert_eq!(
        keys.packet_key_bytes(),
        decode_hex("8b1a0bc121284290a29e0971b5cd045d")
    );
    assert_eq!(keys.iv_bytes(), decode_hex("91f73e2351d8fa91660e909f"));
    assert_eq!(
        keys.header_key_bytes(),
        decode_hex("45b95e15235d6f45a6b19cbcb0294ba9")
    );
}

#[test]
fn crypto_round_trips_all_supported_suites() {
    for suite in [
        QuicCipherSuite::Aes128GcmSha256,
        QuicCipherSuite::Aes256GcmSha384,
        QuicCipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let secret = vec![0x5a; suite.secret_len()];
        let keys = RustCryptoProvider
            .derive_traffic_keys(&V1, suite, &secret)
            .unwrap();
        let header = b"authenticated header";
        let plaintext = b"authenticated QUIC payload";
        let mut sealed = plaintext.to_vec();
        let tag = keys
            .packet_key()
            .encrypt_in_place(77, header, &mut sealed)
            .unwrap();
        sealed.extend_from_slice(tag.as_ref());
        let opened = keys
            .packet_key()
            .decrypt_in_place(77, header, &mut sealed)
            .unwrap();
        assert_eq!(opened, plaintext, "suite {suite:?}");
    }
}

#[test]
fn crypto_key_update_keeps_header_key_stable() {
    let secret = decode_hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let expected_next =
        decode_hex("c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88");
    let next = RustCryptoProvider
        .derive_next_secret(&V2, QuicCipherSuite::ChaCha20Poly1305Sha256, &secret)
        .unwrap();
    assert_eq!(&*next, &expected_next);

    let mut keys = ApplicationKeySet::new(
        &RustCryptoProvider,
        &V2,
        QuicCipherSuite::ChaCha20Poly1305Sha256,
        &secret,
    )
    .unwrap();
    let header_key = keys.header_key_bytes().to_vec();
    let packet_key = keys.current().packet_key_bytes().to_vec();
    keys.rotate(
        &RustCryptoProvider,
        &V2,
        QuicCipherSuite::ChaCha20Poly1305Sha256,
    )
    .unwrap();
    assert_eq!(keys.header_key_bytes(), header_key);
    assert_ne!(keys.current().packet_key_bytes(), packet_key);
    assert!(keys.previous().is_some());
}

#[test]
fn packet_codec_decodes_rfc9369_chacha_short_packet() {
    let secret = decode_hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let keys = RustCryptoProvider
        .derive_traffic_keys(&V2, QuicCipherSuite::ChaCha20Poly1305Sha256, &secret)
        .unwrap();
    let packet = decode_hex("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba");
    let decoded = DefaultPacketCodec
        .decode(
            ProtectedPacket {
                datagram: &packet,
                offset: 0,
                version: &V2,
                dcid_len: Some(0),
                largest_packet_number: Some(654_360_563),
            },
            keys.header_key(),
            keys.packet_key(),
        )
        .unwrap();
    assert_eq!(decoded.packet_type, PacketType::OneRtt);
    assert_eq!(decoded.packet_number, 654_360_564);
    assert_eq!(decoded.payload, [0x01]);
    assert_eq!(decoded.consumed, packet.len());
}

#[test]
fn retry_integrity_is_version_specific() {
    let original_dcid = decode_hex("8394c8f03e515708");
    let v1 = decode_hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    let v2 = decode_hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
    DefaultPacketCodec
        .verify_retry(&V1, &original_dcid, &v1)
        .unwrap();
    DefaultPacketCodec
        .verify_retry(&V2, &original_dcid, &v2)
        .unwrap();
    assert_eq!(
        DefaultPacketCodec.verify_retry(&V1, &original_dcid, &v2),
        Err(PacketDecodeError::InvalidRetry)
    );
}

#[test]
fn project_does_not_link_oxiquic_endpoint_modules() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("oxiquic-transport"),
        "oxiquic-transport compiles its endpoint on every platform"
    );

    let source = include_str!("../src/quic/packet.rs");
    for forbidden in [
        "oxiquic_transport::connection",
        "oxiquic_transport::endpoint",
        "oxiquic_transport::handle",
        "oxiquic_transport::h3_compat",
    ] {
        assert!(!source.contains(forbidden), "forbidden import: {forbidden}");
    }
}

fn assert_client_initial(version: &'static pcap2har::quic::QuicVersionProfile, fixture: &str) {
    let packet = decode_fixture(fixture);
    assert_eq!(packet.len(), 1200);
    let dcid = decode_hex("8394c8f03e515708");
    let keys = RustCryptoProvider
        .derive_initial_keys(version, &dcid, EndpointRole::Client)
        .unwrap();
    let decoded = DefaultPacketCodec
        .decode(
            ProtectedPacket {
                datagram: &packet,
                offset: 0,
                version,
                dcid_len: None,
                largest_packet_number: None,
            },
            keys.header_key(),
            keys.packet_key(),
        )
        .unwrap();
    let crypto = decode_fixture(include_str!("vectors/rfc9001/client-initial-crypto.hex"));
    assert_eq!(decoded.packet_type, PacketType::Initial);
    assert_eq!(decoded.packet_number, 2);
    assert_eq!(decoded.dcid, dcid);
    assert!(decoded.scid.is_empty());
    assert_eq!(decoded.consumed, 1200);
    assert_eq!(decoded.payload.len(), 1162);
    assert_eq!(&decoded.payload[..crypto.len()], crypto);
    assert!(decoded.payload[crypto.len()..]
        .iter()
        .all(|value| *value == 0));
}

#[test]
fn packet_codec_decodes_rfc9001_client_initial() {
    assert_client_initial(&V1, include_str!("vectors/rfc9001/client-initial.hex"));
}

#[test]
fn packet_codec_decodes_rfc9369_client_initial() {
    assert_client_initial(&V2, include_str!("vectors/rfc9369/client-initial.hex"));
}

#[test]
fn packet_codec_rejects_truncated_header_protection_sample() {
    let dcid = decode_hex("8394c8f03e515708");
    let keys = RustCryptoProvider
        .derive_initial_keys(&V1, &dcid, EndpointRole::Client)
        .unwrap();
    let truncated = decode_hex("c000000001088394c8f03e51570800000400000000");
    assert!(matches!(
        DefaultPacketCodec.decode(
            ProtectedPacket {
                datagram: &truncated,
                offset: 0,
                version: &V1,
                dcid_len: None,
                largest_packet_number: None,
            },
            keys.header_key(),
            keys.packet_key(),
        ),
        Err(PacketDecodeError::Truncated | PacketDecodeError::InvalidLength)
    ));
}

fn push_varint(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        _ => panic!("test value is too large"),
    }
}

fn protect_long(
    version: &'static QuicVersionProfile,
    packet_type: PacketType,
    packet_number: u64,
    payload: &[u8],
    header_key: &QuicHeaderKey,
    packet_key: &QuicPacketKey,
) -> Vec<u8> {
    let type_bits = (0..=3)
        .find(|bits| version.packet_type(*bits) == Some(packet_type))
        .expect("long packet type");
    let pn_len = 2usize;
    let mut packet = vec![0xc0 | (type_bits << 4) | (pn_len as u8 - 1)];
    packet.extend_from_slice(&version.wire.to_be_bytes());
    packet.push(4);
    packet.extend_from_slice(b"dcid");
    packet.push(4);
    packet.extend_from_slice(b"scid");
    if packet_type == PacketType::Initial {
        push_varint(&mut packet, 0);
    }
    push_varint(&mut packet, (pn_len + payload.len() + 16) as u64);
    let pn_offset = packet.len();
    packet.extend_from_slice(&(packet_number as u16).to_be_bytes());
    let header = packet.clone();
    let mut sealed = payload.to_vec();
    let tag = packet_key
        .encrypt_in_place(packet_number, &header, &mut sealed)
        .unwrap();
    packet.extend_from_slice(&sealed);
    packet.extend_from_slice(tag.as_ref());
    let sample = packet[pn_offset + 4..pn_offset + 20].to_vec();
    let (first, tail) = packet.split_first_mut().unwrap();
    header_key
        .encrypt_in_place(
            &sample,
            first,
            &mut tail[pn_offset - 1..pn_offset - 1 + pn_len],
        )
        .unwrap();
    packet
}

fn protect_short(
    packet_number: u64,
    key_phase: bool,
    payload: &[u8],
    header_key: &QuicHeaderKey,
    packet_key: &QuicPacketKey,
) -> Vec<u8> {
    let pn_len = 2usize;
    let mut packet = vec![0x40 | (u8::from(key_phase) * 0x04) | (pn_len as u8 - 1)];
    packet.extend_from_slice(b"dcid");
    let pn_offset = packet.len();
    packet.extend_from_slice(&(packet_number as u16).to_be_bytes());
    let header = packet.clone();
    let mut sealed = payload.to_vec();
    let tag = packet_key
        .encrypt_in_place(packet_number, &header, &mut sealed)
        .unwrap();
    packet.extend_from_slice(&sealed);
    packet.extend_from_slice(tag.as_ref());
    let sample = packet[pn_offset + 4..pn_offset + 20].to_vec();
    let (first, tail) = packet.split_first_mut().unwrap();
    header_key
        .encrypt_in_place(
            &sample,
            first,
            &mut tail[pn_offset - 1..pn_offset - 1 + pn_len],
        )
        .unwrap();
    packet
}

#[test]
fn packet_codec_decodes_long_header_cipher_and_version_matrix() {
    for version in [&V1, &V2] {
        for suite in [
            QuicCipherSuite::Aes128GcmSha256,
            QuicCipherSuite::Aes256GcmSha384,
            QuicCipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let secret = vec![0x42; suite.secret_len()];
            let keys = RustCryptoProvider
                .derive_traffic_keys(version, suite, &secret)
                .unwrap();
            for packet_type in [PacketType::ZeroRtt, PacketType::Handshake] {
                let packet = protect_long(
                    version,
                    packet_type,
                    0x1234,
                    &[0x01, 0x00],
                    keys.header_key(),
                    keys.packet_key(),
                );
                let decoded = DefaultPacketCodec
                    .decode(
                        ProtectedPacket {
                            datagram: &packet,
                            offset: 0,
                            version,
                            dcid_len: None,
                            largest_packet_number: None,
                        },
                        keys.header_key(),
                        keys.packet_key(),
                    )
                    .unwrap();
                assert_eq!(decoded.packet_type, packet_type);
                assert_eq!(decoded.packet_number, 0x1234);
                assert_eq!(decoded.payload, [0x01, 0x00]);
            }
        }
    }
}

#[test]
fn packet_codec_splits_coalesced_long_packets() {
    let secret = vec![0x24; QuicCipherSuite::Aes128GcmSha256.secret_len()];
    let keys = RustCryptoProvider
        .derive_traffic_keys(&V1, QuicCipherSuite::Aes128GcmSha256, &secret)
        .unwrap();
    let first = protect_long(
        &V1,
        PacketType::Handshake,
        4,
        &[0x01, 0x00],
        keys.header_key(),
        keys.packet_key(),
    );
    let second = protect_long(
        &V1,
        PacketType::Handshake,
        5,
        &[0x01, 0x00],
        keys.header_key(),
        keys.packet_key(),
    );
    let mut datagram = first.clone();
    datagram.extend_from_slice(&second);
    let decoded_first = DefaultPacketCodec
        .decode(
            ProtectedPacket {
                datagram: &datagram,
                offset: 0,
                version: &V1,
                dcid_len: None,
                largest_packet_number: Some(3),
            },
            keys.header_key(),
            keys.packet_key(),
        )
        .unwrap();
    let decoded_second = DefaultPacketCodec
        .decode(
            ProtectedPacket {
                datagram: &datagram,
                offset: decoded_first.consumed,
                version: &V1,
                dcid_len: None,
                largest_packet_number: Some(4),
            },
            keys.header_key(),
            keys.packet_key(),
        )
        .unwrap();
    assert_eq!(decoded_first.packet_number, 4);
    assert_eq!(decoded_first.consumed, first.len());
    assert_eq!(decoded_second.packet_number, 5);
    assert_eq!(decoded_second.consumed, second.len());
}

#[test]
fn packet_codec_key_update_uses_nonrotating_header_key() {
    let suite = QuicCipherSuite::ChaCha20Poly1305Sha256;
    let secret = decode_hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let keys = ApplicationKeySet::new(&RustCryptoProvider, &V2, suite, &secret).unwrap();
    let packet = protect_short(
        0x2345,
        true,
        &[0x01, 0x00],
        keys.header_key(),
        keys.next().packet_key(),
    );
    let decoded = DefaultPacketCodec
        .decode(
            ProtectedPacket {
                datagram: &packet,
                offset: 0,
                version: &V2,
                dcid_len: Some(4),
                largest_packet_number: Some(0x2344),
            },
            keys.header_key(),
            keys.next().packet_key(),
        )
        .unwrap();
    assert!(decoded.key_phase);
    assert_eq!(decoded.packet_number, 0x2345);

    let next_secret = RustCryptoProvider
        .derive_next_secret(&V2, suite, &secret)
        .unwrap();
    let incorrectly_rotated_header = RustCryptoProvider
        .derive_traffic_keys(&V2, suite, &next_secret)
        .unwrap();
    assert!(DefaultPacketCodec
        .decode(
            ProtectedPacket {
                datagram: &packet,
                offset: 0,
                version: &V2,
                dcid_len: Some(4),
                largest_packet_number: Some(0x2344),
            },
            incorrectly_rotated_header.header_key(),
            keys.next().packet_key(),
        )
        .is_err());
}

#[test]
fn packet_codec_never_returns_tampered_plaintext() {
    let secret = vec![0x81; QuicCipherSuite::Aes256GcmSha384.secret_len()];
    let keys = RustCryptoProvider
        .derive_traffic_keys(&V1, QuicCipherSuite::Aes256GcmSha384, &secret)
        .unwrap();
    let mut packet = protect_short(9, false, &[0x01; 32], keys.header_key(), keys.packet_key());
    *packet.last_mut().unwrap() ^= 1;
    assert_eq!(
        DefaultPacketCodec.decode(
            ProtectedPacket {
                datagram: &packet,
                offset: 0,
                version: &V1,
                dcid_len: Some(4),
                largest_packet_number: Some(8),
            },
            keys.header_key(),
            keys.packet_key(),
        ),
        Err(PacketDecodeError::AuthenticationFailed)
    );
}
