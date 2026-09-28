mod support;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use flate2::{write::GzEncoder, Compression};
use hpack::Encoder;
use pcap2har::{
    convert_capture, CaptureError, CaptureReader, CapturedPacket, ConversionError,
    ConversionOptions, DecodeLimits, DiagnosticCode, DiagnosticScope, LinkDecoder, LinkError,
    LinkType, Severity, TransportPacket,
};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use support::capture::{
    big_endian_pcapng, big_endian_pcapng_with_offset, ethernet, ethernet_ipv4_udp,
    ethernet_with_vlan_tags, ipv4_tcp, ipv4_udp, ipv6_udp, legacy_pcap, legacy_pcap_packets,
    linux_sll, linux_sll2, pcapng_with_dsb_blocks, pcapng_with_interfaces, pcapng_with_late_dsb,
    pcapng_with_packets, pcapng_with_simple_packet, pcapng_with_two_sections, TempCapture,
};

fn captured(link_type: LinkType, data: Vec<u8>) -> CapturedPacket {
    CapturedPacket {
        index: 7,
        interface_id: 0,
        timestamp_ns: 123_456_789,
        link_type,
        original_len: u32::try_from(data.len()).expect("test packet fits u32"),
        data,
    }
}

fn tcp_frame(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4_tcp(src, dst, src_port, dst_port, sequence, false, payload),
    )
}

fn http_exchange_frames(client_port: u16) -> Vec<Vec<u8>> {
    vec![
        tcp_frame(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            client_port,
            8080,
            1,
            b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
        tcp_frame(
            [192, 0, 2, 20],
            [192, 0, 2, 10],
            8080,
            client_port,
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        ),
    ]
}

fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len()).expect("test TLS record fits u16");
    let mut record = vec![content_type, 0x03, 0x03];
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn client_hello_record(random: &[u8; 32]) -> Vec<u8> {
    let mut hello = vec![0; 38];
    hello[0] = 1;
    hello[6..38].copy_from_slice(random);
    tls_record(22, &hello)
}

fn tls13_application_record(secret: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let (key, iv) = pcap2har::tls::derive_key_iv(secret, 16);
    let mut inner = plaintext.to_vec();
    inner.push(23);
    let length = u16::try_from(inner.len() + 16).expect("test TLS ciphertext fits u16");
    let aad = [23, 0x03, 0x03, (length >> 8) as u8, (length & 0xff) as u8];
    let encrypted = Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .unwrap();
    tls_record(23, &encrypted)
}

fn http2_headers(headers: &[(&[u8], &[u8])]) -> Vec<u8> {
    let payload = Encoder::new().encode(headers.iter().copied());
    let length = u32::try_from(payload.len()).expect("test HTTP/2 frame fits u32");
    let mut frame = vec![
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        1,
        4,
        0,
        0,
        0,
        1,
    ];
    frame.extend_from_slice(&payload);
    frame
}

#[test]
fn tcp_capture_parity() {
    let file = TempCapture::new(legacy_pcap_packets(&http_exchange_frames(50_000)));

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    assert_eq!(
        report.har.log.entries[0].request.url,
        "http://example.test/health"
    );
    assert_eq!(report.har.log.entries[0].response.status, 200);
    assert_eq!(report.stats.datagrams_seen, 2);
    assert_eq!(report.stats.tcp_packets_seen, 2);
    assert_eq!(report.stats.connections_seen, 1);
    assert_eq!(report.stats.exchanges_emitted, 1);
    assert!(report.diagnostics.is_empty());
}

#[test]
fn plaintext_http_on_port_443_is_not_misclassified_as_tls() {
    let frames = vec![
        tcp_frame(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            50_010,
            443,
            1,
            b"GET /plain HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
        ),
        tcp_frame(
            [192, 0, 2, 20],
            [192, 0, 2, 10],
            443,
            50_010,
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        ),
    ];
    let file = TempCapture::new(legacy_pcap_packets(&frames));

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    assert_eq!(
        report.har.log.entries[0].request.url,
        "http://example.test:443/plain"
    );
}

#[test]
fn tls_http1_on_non_default_port_preserves_direction_and_har() {
    let random = [0xab; 32];
    let client_secret = [0xcd; 32];
    let server_secret = [0xef; 32];
    let mut client_tls = client_hello_record(&random);
    client_tls.extend_from_slice(&tls13_application_record(
        &client_secret,
        b"GET /secure HTTP/1.1\r\nHost: example.test:8443\r\n\r\n",
    ));
    let server_tls = tls13_application_record(
        &server_secret,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK",
    );
    let capture = TempCapture::new(legacy_pcap_packets(&[
        tcp_frame(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            50_011,
            8443,
            1,
            &client_tls,
        ),
        tcp_frame(
            [192, 0, 2, 20],
            [192, 0, 2, 10],
            8443,
            50_011,
            1,
            &server_tls,
        ),
    ]));
    let keylog = TempCapture::new(
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
            hex::encode(random),
            hex::encode(client_secret),
            hex::encode(random),
            hex::encode(server_secret)
        )
        .into_bytes(),
    );
    let options = ConversionOptions {
        keylog: Some(keylog.path().to_path_buf()),
        ..ConversionOptions::default()
    };

    let report = convert_capture(capture.path(), options).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    let entry = &report.har.log.entries[0];
    assert_eq!(entry.request.url, "https://example.test:8443/secure");
    assert_eq!(entry.request.http_version, "HTTP/1.1");
    assert_eq!(entry.response.status, 200);
    assert_eq!(entry.response.content.text.as_deref(), Some("OK"));
}

#[test]
fn tls_http2_on_non_default_port_preserves_pseudo_headers_and_stream() {
    let random = [0x12; 32];
    let client_secret = [0x34; 32];
    let server_secret = [0x56; 32];
    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&http2_headers(&[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"h2.example.test:8443"),
        (b":path", b"/h2"),
    ]));
    let response = http2_headers(&[(b":status", b"200"), (b"content-type", b"text/plain")]);
    let mut client_tls = client_hello_record(&random);
    client_tls.extend_from_slice(&tls13_application_record(&client_secret, &request));
    let server_tls = tls13_application_record(&server_secret, &response);
    let capture = TempCapture::new(legacy_pcap_packets(&[
        tcp_frame(
            [198, 51, 100, 10],
            [198, 51, 100, 20],
            50_012,
            8443,
            1,
            &client_tls,
        ),
        tcp_frame(
            [198, 51, 100, 20],
            [198, 51, 100, 10],
            8443,
            50_012,
            1,
            &server_tls,
        ),
    ]));
    let keylog = TempCapture::new(
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
            hex::encode(random),
            hex::encode(client_secret),
            hex::encode(random),
            hex::encode(server_secret)
        )
        .into_bytes(),
    );
    let options = ConversionOptions {
        keylog: Some(keylog.path().to_path_buf()),
        ..ConversionOptions::default()
    };

    let report = convert_capture(capture.path(), options).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    let entry = &report.har.log.entries[0];
    assert_eq!(entry.request.url, "https://h2.example.test:8443/h2");
    assert_eq!(entry.request.http_version, "HTTP/2");
    assert_eq!(entry.response.status, 200);
    assert_eq!(entry.response.http_version, "HTTP/2");
}

#[test]
fn malformed_link_packet_does_not_abort_later_exchange() {
    let frames = http_exchange_frames(50_001);
    let bytes = pcapng_with_packets(
        &[147, 1],
        false,
        &[
            (0, 1, vec![0xde, 0xad]),
            (1, 2, frames[0].clone()),
            (1, 3, frames[1].clone()),
        ],
    );
    let file = TempCapture::new(bytes);

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    assert_eq!(report.stats.datagrams_seen, 3);
    assert_eq!(report.stats.packets_dropped, 1);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::UnsupportedLinkType
            && diagnostic.scope == DiagnosticScope::Datagram { index: 0 }
    }));
}

#[test]
fn timestamp_overflow_is_diagnosed_without_wall_clock_fallback() {
    let packet = tcp_frame(
        [198, 51, 100, 10],
        [198, 51, 100, 20],
        51_000,
        80,
        1,
        b"GET / HTTP/1.1\r\nHost: overflow.test\r\n\r\n",
    );
    let timestamp = u64::try_from(i64::MAX).unwrap() + 1;
    let file = TempCapture::new(pcapng_with_packets(&[1], true, &[(0, timestamp, packet)]));

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert_eq!(report.stats.tcp_packets_seen, 0);
    assert_eq!(report.stats.packets_dropped, 1);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::MalformedDatagram
            && diagnostic.scope == DiagnosticScope::Datagram { index: 0 }
    }));
}

#[test]
fn tcp_connection_limit_counts_bidirectional_flow_once() {
    let mut frames = http_exchange_frames(50_002);
    frames.push(tcp_frame(
        [192, 0, 2, 11],
        [192, 0, 2, 20],
        50_003,
        8080,
        1,
        b"GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ));
    let file = TempCapture::new(legacy_pcap_packets(&frames));
    let mut options = ConversionOptions::default();
    options.limits.max_connections = 1;

    let report = convert_capture(file.path(), options).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    assert_eq!(report.stats.connections_seen, 1);
    assert_eq!(report.stats.tcp_packets_seen, 2);
    assert_eq!(report.stats.packets_dropped, 1);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::ResourceLimit));
}

#[test]
fn tcp_payload_limits_are_enforced_before_buffer_growth() {
    let packet = tcp_frame(
        [203, 0, 113, 10],
        [203, 0, 113, 20],
        52_000,
        8080,
        1,
        &[b'x'; 700],
    );
    let file = TempCapture::new(legacy_pcap(&packet));
    let mut options = ConversionOptions::default();
    options.limits.capture_buffer_bytes = 1 << 10;
    options.limits.max_connection_bytes = 699;
    options.limits.max_total_buffered_bytes = 1 << 10;

    let report = convert_capture(file.path(), options).unwrap();

    assert_eq!(report.stats.tcp_packets_seen, 0);
    assert_eq!(report.stats.packets_dropped, 1);
    assert_eq!(report.stats.connections_seen, 0);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::ResourceLimit));
}

#[test]
fn gzip_body_expansion_is_bounded_and_reported() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&vec![b'x'; 32 << 10]).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    response.extend_from_slice(&compressed);
    let file = TempCapture::new(legacy_pcap_packets(&[
        tcp_frame(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            52_001,
            8080,
            1,
            b"GET /compressed HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
        tcp_frame([192, 0, 2, 20], [192, 0, 2, 10], 8080, 52_001, 1, &response),
    ]));
    let mut options = ConversionOptions::default();
    options.limits.max_body_bytes = 1 << 10;

    let report = convert_capture(file.path(), options).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    let response = &report.har.log.entries[0].response;
    // bodySize is what was transferred; content.size is what was decoded (up to the limit)
    assert_eq!(response.body_size, compressed.len() as i64);
    assert_eq!(response.content.size, 1 << 10);
    assert_eq!(response.content.text.as_ref().unwrap().len(), 1 << 10);
    assert!(response.content.truncated);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::ResourceLimit
            && diagnostic.scope == DiagnosticScope::Capture
    }));
}

#[test]
fn decoded_bodies_share_the_conversion_stage_budget() {
    let gzip = |byte| {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![byte; 3_000]).unwrap();
        encoder.finish().unwrap()
    };
    let response = |body: &[u8]| {
        let mut message = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        message.extend_from_slice(body);
        message
    };
    let first = gzip(b'a');
    let second = gzip(b'b');
    let third = gzip(b'c');
    let mut requests =
        b"GET /one HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n".to_vec();
    requests
        .extend_from_slice(b"GET /two HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n");
    requests.extend_from_slice(
        b"GET /three HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n",
    );
    let mut responses = response(&first);
    responses.extend_from_slice(&response(&second));
    responses.extend_from_slice(&response(&third));
    let file = TempCapture::new(legacy_pcap_packets(&[
        tcp_frame([192, 0, 2, 10], [192, 0, 2, 20], 52_002, 8080, 1, &requests),
        tcp_frame(
            [192, 0, 2, 20],
            [192, 0, 2, 10],
            8080,
            52_002,
            1,
            &responses,
        ),
    ]));
    let mut options = ConversionOptions::default();
    options.limits.capture_buffer_bytes = 1 << 10;
    options.limits.max_body_bytes = 4 << 10;
    options.limits.max_total_buffered_bytes = 8 << 10;

    let report = convert_capture(file.path(), options).unwrap();

    assert_eq!(report.har.log.entries.len(), 3);
    let content_sizes: Vec<_> = report
        .har
        .log
        .entries
        .iter()
        .map(|entry| entry.response.content.size)
        .collect();
    assert_eq!(content_sizes, [3_000, 2_192, 3_000]);
    let total_body_bytes: i64 = content_sizes.iter().sum();
    assert_eq!(total_body_bytes, 8 << 10);
    let truncated: Vec<_> = report
        .har
        .log
        .entries
        .iter()
        .map(|entry| entry.response.content.truncated)
        .collect();
    assert_eq!(truncated, [false, true, false]);
    let body_sizes: Vec<_> = report
        .har
        .log
        .entries
        .iter()
        .map(|entry| entry.response.body_size)
        .collect();
    assert_eq!(
        body_sizes,
        [first.len() as i64, second.len() as i64, third.len() as i64]
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::ResourceLimit));
}

#[test]
fn udp_capture_is_counted_without_application_selection() {
    let packet = ethernet_ipv4_udp(
        [203, 0, 113, 1],
        [203, 0, 113, 2],
        44_444,
        44_445,
        b"not-quic-yet",
    );
    let file = TempCapture::new(legacy_pcap(&packet));

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert_eq!(report.stats.datagrams_seen, 1);
    assert_eq!(report.stats.udp_packets_seen, 1);
    assert_eq!(report.stats.tcp_packets_seen, 0);
    assert_eq!(report.stats.packets_dropped, 0);
    assert!(report.har.log.entries.is_empty());
}

#[test]
fn capture_index_diagnostics_are_copied_to_report() {
    let file = TempCapture::new(pcapng_with_dsb_blocks(&[b"CLIENT_RANDOM zz zz\n".to_vec()]));

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::MalformedDatagram
            && diagnostic.scope == DiagnosticScope::Capture
    }));
}

#[test]
fn truncated_header_remains_a_conversion_error() {
    let mut bytes = legacy_pcap_packets(&http_exchange_frames(50_000));
    bytes.truncate(10);
    let file = TempCapture::new(bytes);

    assert!(matches!(
        convert_capture(file.path(), ConversionOptions::default()),
        Err(ConversionError::Capture(CaptureError::Truncated))
    ));
}

#[test]
fn truncated_final_block_keeps_earlier_exchanges() {
    let mut frames = http_exchange_frames(50_000);
    frames.push(http_exchange_frames(50_001).remove(0));
    let mut bytes = legacy_pcap_packets(&frames);
    // 16-byte legacy record header precedes each packet
    let complete_len = bytes.len() - 16 - frames[2].len();
    bytes.truncate(bytes.len() - 3);
    let file = TempCapture::new(bytes);

    let report = convert_capture(file.path(), ConversionOptions::default()).unwrap();

    assert_eq!(report.har.log.entries.len(), 1);
    assert_eq!(
        report.har.log.entries[0].request.url,
        "http://example.test/health"
    );
    assert_eq!(report.har.log.entries[0].response.status, 200);
    assert_eq!(report.stats.datagrams_seen, 2);
    let truncations: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::TruncatedCapture)
        .collect();
    assert_eq!(truncations.len(), 1);
    assert_eq!(truncations[0].severity, Severity::Warning);
    assert_eq!(truncations[0].scope, DiagnosticScope::Capture);
    assert!(truncations[0]
        .message
        .contains(&format!("at byte {complete_len};")));
}

#[test]
fn decodes_udp_without_port_heuristics() {
    let frame = ethernet_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 52_000, 4433, &[0xc0, 0, 0, 0]);
    let packet = captured(LinkType::Ethernet, frame);
    let TransportPacket::Udp(udp) = LinkDecoder::decode(&packet).unwrap() else {
        panic!("expected UDP");
    };
    assert_eq!(udp.src.port(), 52_000);
    assert_eq!(udp.dst.port(), 4433);
    assert_eq!(udp.payload, vec![0xc0, 0, 0, 0]);
    assert_eq!(udp.packet_index, 7);
    assert_eq!(udp.timestamp_ns, 123_456_789);
}

#[test]
fn rejects_truncated_sll2_without_panicking() {
    let packet = captured(LinkType::LinuxSll2, vec![0; 12]);
    assert!(matches!(
        LinkDecoder::decode(&packet),
        Err(LinkError::Truncated)
    ));
}

#[test]
fn decodes_all_supported_link_types() {
    let ip = ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 1111, 2222, b"links");
    let packets = [
        captured(LinkType::Ethernet, ethernet(0x0800, &ip)),
        captured(LinkType::LinuxSll, linux_sll(0x0800, &ip)),
        captured(LinkType::LinuxSll2, linux_sll2(0x0800, &ip)),
        captured(LinkType::RawIp, ip),
    ];

    for packet in packets {
        let TransportPacket::Udp(datagram) = LinkDecoder::decode(&packet).unwrap() else {
            panic!("expected UDP");
        };
        assert_eq!(datagram.payload, b"links");
    }
}

#[test]
fn decodes_vlan_link_types() {
    let ip = ipv4_udp([10, 1, 0, 1], [10, 1, 0, 2], 9000, 9001, b"qinq");
    for tags in [&[0x8100][..], &[0x88a8, 0x8100][..]] {
        let frame = ethernet_with_vlan_tags(tags, 0x0800, &ip);
        let TransportPacket::Udp(datagram) =
            LinkDecoder::decode(&captured(LinkType::Ethernet, frame)).unwrap()
        else {
            panic!("expected UDP");
        };
        assert_eq!(datagram.payload, b"qinq");
    }
}

#[test]
fn decodes_udp_over_raw_and_ethernet_ipv6() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 2);
    let ip = ipv6_udp(src.octets(), dst.octets(), 12_345, 4433, b"ipv6");
    for packet in [
        captured(LinkType::RawIp, ip.clone()),
        captured(LinkType::Ethernet, ethernet(0x86dd, &ip)),
    ] {
        let TransportPacket::Udp(datagram) = LinkDecoder::decode(&packet).unwrap() else {
            panic!("expected UDP");
        };
        assert_eq!(datagram.src.ip(), IpAddr::V6(src));
        assert_eq!(datagram.dst.ip(), IpAddr::V6(dst));
        assert_eq!(datagram.payload, b"ipv6");
    }
}

#[test]
fn decodes_tcp_sequence_fin_and_payload() {
    let packet = captured(
        LinkType::Ethernet,
        ethernet(
            0x0800,
            &ipv4_tcp(
                [198, 51, 100, 1],
                [198, 51, 100, 2],
                50_000,
                8080,
                0x0102_0304,
                true,
                b"GET /",
            ),
        ),
    );
    let TransportPacket::Tcp(tcp) = LinkDecoder::decode(&packet).unwrap() else {
        panic!("expected TCP");
    };
    assert_eq!(tcp.src.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
    assert_eq!(tcp.sequence, 0x0102_0304);
    assert!(tcp.fin);
    assert_eq!(tcp.payload, b"GET /");
}

#[test]
fn trims_udp_payload_to_declared_lengths() {
    let mut frame = ethernet_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"body");
    frame.extend_from_slice(&[0xaa; 18]);
    let TransportPacket::Udp(datagram) =
        LinkDecoder::decode(&captured(LinkType::Ethernet, frame)).unwrap()
    else {
        panic!("expected UDP");
    };
    assert_eq!(datagram.payload, b"body");
}

#[test]
fn rejects_unsupported_link_network_and_transport() {
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::Unsupported(147), vec![])),
        Err(LinkError::UnsupportedLink(147))
    );
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::Ethernet, ethernet(0x0806, &[0; 28]))),
        Err(LinkError::UnsupportedNetwork(0x0806))
    );
    let mut icmp = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, &[0; 8]);
    icmp[9] = 1;
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::RawIp, icmp)),
        Err(LinkError::UnsupportedTransport)
    );
}

#[test]
fn rejects_malformed_network_and_transport_headers() {
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::RawIp, vec![0x70])),
        Err(LinkError::Malformed)
    );

    let mut malformed_udp = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"");
    malformed_udp[24..26].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::RawIp, malformed_udp)),
        Err(LinkError::Malformed)
    );
}

#[test]
fn rejects_ipv4_and_ipv6_fragments() {
    let mut ipv4 = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"fragment");
    ipv4[6] = 0x20;
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::RawIp, ipv4)),
        Err(LinkError::UnsupportedFragment)
    );

    let src = Ipv6Addr::LOCALHOST.octets();
    let dst = Ipv6Addr::UNSPECIFIED.octets();
    let udp = ipv6_udp(src, dst, 1, 2, b"fragment");
    let udp_payload = &udp[40..];
    let payload_len = u16::try_from(8 + udp_payload.len()).unwrap();
    let mut ipv6 = vec![0x60, 0, 0, 0];
    ipv6.extend_from_slice(&payload_len.to_be_bytes());
    ipv6.extend_from_slice(&[44, 64]);
    ipv6.extend_from_slice(&src);
    ipv6.extend_from_slice(&dst);
    ipv6.extend_from_slice(&[17, 0, 0, 1, 0, 0, 0, 1]);
    ipv6.extend_from_slice(udp_payload);
    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::RawIp, ipv6)),
        Err(LinkError::UnsupportedFragment)
    );
}

#[test]
fn rejects_atomic_ipv6_fragment_header() {
    let src = Ipv6Addr::LOCALHOST.octets();
    let dst = Ipv6Addr::UNSPECIFIED.octets();
    let udp = ipv6_udp(src, dst, 1, 2, b"atomic");
    let udp_payload = &udp[40..];
    let payload_len = u16::try_from(8 + udp_payload.len()).unwrap();
    let mut ipv6 = vec![0x60, 0, 0, 0];
    ipv6.extend_from_slice(&payload_len.to_be_bytes());
    ipv6.extend_from_slice(&[44, 64]);
    ipv6.extend_from_slice(&src);
    ipv6.extend_from_slice(&dst);
    ipv6.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 1]);
    ipv6.extend_from_slice(udp_payload);

    assert_eq!(
        LinkDecoder::decode(&captured(LinkType::RawIp, ipv6)),
        Err(LinkError::UnsupportedFragment)
    );
}

#[test]
fn rejects_truncation_at_link_and_network_boundaries() {
    let mut truncated_udp = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"");
    truncated_udp.truncate(27);
    truncated_udp[2..4].copy_from_slice(&27u16.to_be_bytes());

    let mut truncated_tcp = ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 0, false, b"");
    truncated_tcp.truncate(39);
    truncated_tcp[2..4].copy_from_slice(&39u16.to_be_bytes());

    for packet in [
        captured(LinkType::Ethernet, vec![0; 13]),
        captured(LinkType::Ethernet, ethernet(0x8100, &[0; 3])),
        captured(LinkType::LinuxSll, vec![0; 15]),
        captured(LinkType::LinuxSll2, vec![0; 19]),
        captured(LinkType::RawIp, vec![]),
        captured(LinkType::RawIp, vec![0x45; 10]),
        captured(LinkType::RawIp, vec![0x60; 39]),
        captured(LinkType::RawIp, truncated_udp),
        captured(LinkType::RawIp, truncated_tcp),
    ] {
        assert_eq!(LinkDecoder::decode(&packet), Err(LinkError::Truncated));
    }
}

#[test]
fn indexes_dsb_that_appears_after_packets() {
    let random = "ab".repeat(32);
    let keylog = format!("CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "cd".repeat(32));
    let file = TempCapture::new(pcapng_with_late_dsb(&[0; 14], keylog.as_bytes()));

    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();

    assert_eq!(reader.index().packet_count, 1);
    assert!(reader.index().secrets.traffic(&[0xab; 32]).is_some());
}

#[test]
fn streams_legacy_pcap_packets_with_nanosecond_timestamps() {
    let file = TempCapture::new(legacy_pcap(&[1, 2, 3]));
    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].interface_id, 0);
    assert_eq!(packets[0].timestamp_ns, 2_000_003_000);
    assert_eq!(packets[0].link_type, LinkType::Ethernet);
    assert_eq!(packets[0].data, vec![1, 2, 3]);
}

#[test]
fn streams_big_endian_pcapng_packets() {
    let file = TempCapture::new(big_endian_pcapng(&[4, 5, 6]));
    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp_ns, 1_000_000_000);
    assert_eq!(packets[0].link_type, LinkType::Ethernet);
    assert_eq!(packets[0].data, vec![4, 5, 6]);
}

#[test]
fn decodes_big_endian_interface_timestamp_offset() {
    let file = TempCapture::new(big_endian_pcapng_with_offset(&[4, 5, 6], Some(1)));
    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(reader.index().interfaces[0].timestamp_offset_seconds, 1);
    assert_eq!(packets[0].timestamp_ns, 2_000_000_000);
}

#[test]
fn flattens_interface_ids_across_pcapng_sections() {
    let file = TempCapture::new(pcapng_with_two_sections(&[7], &[8]));
    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(reader.index().interfaces.len(), 2);
    assert_eq!(
        packets
            .iter()
            .map(|packet| packet.interface_id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(packets[0].link_type, LinkType::Ethernet);
    assert_eq!(packets[1].link_type, LinkType::RawIp);
}

#[test]
fn tolerates_truncated_final_capture_block() {
    let mut data = pcapng_with_packets(&[1], false, &[(0, 1, vec![9, 10]), (0, 2, vec![11, 12])]);
    data.truncate(data.len() - 3);
    let file = TempCapture::new(data);

    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();
    let mut packets = Vec::new();
    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet.data);
            Ok(())
        })
        .unwrap();

    assert_eq!(reader.index().packet_count, 1);
    assert_eq!(packets, vec![vec![9, 10]]);
    assert_eq!(
        reader
            .index()
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagnosticCode::TruncatedCapture)
            .count(),
        1
    );
}

#[test]
fn big_endian_pcapng_truncated_inside_only_block_is_empty_not_fatal() {
    let mut data = big_endian_pcapng(&[9, 10]);
    data.truncate(data.len() - 3);
    let file = TempCapture::new(data);

    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();

    assert_eq!(reader.index().packet_count, 0);
    assert!(reader
        .index()
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::TruncatedCapture));
}

#[test]
fn reports_truncated_for_pcap_magic_followed_by_eof() {
    let file = TempCapture::new(0xa1b2c3d4u32.to_le_bytes().to_vec());
    let limits = DecodeLimits {
        capture_buffer_bytes: 4,
        max_total_buffered_bytes: 512,
        ..DecodeLimits::default()
    };

    assert!(matches!(
        CaptureReader::open(file.path(), limits),
        Err(CaptureError::Truncated)
    ));
}

#[test]
fn refills_and_grows_for_packet_blocks_larger_than_initial_window() {
    let packet = vec![0x55; 200];
    let file = TempCapture::new(pcapng_with_late_dsb(&packet, b""));
    let limits = DecodeLimits {
        capture_buffer_bytes: 64,
        max_total_buffered_bytes: 512,
        ..DecodeLimits::default()
    };
    let reader = CaptureReader::open(file.path(), limits).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, packet);
}

#[test]
fn clamps_final_buffer_growth_to_non_power_of_two_limit() {
    let packet = vec![0x66; 240];
    let file = TempCapture::new(pcapng_with_late_dsb(&packet, b""));
    let limits = DecodeLimits {
        capture_buffer_bytes: 128,
        max_total_buffered_bytes: 300,
        ..DecodeLimits::default()
    };
    let reader = CaptureReader::open(file.path(), limits).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, packet);
}

#[test]
fn grows_initial_window_when_capture_header_does_not_fit() {
    let file = TempCapture::new(pcapng_with_late_dsb(&[0; 14], b""));
    let limits = DecodeLimits {
        capture_buffer_bytes: 16,
        max_total_buffered_bytes: 512,
        ..DecodeLimits::default()
    };

    let reader = CaptureReader::open(file.path(), limits).unwrap();

    assert_eq!(reader.index().packet_count, 1);
}

#[test]
fn rejects_capture_index_with_too_many_interfaces() {
    let file = TempCapture::new(pcapng_with_interfaces(8));
    let limits = DecodeLimits {
        capture_buffer_bytes: 64,
        max_total_buffered_bytes: 256,
        ..DecodeLimits::default()
    };

    assert!(matches!(
        CaptureReader::open(file.path(), limits),
        Err(CaptureError::BufferLimit)
    ));
}

#[test]
fn rejects_capture_index_with_too_many_distinct_secrets() {
    let keylogs = (0u8..8)
        .map(|value| {
            format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                format!("{value:02x}").repeat(32),
                "cd".repeat(32)
            )
            .into_bytes()
        })
        .collect::<Vec<_>>();
    let file = TempCapture::new(pcapng_with_dsb_blocks(&keylogs));
    let limits = DecodeLimits {
        capture_buffer_bytes: 192,
        max_total_buffered_bytes: 2_048,
        ..DecodeLimits::default()
    };

    assert!(matches!(
        CaptureReader::open(file.path(), limits),
        Err(CaptureError::BufferLimit)
    ));
}

#[test]
fn rejects_capture_index_with_too_many_keylog_diagnostics() {
    let keylogs = vec![b"CLIENT_RANDOM zz zz\n".to_vec(); 16];
    let file = TempCapture::new(pcapng_with_dsb_blocks(&keylogs));
    let limits = DecodeLimits {
        capture_buffer_bytes: 64,
        max_total_buffered_bytes: 2_048,
        ..DecodeLimits::default()
    };

    assert!(matches!(
        CaptureReader::open(file.path(), limits),
        Err(CaptureError::BufferLimit)
    ));
}

#[test]
fn simple_packet_uses_snaplen_instead_of_padding_as_captured_length() {
    let expected = vec![1, 2, 3, 4, 5];
    let file = TempCapture::new(pcapng_with_simple_packet(5, 10, &expected));
    let reader = CaptureReader::open(file.path(), DecodeLimits::default()).unwrap();
    let mut packets = Vec::new();

    reader
        .for_each_packet(&mut |packet| {
            packets.push(packet);
            Ok(())
        })
        .unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].original_len, 10);
    assert_eq!(packets[0].data, expected);
}
