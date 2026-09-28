#[allow(dead_code)]
mod support;

use serde_json::Value;
use std::process::{Command, Output};
use support::capture::{legacy_pcap_packets, pcapng_with_packets, TempCapture};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pcap2har"))
}

fn run(args: &[&str]) -> Output {
    binary().args(args).output().expect("pcap2har runs")
}

fn tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    support::capture::ethernet(
        0x0800,
        &support::capture::ipv4_tcp(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            src_port,
            dst_port,
            1,
            false,
            payload,
        ),
    )
}

fn fcgi_record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let content_len = u16::try_from(content.len()).unwrap();
    let mut record = vec![
        1,
        record_type,
        0,
        1,
        (content_len >> 8) as u8,
        content_len as u8,
        0,
        0,
    ];
    record.extend_from_slice(content);
    record
}

fn fcgi_request(params: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&fcgi_record(1, &[0, 1, 0, 0, 0, 0, 0, 0]));
    let mut encoded_params = Vec::new();
    for (name, value) in params {
        encoded_params.push(u8::try_from(name.len()).unwrap());
        encoded_params.push(u8::try_from(value.len()).unwrap());
        encoded_params.extend_from_slice(name.as_bytes());
        encoded_params.extend_from_slice(value.as_bytes());
    }
    payload.extend_from_slice(&fcgi_record(4, &encoded_params));
    payload
}

#[test]
fn help_lists_capture_controls() {
    let output = run(&["--help"]);
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.contains("--keylog <FILE>"));
    assert!(stdout.contains("--strict"));
    assert!(stdout.contains("--max-memory-mib <MIB>"));
    assert!(stdout.contains("--max-body-mib <MIB>"));
    assert!(stdout.contains("per conversion stage"));
}

#[test]
fn clap_configuration_errors_exit_one_without_har() {
    for args in [&[][..], &["--unknown-option"][..]] {
        let output = run(args);

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn stdout_contains_only_har_and_stderr_contains_stable_stats() {
    let capture = TempCapture::new(legacy_pcap_packets(&[
        tcp_frame(
            50_000,
            8080,
            b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
        support::capture::ethernet(
            0x0800,
            &support::capture::ipv4_tcp(
                [192, 0, 2, 20],
                [192, 0, 2, 10],
                8080,
                50_000,
                1,
                false,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            ),
        ),
    ]));

    let output = run(&[capture.path().to_str().unwrap()]);
    let har: Value = serde_json::from_slice(&output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert_eq!(
        har["log"]["entries"][0]["request"]["url"],
        "http://example.test/health"
    );
    assert_eq!(
        stderr,
        "stats datagrams=2 tcp=2 udp=0 connections=1 exchanges=1 dropped=0\n"
    );
    assert!(!stderr.contains("\"log\""));
}

#[test]
fn strict_mode_writes_partial_har_before_exit_two() {
    let capture = TempCapture::new(pcapng_with_packets(
        &[147],
        false,
        &[(0, 1, vec![0xde, 0xad])],
    ));

    let output = run(&["--strict", capture.path().to_str().unwrap()]);
    let har: Value = serde_json::from_slice(&output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(har["log"]["entries"].as_array().unwrap().is_empty());
    assert!(stderr.contains("diagnostic severity=warning code=unsupported_link_type"));
    assert!(stderr.ends_with("stats datagrams=1 tcp=0 udp=0 connections=0 exchanges=0 dropped=1\n"));
}

#[test]
fn repeated_conversion_is_byte_for_byte_deterministic() {
    let response = |client_port| {
        support::capture::ethernet(
            0x0800,
            &support::capture::ipv4_tcp(
                [192, 0, 2, 20],
                [192, 0, 2, 10],
                8080,
                client_port,
                1,
                false,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ),
        )
    };
    let capture = TempCapture::new(pcapng_with_packets(
        &[147, 1],
        false,
        &[
            (0, 1, vec![0xde, 0xad]),
            (
                1,
                1,
                tcp_frame(
                    50_021,
                    8080,
                    b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n",
                ),
            ),
            (1, 1, response(50_021)),
            (
                1,
                1,
                tcp_frame(
                    50_022,
                    8080,
                    b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n",
                ),
            ),
            (1, 1, response(50_022)),
        ],
    ));
    let path = capture.path().to_str().unwrap();

    let first = run(&[path]);
    let second = run(&[path]);

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
    let har: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 2);
}

#[test]
fn fastcgi_headers_are_byte_for_byte_deterministic_across_processes() {
    let request = fcgi_request(&[
        ("REQUEST_METHOD", "GET"),
        ("REQUEST_URI", "/fcgi"),
        ("HTTP_HOST", "fcgi.example.test"),
        ("HTTP_X_ZULU", "z"),
        ("HTTP_ACCEPT", "text/plain"),
        ("HTTP_X_ALPHA", "a"),
        ("HTTP_USER_AGENT", "fixture"),
    ]);
    let response = fcgi_record(
        6,
        b"Status: 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK",
    );
    let capture = TempCapture::new(legacy_pcap_packets(&[
        tcp_frame(50_023, 9000, &request),
        support::capture::ethernet(
            0x0800,
            &support::capture::ipv4_tcp(
                [192, 0, 2, 20],
                [192, 0, 2, 10],
                9000,
                50_023,
                1,
                false,
                &response,
            ),
        ),
    ]));
    let path = capture.path().to_str().unwrap();

    let outputs: Vec<_> = (0..4).map(|_| run(&[path])).collect();

    assert!(outputs.iter().all(|output| output.status.success()));
    for output in &outputs[1..] {
        assert_eq!(output.stdout, outputs[0].stdout);
        assert_eq!(output.stderr, outputs[0].stderr);
    }
    let har: Value = serde_json::from_slice(&outputs[0].stdout).unwrap();
    let names: Vec<_> = har["log"]["entries"][0]["request"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|header| header["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Accept", "Host", "User-Agent", "X-Alpha", "X-Zulu"]);
}

#[test]
fn invalid_memory_values_are_configuration_exit_one() {
    for value in ["0", "340282366920938463463374607431768211455"] {
        let output = run(&["--max-memory-mib", value, "unused.pcap"]);
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(stderr.contains("invalid --max-memory-mib"));
    }
}

#[test]
fn invalid_body_limits_are_configuration_exit_one() {
    for value in ["0", "abc"] {
        let output = run(&["--max-body-mib", value, "unused.pcap"]);
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(stderr.contains("invalid --max-body-mib"));
    }
}

#[test]
fn bodies_above_default_limit_are_complete_with_larger_max_body_mib() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    // Typical Ethernet MSS, so the per-stream segment cap is exercised too.
    const SEGMENT: usize = 1_448;
    // Binary content mislabelled as text/html must survive byte-for-byte.
    let body: Vec<u8> = (0..(17usize << 20))
        .map(|i| (i % 251) as u8 | 0x80)
        .collect();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);

    let mut packets = vec![tcp_frame(
        50_030,
        80,
        b"GET /big HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )];
    for (index, chunk) in response.chunks(SEGMENT).enumerate() {
        packets.push(support::capture::ethernet(
            0x0800,
            &support::capture::ipv4_tcp(
                [192, 0, 2, 20],
                [192, 0, 2, 10],
                80,
                50_030,
                1 + u32::try_from(index * SEGMENT).unwrap(),
                false,
                chunk,
            ),
        ));
    }
    let capture = TempCapture::new(legacy_pcap_packets(&packets));
    let path = capture.path().to_str().unwrap();

    let decoded_body = |output: &Output| {
        assert!(output.status.success());
        let har: Value = serde_json::from_slice(&output.stdout).unwrap();
        let content = &har["log"]["entries"][0]["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        STANDARD.decode(content["text"].as_str().unwrap()).unwrap()
    };

    let default = decoded_body(&run(&[path]));
    assert!(default.len() < body.len());
    assert_eq!(default, body[..default.len()]);

    let raised = decoded_body(&run(&["--max-body-mib", "32", path]));
    assert_eq!(raised, body);
}

#[test]
fn truncated_final_packet_converts_earlier_exchanges_with_warning() {
    let mut bytes = legacy_pcap_packets(&[
        tcp_frame(
            50_040,
            8080,
            b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
        support::capture::ethernet(
            0x0800,
            &support::capture::ipv4_tcp(
                [192, 0, 2, 20],
                [192, 0, 2, 10],
                8080,
                50_040,
                1,
                false,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            ),
        ),
        tcp_frame(50_041, 8080, b"GET /cut HTTP/1.1\r\n"),
    ]);
    bytes.truncate(bytes.len() - 10);
    let capture = TempCapture::new(bytes);
    let path = capture.path().to_str().unwrap();

    let output = run(&[path]);
    let har: Value = serde_json::from_slice(&output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        har["log"]["entries"][0]["request"]["url"],
        "http://example.test/health"
    );
    assert!(stderr.contains("diagnostic severity=warning code=truncated_capture scope=capture"));
    assert!(stderr.ends_with("stats datagrams=2 tcp=2 udp=0 connections=1 exchanges=1 dropped=0\n"));

    let strict = run(&["--strict", path]);
    assert_eq!(strict.status.code(), Some(2));
    assert_eq!(strict.stdout, output.stdout);
}

#[test]
fn fatal_capture_error_is_exit_one_without_packet_content() {
    let marker = "secret-packet-marker";
    let output = run(&[marker]);
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("conversion failed"));
    assert!(!stderr.contains(marker));
}
