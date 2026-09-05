use pcap2har::{convert_capture, ConversionOptions};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".superpowers/artifacts/quic")
        .join(name)
}

#[test]
fn converts_real_chromium_http3_capture_to_har() {
    let capture = fixture("chromium-http3.pcapng");
    let keylog = fixture("chromium-http3.keys");
    if !capture.exists() || !keylog.exists() {
        return;
    }

    let report = convert_capture(
        &capture,
        ConversionOptions {
            keylog: Some(keylog),
            ..ConversionOptions::default()
        },
    )
    .unwrap();

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_eq!(report.stats.udp_packets_seen, 16);
    assert_eq!(report.stats.connections_seen, 1);
    assert_eq!(report.stats.exchanges_emitted, 1);
    let entry = &report.har.log.entries[0];
    assert_eq!(entry.request.method, "GET");
    assert_eq!(entry.request.url, "https://h3.test/fixture");
    assert_eq!(entry.request.http_version, "HTTP/3");
    assert_eq!(entry.response.status, 200);
    assert_eq!(entry.response.http_version, "HTTP/3");
    assert_eq!(
        entry.response.content.text.as_deref(),
        Some("{\"protocol\":\"http3\",\"source\":\"pcap2har-fixture\",\"ok\":true}")
    );
}
