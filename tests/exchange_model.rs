use pcap2har::{
    normalized_exchanges_to_har, NormalizedExchange, NormalizedRequest, NormalizedResponse,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn request(scheme: &str, authority: &str, path: &str) -> NormalizedRequest {
    NormalizedRequest {
        method: "GET".to_string(),
        scheme: scheme.to_string(),
        authority: authority.to_string(),
        path: path.to_string(),
        version: "HTTP/3".to_string(),
        headers: Vec::new(),
        trailers: Vec::new(),
        body: Vec::new(),
        header_size: 0,
    }
}

fn exchange(
    client_port: u16,
    server: SocketAddr,
    path: &str,
    stream_id: u64,
) -> NormalizedExchange {
    NormalizedExchange {
        connection_sequence: 99,
        stream_id,
        client: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), client_port),
        server,
        request: request("https", "example.test", path),
        response: None,
        request_started_ns: 1_000_000,
        response_started_ns: None,
        ended_ns: 1_000_000,
    }
}

#[test]
fn explicit_scheme_wins_over_destination_port() {
    let mut value = exchange(
        50_000,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 80),
        "/secure",
        0,
    );
    value.request.scheme = "https".to_string();

    let har = normalized_exchanges_to_har(vec![value]);

    assert_eq!(
        har.log.entries[0].request.url,
        "https://example.test/secure"
    );
}

#[test]
fn exchange_order_is_stable_for_equal_timestamps() {
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443);
    let mut first = exchange(50_002, server, "/first", 0);
    first.connection_sequence = 1;
    let mut second = exchange(50_001, server, "/second", 0);
    second.connection_sequence = 2;

    let forward = normalized_exchanges_to_har(vec![second.clone(), first.clone()]);
    let reverse = normalized_exchanges_to_har(vec![first, second]);

    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&reverse).unwrap()
    );
    assert_eq!(
        forward.log.entries[0].request.url,
        "https://example.test/first"
    );
}

#[test]
fn supplied_connection_sequence_distinguishes_reused_endpoint_tuple() {
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443);
    let mut earlier_connection = exchange(50_007, server, "/earlier-connection", 0);
    earlier_connection.connection_sequence = 3;
    let mut later_connection = exchange(50_007, server, "/later-connection", 0);
    later_connection.connection_sequence = 4;

    let har = normalized_exchanges_to_har(vec![later_connection, earlier_connection]);

    assert_eq!(
        har.log.entries[0].request.url,
        "https://example.test/earlier-connection"
    );
}

#[test]
fn migrated_paths_keep_one_supplied_connection_sequence() {
    let first_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443);
    let second_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443);
    let mut first = exchange(50_008, first_server, "/stream-4", 4);
    first.connection_sequence = 7;
    let mut second = exchange(50_009, second_server, "/stream-8", 8);
    second.connection_sequence = 7;

    let har = normalized_exchanges_to_har(vec![second, first]);

    assert_eq!(
        har.log.entries[0].request.url,
        "https://example.test/stream-4"
    );
    assert_eq!(
        har.log.entries[1].request.url,
        "https://example.test/stream-8"
    );
}

#[test]
fn explicit_authority_preserves_non_default_port_and_ipv6_brackets() {
    let server = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 8)),
        8443,
    );
    let mut value = exchange(50_003, server, "/v6", 0);
    value.request.authority = "[2001:db8::8]:8443".to_string();

    let har = normalized_exchanges_to_har(vec![value]);

    assert_eq!(
        har.log.entries[0].request.url,
        "https://[2001:db8::8]:8443/v6"
    );
}

#[test]
fn duplicate_headers_and_trailers_reach_har_in_wire_order() {
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443);
    let mut value = exchange(50_004, server, "/headers", 0);
    value.request.headers = vec![
        ("x-repeat".to_string(), "one".to_string()),
        ("x-repeat".to_string(), "two".to_string()),
    ];
    value.request.trailers = vec![("x-request-trailer".to_string(), "done".to_string())];
    value.response = Some(NormalizedResponse {
        status: 200,
        reason: "OK".to_string(),
        version: "HTTP/3".to_string(),
        headers: vec![
            ("set-cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
        ],
        trailers: vec![("x-response-trailer".to_string(), "done".to_string())],
        body: Vec::new(),
        header_size: 0,
    });

    let har = normalized_exchanges_to_har(vec![value]);
    let entry = &har.log.entries[0];

    assert_eq!(
        entry
            .request
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("x-repeat", "one"),
            ("x-repeat", "two"),
            ("x-request-trailer", "done"),
        ]
    );
    assert_eq!(
        entry
            .response
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
            ("x-response-trailer", "done"),
        ]
    );
}

#[test]
fn request_only_exchange_has_an_empty_har_response() {
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443);

    let har = normalized_exchanges_to_har(vec![exchange(50_005, server, "/partial", 0)]);

    assert_eq!(har.log.entries[0].response.status, 0);
    assert_eq!(har.log.entries[0].response.http_version, "HTTP/3");
    assert!(har.log.entries[0].response.headers.is_empty());
}

#[test]
fn equal_primary_sort_keys_have_a_deterministic_tie_breaker() {
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443);
    let a = exchange(50_006, server, "/a", 7);
    let b = exchange(50_006, server, "/b", 7);

    let har = normalized_exchanges_to_har(vec![b, a]);

    assert_eq!(har.log.entries[0].request.url, "https://example.test/a");
    assert_eq!(har.log.entries[1].request.url, "https://example.test/b");
}
