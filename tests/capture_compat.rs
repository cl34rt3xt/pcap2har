use pcap2har::{convert_pcap_to_har, tcp::TcpError, Har};

#[test]
fn legacy_converter_keeps_tcp_error_result_type() {
    let _converter: fn(&str) -> Result<Har, TcpError> = convert_pcap_to_har;
}
