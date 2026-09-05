use super::{CapturedPacket, LinkType};
use etherparse::{
    err::packet::SliceError, Ipv6ExtensionSlice, LenSource, NetSlice, SlicedPacket, TransportSlice,
};
use std::net::{IpAddr, SocketAddr};

const ETHERNET_HEADER_LEN: usize = 14;
const LINUX_SLL_HEADER_LEN: usize = 16;
const LINUX_SLL2_HEADER_LEN: usize = 20;
const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const VLAN_TYPES: [u16; 3] = [0x8100, 0x88a8, 0x9100];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramRecord {
    pub packet_index: u64,
    pub timestamp_ns: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTcpPacket {
    pub packet_index: u64,
    pub timestamp_ns: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub sequence: u32,
    pub fin: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportPacket {
    Tcp(NormalizedTcpPacket),
    Udp(DatagramRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("captured packet is truncated")]
    Truncated,
    #[error("captured packet has malformed headers")]
    Malformed,
    #[error("capture link type {0} is unsupported")]
    UnsupportedLink(u32),
    #[error("network protocol 0x{0:04x} is unsupported")]
    UnsupportedNetwork(u16),
    #[error("transport protocol is unsupported")]
    UnsupportedTransport,
    #[error("fragmented IP packets are unsupported")]
    UnsupportedFragment,
}

pub struct LinkDecoder;

impl LinkDecoder {
    pub fn decode(packet: &CapturedPacket) -> Result<TransportPacket, LinkError> {
        let ip_packet = ip_payload(packet)?;
        let sliced = SlicedPacket::from_ip(ip_packet).map_err(map_slice_error)?;
        if sliced.is_ip_payload_fragmented() {
            return Err(LinkError::UnsupportedFragment);
        }

        let (src_ip, dst_ip) = match sliced.net.as_ref() {
            Some(NetSlice::Ipv4(ipv4)) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
            ),
            Some(NetSlice::Ipv6(ipv6)) => {
                if ipv6
                    .extensions()
                    .clone()
                    .into_iter()
                    .any(|extension| matches!(extension, Ipv6ExtensionSlice::Fragment(_)))
                {
                    return Err(LinkError::UnsupportedFragment);
                }
                (
                    IpAddr::V6(ipv6.header().source_addr()),
                    IpAddr::V6(ipv6.header().destination_addr()),
                )
            }
            None => return Err(LinkError::Malformed),
        };

        match sliced.transport {
            Some(TransportSlice::Udp(udp)) => Ok(TransportPacket::Udp(DatagramRecord {
                packet_index: packet.index,
                timestamp_ns: packet.timestamp_ns,
                src: SocketAddr::new(src_ip, udp.source_port()),
                dst: SocketAddr::new(dst_ip, udp.destination_port()),
                payload: udp.payload().to_vec(),
            })),
            Some(TransportSlice::Tcp(tcp)) => Ok(TransportPacket::Tcp(NormalizedTcpPacket {
                packet_index: packet.index,
                timestamp_ns: packet.timestamp_ns,
                src: SocketAddr::new(src_ip, tcp.source_port()),
                dst: SocketAddr::new(dst_ip, tcp.destination_port()),
                sequence: tcp.sequence_number(),
                fin: tcp.fin(),
                payload: tcp.payload().to_vec(),
            })),
            _ => Err(LinkError::UnsupportedTransport),
        }
    }
}

fn ip_payload(packet: &CapturedPacket) -> Result<&[u8], LinkError> {
    match packet.link_type {
        LinkType::Ethernet => ethernet_payload(&packet.data),
        LinkType::LinuxSll => cooked_payload(&packet.data, LINUX_SLL_HEADER_LEN, 14),
        LinkType::LinuxSll2 => cooked_payload(&packet.data, LINUX_SLL2_HEADER_LEN, 0),
        LinkType::RawIp => validate_raw_ip(&packet.data),
        LinkType::Unsupported(value) => Err(LinkError::UnsupportedLink(value)),
    }
}

fn ethernet_payload(data: &[u8]) -> Result<&[u8], LinkError> {
    if data.len() < ETHERNET_HEADER_LEN {
        return Err(LinkError::Truncated);
    }
    let mut offset = ETHERNET_HEADER_LEN;
    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    while VLAN_TYPES.contains(&ether_type) {
        let tag_end = offset.checked_add(4).ok_or(LinkError::Truncated)?;
        let tag = data.get(offset..tag_end).ok_or(LinkError::Truncated)?;
        ether_type = u16::from_be_bytes([tag[2], tag[3]]);
        offset = tag_end;
    }
    validate_ether_type(data.get(offset..).ok_or(LinkError::Truncated)?, ether_type)
}

fn cooked_payload(
    data: &[u8],
    header_len: usize,
    protocol_offset: usize,
) -> Result<&[u8], LinkError> {
    if data.len() < header_len {
        return Err(LinkError::Truncated);
    }
    let protocol = u16::from_be_bytes([data[protocol_offset], data[protocol_offset + 1]]);
    validate_ether_type(&data[header_len..], protocol)
}

fn validate_ether_type(data: &[u8], ether_type: u16) -> Result<&[u8], LinkError> {
    match ether_type {
        ETHER_TYPE_IPV4 | ETHER_TYPE_IPV6 => Ok(data),
        value => Err(LinkError::UnsupportedNetwork(value)),
    }
}

fn validate_raw_ip(data: &[u8]) -> Result<&[u8], LinkError> {
    let first = *data.first().ok_or(LinkError::Truncated)?;
    match first >> 4 {
        4 | 6 => Ok(data),
        _ => Err(LinkError::Malformed),
    }
}

fn map_slice_error(error: SliceError) -> LinkError {
    match error {
        SliceError::Len(error) if error.len_source == LenSource::UdpHeaderLen => {
            LinkError::Malformed
        }
        SliceError::Len(_) => LinkError::Truncated,
        _ => LinkError::Malformed,
    }
}
