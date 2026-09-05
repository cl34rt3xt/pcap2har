use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_CAPTURE_ID: AtomicU64 = AtomicU64::new(0);

pub struct TempCapture {
    directory: PathBuf,
    path: PathBuf,
}

pub fn ethernet_ipv4_udp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    ethernet(0x0800, &ipv4_udp(src, dst, src_port, dst_port, payload))
}

pub fn ipv4_udp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).expect("test UDP payload fits u16");
    let ip_len = u16::try_from(20 + usize::from(udp_len)).expect("test IPv4 packet fits u16");
    let mut packet = vec![
        0x45,
        0,
        (ip_len >> 8) as u8,
        ip_len as u8,
        0,
        0,
        0,
        0,
        64,
        17,
        0,
        0,
    ];
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub fn ipv4_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    fin: bool,
    payload: &[u8],
) -> Vec<u8> {
    let ip_len = u16::try_from(40 + payload.len()).expect("test IPv4 packet fits u16");
    let mut packet = vec![
        0x45,
        0,
        (ip_len >> 8) as u8,
        ip_len as u8,
        0,
        0,
        0,
        0,
        64,
        6,
        0,
        0,
    ];
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.push(0x50);
    packet.push(u8::from(fin));
    packet.extend_from_slice(&65_535u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub fn ipv6_udp(
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).expect("test UDP payload fits u16");
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[17, 64]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn ethernet_with_vlan_tags(tags: &[u16], ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&tags.first().copied().unwrap_or(ether_type).to_be_bytes());
    for (index, _) in tags.iter().enumerate() {
        frame.extend_from_slice(&0u16.to_be_bytes());
        let next = tags.get(index + 1).copied().unwrap_or(ether_type);
        frame.extend_from_slice(&next.to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

pub fn linux_sll(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 14];
    packet.extend_from_slice(&ether_type.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub fn linux_sll2(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend_from_slice(&ether_type.to_be_bytes());
    packet.extend_from_slice(&[0u8; 18]);
    packet.extend_from_slice(payload);
    packet
}

impl TempCapture {
    pub fn new(data: Vec<u8>) -> Self {
        let id = NEXT_CAPTURE_ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("pcap2har-capture-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("capture.pcapng");
        fs::write(&path, data).unwrap();
        Self { directory, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCapture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn push_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let padded = (body.len() + 3) & !3;
    let total = (12 + padded) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + padded - body.len(), 0);
    out.extend_from_slice(&total.to_le_bytes());
}

fn push_block_be(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let padded = (body.len() + 3) & !3;
    let total = (12 + padded) as u32;
    out.extend_from_slice(&block_type.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + padded - body.len(), 0);
    out.extend_from_slice(&total.to_be_bytes());
}

fn push_section(out: &mut Vec<u8>) {
    push_block(
        out,
        0x0a0d0d0a,
        &[
            0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
    );
}

fn push_idb(out: &mut Vec<u8>, link_type: u16) {
    push_idb_with_snaplen(out, link_type, 65_535);
}

fn push_idb_with_timestamp_resolution(out: &mut Vec<u8>, link_type: u16, resolution: u8) {
    let mut idb = Vec::new();
    idb.extend_from_slice(&link_type.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65_535u32.to_le_bytes());
    idb.extend_from_slice(&9u16.to_le_bytes());
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.push(resolution);
    idb.extend_from_slice(&[0; 3]);
    push_block(out, 1, &idb);
}

fn push_idb_with_snaplen(out: &mut Vec<u8>, link_type: u16, snaplen: u32) {
    let mut idb = Vec::new();
    idb.extend_from_slice(&link_type.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&snaplen.to_le_bytes());
    push_block(out, 1, &idb);
}

fn push_dsb(out: &mut Vec<u8>, keylog: &[u8]) {
    let mut dsb = Vec::new();
    dsb.extend_from_slice(&0x544c534bu32.to_le_bytes());
    dsb.extend_from_slice(&(keylog.len() as u32).to_le_bytes());
    dsb.extend_from_slice(keylog);
    push_block(out, 0x0000000a, &dsb);
}

fn push_epb(out: &mut Vec<u8>, interface_id: u32, timestamp: u32, packet: &[u8]) {
    push_epb_timestamp(out, interface_id, u64::from(timestamp), packet);
}

fn push_epb_timestamp(out: &mut Vec<u8>, interface_id: u32, timestamp: u64, packet: &[u8]) {
    let mut epb = Vec::new();
    epb.extend_from_slice(&interface_id.to_le_bytes());
    epb.extend_from_slice(&u32::try_from(timestamp >> 32).unwrap().to_le_bytes());
    epb.extend_from_slice(
        &u32::try_from(timestamp & u64::from(u32::MAX))
            .unwrap()
            .to_le_bytes(),
    );
    epb.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    epb.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    epb.extend_from_slice(packet);
    push_block(out, 6, &epb);
}

pub fn pcapng_with_late_dsb(packet: &[u8], keylog: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_section(&mut out);
    push_idb(&mut out, 1);
    push_epb(&mut out, 0, 1_000_000, packet);
    push_dsb(&mut out, keylog);
    out
}

pub fn pcapng_with_interfaces(count: usize) -> Vec<u8> {
    let mut out = Vec::new();
    push_section(&mut out);
    for _ in 0..count {
        push_idb(&mut out, 1);
    }
    out
}

pub fn pcapng_with_dsb_blocks(keylogs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    push_section(&mut out);
    push_idb(&mut out, 1);
    for keylog in keylogs {
        push_dsb(&mut out, keylog);
    }
    out
}

pub fn pcapng_with_simple_packet(snaplen: u32, origlen: u32, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_section(&mut out);
    push_idb_with_snaplen(&mut out, 1, snaplen);
    let mut spb = Vec::new();
    spb.extend_from_slice(&origlen.to_le_bytes());
    spb.extend_from_slice(packet);
    push_block(&mut out, 3, &spb);
    out
}

pub fn legacy_pcap(packet: &[u8]) -> Vec<u8> {
    legacy_pcap_packets(&[packet.to_vec()])
}

pub fn legacy_pcap_packets(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (index, packet) in packets.iter().enumerate() {
        let timestamp = 2u32
            .checked_add(u32::try_from(index).expect("test packet index fits u32"))
            .expect("test timestamp fits u32");
        out.extend_from_slice(&timestamp.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(packet);
    }
    out
}

pub fn pcapng_with_packets(
    link_types: &[u16],
    nanosecond_resolution: bool,
    packets: &[(u32, u64, Vec<u8>)],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_section(&mut out);
    for link_type in link_types {
        if nanosecond_resolution {
            push_idb_with_timestamp_resolution(&mut out, *link_type, 9);
        } else {
            push_idb(&mut out, *link_type);
        }
    }
    for (interface_id, timestamp, packet) in packets {
        push_epb_timestamp(&mut out, *interface_id, *timestamp, packet);
    }
    out
}

pub fn big_endian_pcapng(packet: &[u8]) -> Vec<u8> {
    big_endian_pcapng_with_offset(packet, None)
}

pub fn big_endian_pcapng_with_offset(packet: &[u8], offset_seconds: Option<i64>) -> Vec<u8> {
    let mut out = Vec::new();
    push_block_be(
        &mut out,
        0x0a0d0d0a,
        &[
            0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
    );
    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_be_bytes());
    idb.extend_from_slice(&0u16.to_be_bytes());
    idb.extend_from_slice(&65_535u32.to_be_bytes());
    if let Some(offset_seconds) = offset_seconds {
        idb.extend_from_slice(&14u16.to_be_bytes());
        idb.extend_from_slice(&8u16.to_be_bytes());
        idb.extend_from_slice(&offset_seconds.to_be_bytes());
        idb.extend_from_slice(&0u16.to_be_bytes());
        idb.extend_from_slice(&0u16.to_be_bytes());
    }
    push_block_be(&mut out, 1, &idb);
    let mut epb = Vec::new();
    epb.extend_from_slice(&0u32.to_be_bytes());
    epb.extend_from_slice(&0u32.to_be_bytes());
    epb.extend_from_slice(&1_000_000u32.to_be_bytes());
    epb.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    epb.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    epb.extend_from_slice(packet);
    push_block_be(&mut out, 6, &epb);
    out
}

pub fn pcapng_with_two_sections(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_section(&mut out);
    push_idb(&mut out, 1);
    push_epb(&mut out, 0, 1, first);
    push_section(&mut out);
    push_idb(&mut out, 101);
    push_epb(&mut out, 0, 2, second);
    out
}
