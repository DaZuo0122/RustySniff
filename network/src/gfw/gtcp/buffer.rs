use pcap::Capture;
use pcap::Offline;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use std::collections::HashMap;
use std::net::IpAddr;

/// Get fixed size of buffer for each tcp stream
pub fn get_buf(mut cap: Capture<Offline>, limit: usize) -> HashMap<(IpAddr, IpAddr), Vec<u8>> {
    let mut conn: HashMap<(IpAddr, IpAddr), Vec<u8>> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        if let Some(eth_frame) = EthernetPacket::new(packet.data) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth_frame.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let src_ip = IpAddr::V4(ipv4.get_source());
                            let dst_ip = IpAddr::V4(ipv4.get_destination());
                            let payload = tcp.payload();

                            let key = (src_ip, dst_ip);
                            let buf = conn.entry(key).or_insert_with(|| Vec::with_capacity(limit));

                            if buf.len() == limit {
                                continue;
                            }
                            let remaining = limit - buf.len();
                            let chunk = &payload[..payload.len().min(remaining)];
                            buf.extend_from_slice(chunk);
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth_frame.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                            let src_ip = IpAddr::V6(ipv6.get_source());
                            let dst_ip = IpAddr::V6(ipv6.get_destination());
                            let payload = tcp.payload();

                            let key = (src_ip, dst_ip);
                            let buf = conn.entry(key).or_insert_with(|| Vec::with_capacity(limit));

                            if buf.len() == limit {
                                continue;
                            }
                            let remaining = limit - buf.len();
                            let chunk = &payload[..payload.len().min(remaining)];
                            buf.extend_from_slice(chunk);
                        }
                    }
                }
                _ => (),
            }
        }
    }
    conn
}
