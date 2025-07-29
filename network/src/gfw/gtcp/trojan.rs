//use crate::gfw::gtcp::buffer::get_buf;
use pcap::Capture;
use pcap::Offline;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use std::collections::HashMap;
use std::net::IpAddr;

/// The magic byte sequence that signals the start of upload.
/// CCS stands for "Change Cipher Spec"
const CCS: &[u8; 6] = &[20, 3, 3, 0, 1, 1];

pub struct TrojanAnalyzer {
    src_ip: IpAddr,
    dst_ip: IpAddr,

    uploading: bool,
    downloading: bool,
    up_count: usize,
    down_count: usize,

    is_trojan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

impl TrojanAnalyzer {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr) -> Self {
        TrojanAnalyzer {
            src_ip,
            dst_ip,
            uploading: false,
            downloading: false,
            up_count: 0,
            down_count: 0,
            is_trojan: false,
        }
    }

    pub fn on_upload_chunk(&mut self, buf: &[u8]) -> bool {
        if !self.uploading && buf.len() >= CCS.len() && buf[..CCS.len()] == *CCS {
            self.uploading = true;
            self.up_count = 0;
        }

        if self.uploading && !self.downloading {
            self.up_count += buf.len();
        }
        false
    }

    pub fn on_download_chunk(&mut self, buf: &[u8]) -> bool {
        if self.uploading && !self.downloading {
            self.downloading = true;
        }

        if self.downloading {
            self.down_count += buf.len();
        }

        if self.uploading && self.downloading {
            return match_trojan(self.up_count, self.down_count);
        }

        false
    }

    pub fn print(&self) {
        if self.is_trojan {
            println!("––– FET Detected –––");
            println!("Source IP       : {}", self.src_ip);
            println!("Destination IP  : {}", self.dst_ip);
            println!();
            println!("––––––––––––––––––––––––––––––––––––––");
        }
    }
}

pub fn match_trojan(up: usize, down: usize) -> bool {
    (650..=750).contains(&up) && ((170..=180).contains(&down) || (3000..=7500).contains(&down))
}

fn canonicalize_flow(
    ip1: &str,
    port1: u16,
    ip2: &str,
    port2: u16,
) -> (
    FlowKey,
    bool, /* true if this is the "forward" direction */
) {
    let fwd = if port1 < port2 || (port1 == port2 && ip1 < ip2) {
        (
            FlowKey {
                src_ip: ip1.into(),
                src_port: port1,
                dst_ip: ip2.into(),
                dst_port: port2,
            },
            true,
        )
    } else {
        (
            FlowKey {
                src_ip: ip2.into(),
                src_port: port2,
                dst_ip: ip1.into(),
                dst_port: port1,
            },
            false,
        )
    };
    fwd
}

pub fn f_analyze_trojan(mut cap: Capture<Offline>, f_print: bool) -> Option<Vec<TrojanAnalyzer>> {
    let mut detectors: HashMap<FlowKey, TrojanAnalyzer> = HashMap::new();
    let mut res = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        if let Some(eth_frame) = EthernetPacket::new(packet.data) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth_frame.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let src_ip = IpAddr::V4(ipv4.get_source());
                            let dst_ip = IpAddr::V4(ipv4.get_destination());
                            let src_port = tcp.get_source();
                            let dst_port = tcp.get_destination();
                            let payload = tcp.payload();

                            if payload.is_empty() {
                                continue;
                            }

                            let (key, is_fwd) = canonicalize_flow(
                                &src_ip.to_string(),
                                src_port,
                                &dst_ip.to_string(),
                                dst_port,
                            );
                            let det = detectors
                                .entry(key.clone())
                                .or_insert_with(|| TrojanAnalyzer::new(src_ip, dst_ip));

                            let trojan_seen = if is_fwd {
                                // forward direction we treat as "upload"
                                det.on_upload_chunk(payload)
                            } else {
                                // reverse direction as "download"
                                det.on_download_chunk(payload)
                            };

                            if trojan_seen {
                                det.is_trojan = true;
                            }
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth_frame.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                            let src_ip = IpAddr::V6(ipv6.get_source());
                            let dst_ip = IpAddr::V6(ipv6.get_destination());
                            let src_port = tcp.get_source();
                            let dst_port = tcp.get_destination();
                            let payload = tcp.payload();

                            if payload.is_empty() {
                                continue;
                            }

                            let (key, is_fwd) = canonicalize_flow(
                                &src_ip.to_string(),
                                src_port,
                                &dst_ip.to_string(),
                                dst_port,
                            );
                            let det = detectors
                                .entry(key.clone())
                                .or_insert_with(|| TrojanAnalyzer::new(src_ip, dst_ip));

                            let trojan_seen = if is_fwd {
                                // forward direction we treat as "upload"
                                det.on_upload_chunk(payload)
                            } else {
                                // reverse direction as "download"
                                det.on_download_chunk(payload)
                            };

                            if trojan_seen {
                                det.is_trojan = true;
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    for (key, trojan_analyzer) in detectors {
        let _ = key;
        res.push(trojan_analyzer);
    }

    if f_print {
        for trojan_result in res {
            trojan_result.print();
        }
        None
    } else {
        Some(res)
    }
}
