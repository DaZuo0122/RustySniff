// dns.rs
use dns_parser::{Packet as DnsPacket, QueryType, RData, ResponseCode};
use pcap::{Capture, Offline};
use pnet::packet::Packet;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Debug)]
pub struct DnsRecord {
    pub timestamp: Duration,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub is_response: bool,
    pub query: Option<String>,
    pub query_type: Option<String>,
    pub answers: Vec<String>,
    pub rcode: Option<ResponseCode>, // Changed to ResponseCode
    pub answer_count: usize,
}

impl DnsRecord {
    pub fn print(&self) {
        println!("[Timestamp]: {:.6}s", self.timestamp.as_secs_f64());
        println!(
            "[Network] {}:{} -> {}:{} ({})",
            self.src, self.src_port, self.dst, self.dst_port, self.protocol
        );

        if let Some(query) = &self.query {
            println!(
                "[DNS] {}: {} ({})",
                if self.is_response {
                    "Response"
                } else {
                    "Query"
                },
                query,
                self.query_type.as_deref().unwrap_or("UNKNOWN")
            );
        }

        if !self.answers.is_empty() {
            println!("[Answers] ({}):", self.answer_count);
            for answer in &self.answers {
                println!("  - {}", answer);
            }
        }

        if let Some(code) = &self.rcode {
            let status = match code {
                ResponseCode::NoError => "NOERROR",
                ResponseCode::FormatError => "FORMERR",
                ResponseCode::ServerFailure => "SERVFAIL",
                ResponseCode::NameError => "NXDOMAIN",
                ResponseCode::NotImplemented => "NOTIMP",
                ResponseCode::Refused => "REFUSED",
                ResponseCode::Reserved(6) => "YXDOMAIN",
                ResponseCode::Reserved(7) => "YXRRSET",
                ResponseCode::Reserved(8) => "NXRRSET",
                ResponseCode::Reserved(9) => "NOTAUTH",
                ResponseCode::Reserved(10) => "NOTZONE",
                ResponseCode::Reserved(n) => return println!("[Status]: Reserved ({})", n),
            };
            println!("[Status]: {}", status);
        }
        println!("{}", "-".repeat(50));
    }
}

#[derive(Debug, Default)]
pub struct DnsFilter {
    pub domain: Option<String>,
    pub is_response: Option<bool>,
    pub rcode: Option<u8>, // Still u8 for filtering
    pub query_type: Option<String>,
    pub min_answers: Option<usize>,
    pub protocol: Option<String>,
}

impl DnsFilter {
    pub fn matches(&self, record: &DnsRecord) -> bool {
        // Domain filter (query or answers)
        if let Some(domain) = &self.domain {
            let domain = domain.to_lowercase();
            let query_match = record
                .query
                .as_ref()
                .map(|q| q.to_lowercase().contains(&domain))
                .unwrap_or(false);

            let answers_match = record
                .answers
                .iter()
                .any(|a| a.to_lowercase().contains(&domain));

            if !query_match && !answers_match {
                return false;
            }
        }

        // Response type filter
        if let Some(is_res) = self.is_response {
            if record.is_response != is_res {
                return false;
            }
        }

        // Response code filter - convert ResponseCode to u8 for comparison
        if let Some(code) = self.rcode {
            let record_code = match record.rcode {
                Some(ResponseCode::NoError) => 0,
                Some(ResponseCode::FormatError) => 1,
                Some(ResponseCode::ServerFailure) => 2,
                Some(ResponseCode::NameError) => 3,
                Some(ResponseCode::NotImplemented) => 4,
                Some(ResponseCode::Refused) => 5,
                Some(ResponseCode::Reserved(n)) => n,
                None => return false, // No code to compare
            };

            if record_code != code {
                return false;
            }
        }

        // Query type filter
        if let Some(qtype) = &self.query_type {
            if record.query_type.as_ref() != Some(qtype) {
                return false;
            }
        }

        // Minimum answers filter
        if let Some(min) = self.min_answers {
            if record.answer_count < min {
                return false;
            }
        }

        // Protocol filter
        if let Some(proto) = &self.protocol {
            if !record.protocol.eq_ignore_ascii_case(proto) {
                return false;
            }
        }

        true
    }
}

fn extract_dns_payload(transport_payload: &[u8], is_tcp: bool) -> Option<Vec<u8>> {
    if is_tcp {
        if transport_payload.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([transport_payload[0], transport_payload[1]]) as usize;
        if transport_payload.len() >= len + 2 {
            Some(transport_payload[2..2 + len].to_vec())
        } else {
            None
        }
    } else {
        Some(transport_payload.to_vec())
    }
}

fn type_to_string(typ: QueryType) -> String {
    match typ {
        QueryType::A => "A".to_string(),
        QueryType::NS => "NS".to_string(),
        QueryType::CNAME => "CNAME".to_string(),
        QueryType::SOA => "SOA".to_string(),
        QueryType::PTR => "PTR".to_string(),
        QueryType::MX => "MX".to_string(),
        QueryType::TXT => "TXT".to_string(),
        QueryType::AAAA => "AAAA".to_string(),
        QueryType::SRV => "SRV".to_string(),
        QueryType::AXFR => "AXFR".to_string(),
        QueryType::MAILB => "MAILB".to_string(),
        QueryType::MAILA => "MAILA".to_string(),
        QueryType::All => "ALL".to_string(),
        _ => format!("UNKNOWN({:?})", typ),
    }
}

fn parse_dns_packet(
    payload: &[u8],
) -> Option<(
    bool,
    Option<String>,
    Option<String>,
    Vec<String>,
    Option<ResponseCode>,
    usize,
)> {
    match DnsPacket::parse(payload) {
        Ok(packet) => {
            let is_response = !packet.header.query;
            let rcode = Some(packet.header.response_code);
            let answer_count = packet.answers.len();

            let (query, query_type) = match packet.questions.first() {
                Some(q) => (Some(q.qname.to_string()), Some(type_to_string(q.qtype))),
                None => (None, None),
            };

            let answers = packet
                .answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(addr) => {
                        let ip = Ipv4Addr::from(addr.0);
                        Some(format!("A: {}", ip))
                    }
                    RData::AAAA(addr) => {
                        let ip = Ipv6Addr::from(addr.0);
                        Some(format!("AAAA: {}", ip))
                    }
                    RData::CNAME(cname) => Some(format!("CNAME: {:?}", cname)),
                    RData::MX(mx) => Some(format!("MX: {} ({})", mx.exchange, mx.preference)),
                    RData::TXT(txt) => Some(format!(
                        "TXT: {}",
                        txt.iter()
                            .map(|s| String::from_utf8_lossy(s))
                            .collect::<Vec<_>>()
                            .join("|")
                    )),
                    RData::NS(ns) => Some(format!("NS: {:?}", ns)),
                    RData::PTR(ptr) => Some(format!("PTR: {:?}", ptr)),
                    RData::SOA(soa) => Some(format!("SOA: {} {}", soa.primary_ns, soa.mailbox)),
                    _ => None,
                })
                .collect();

            Some((is_response, query, query_type, answers, rcode, answer_count))
        }
        Err(_) => None,
    }
}

fn process_packet(packet: &pcap::Packet) -> Option<DnsRecord> {
    let eth = EthernetPacket::new(packet.data)?;

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                let src = IpAddr::V4(ipv4.get_source());
                let dst = IpAddr::V4(ipv4.get_destination());

                match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if udp.get_destination() != 53 && udp.get_source() != 53 {
                                return None;
                            }

                            let transport_payload = udp.payload();
                            let dns_payload = extract_dns_payload(transport_payload, false)?;
                            let (is_response, query, query_type, answers, rcode, answer_count) =
                                parse_dns_packet(&dns_payload)?;

                            return Some(DnsRecord {
                                timestamp: Duration::new(
                                    packet.header.ts.tv_sec as u64,
                                    packet.header.ts.tv_usec as u32 * 1000,
                                ),
                                src,
                                dst,
                                src_port: udp.get_source(),
                                dst_port: udp.get_destination(),
                                protocol: "UDP".to_string(),
                                is_response,
                                query,
                                query_type,
                                answers,
                                rcode,
                                answer_count,
                            });
                        }
                    }
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() != 53 && tcp.get_source() != 53 {
                                return None;
                            }

                            let transport_payload = tcp.payload();
                            let dns_payload = extract_dns_payload(transport_payload, true)?;
                            let (is_response, query, query_type, answers, rcode, answer_count) =
                                parse_dns_packet(&dns_payload)?;

                            return Some(DnsRecord {
                                timestamp: Duration::new(
                                    packet.header.ts.tv_sec as u64,
                                    packet.header.ts.tv_usec as u32 * 1000,
                                ),
                                src,
                                dst,
                                src_port: tcp.get_source(),
                                dst_port: tcp.get_destination(),
                                protocol: "TCP".to_string(),
                                is_response,
                                query,
                                query_type,
                                answers,
                                rcode,
                                answer_count,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                let src = IpAddr::V6(ipv6.get_source());
                let dst = IpAddr::V6(ipv6.get_destination());

                match ipv6.get_next_header() {
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                            if udp.get_destination() != 53 && udp.get_source() != 53 {
                                return None;
                            }

                            let transport_payload = udp.payload();
                            let dns_payload = extract_dns_payload(transport_payload, false)?;
                            let (is_response, query, query_type, answers, rcode, answer_count) =
                                parse_dns_packet(&dns_payload)?;

                            return Some(DnsRecord {
                                timestamp: Duration::new(
                                    packet.header.ts.tv_sec as u64,
                                    packet.header.ts.tv_usec as u32 * 1000,
                                ),
                                src,
                                dst,
                                src_port: udp.get_source(),
                                dst_port: udp.get_destination(),
                                protocol: "UDP".to_string(),
                                is_response,
                                query,
                                query_type,
                                answers,
                                rcode,
                                answer_count,
                            });
                        }
                    }
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                            if tcp.get_destination() != 53 && tcp.get_source() != 53 {
                                return None;
                            }

                            let transport_payload = tcp.payload();
                            let dns_payload = extract_dns_payload(transport_payload, true)?;
                            let (is_response, query, query_type, answers, rcode, answer_count) =
                                parse_dns_packet(&dns_payload)?;

                            return Some(DnsRecord {
                                timestamp: Duration::new(
                                    packet.header.ts.tv_sec as u64,
                                    packet.header.ts.tv_usec as u32 * 1000,
                                ),
                                src,
                                dst,
                                src_port: tcp.get_source(),
                                dst_port: tcp.get_destination(),
                                protocol: "TCP".to_string(),
                                is_response,
                                query,
                                query_type,
                                answers,
                                rcode,
                                answer_count,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    None
}

pub fn f_process_dns(
    file_path: &str,
    bpf_filter: Option<&str>,
    dns_filter: Option<DnsFilter>,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let mut cap = Capture::from_file(file_path)?;

    if let Some(filter) = bpf_filter {
        cap.filter(filter, true)?;
    }

    let mut records = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        if let Some(record) = process_packet(&packet) {
            if let Some(filter) = &dns_filter {
                if !filter.matches(&record) {
                    continue;
                }
            }
            records.push(record);
        }
    }

    Ok(records)
}
