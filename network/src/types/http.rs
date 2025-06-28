use httparse;
use pcap::{Capture, Offline};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Default, Debug, Clone)]
pub struct HttpFilter {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub path_contains: Option<String>,
}

impl HttpFilter {
    pub fn matches(&self, message: &HttpMessage) -> bool {
        if let Some(filter_ip) = self.src_ip {
            if filter_ip != message.src_ip {
                return false;
            }
        }

        if let Some(filter_ip) = self.dst_ip {
            if filter_ip != message.dst_ip {
                return false;
            }
        }

        if let Some(filter_method) = &self.method {
            if let Some(ref method) = message.method {
                if method.to_uppercase() != filter_method.to_uppercase() {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(filter_code) = self.status_code {
            if message.status_code != Some(filter_code) {
                return false;
            }
        }

        if let Some(filter_path) = &self.path_contains {
            if let Some(ref path) = message.path {
                if !path.contains(filter_path) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

#[derive(Debug)]
pub struct HttpMessage {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub method: Option<String>,
    pub path: Option<String>,
    pub version: Option<u8>,
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl HttpMessage {
    pub fn print(&self) {
        if self.method.is_some() {
            println!("[HTTP Request] {} → {}", self.src_ip, self.dst_ip);
            println!(
                "{} {} {:?}",
                self.method.as_ref().unwrap(),
                self.path.as_ref().unwrap(),
                self.version.unwrap()
            );
        } else {
            println!("[HTTP Response] {} ← {}", self.dst_ip, self.src_ip);
            println!(
                "{:?} {} {}",
                self.version.unwrap(),
                self.status_code.unwrap(),
                self.reason.as_ref().unwrap_or(&"".to_string())
            );
        }

        for (name, value) in &self.headers {
            println!("{}: {}", name, value);
        }
        println!();
    }
}

pub struct TcpStream {
    next_seq: u32,
    buffer: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

impl TcpStream {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr) -> Self {
        TcpStream {
            next_seq: 0,
            buffer: Vec::new(),
            pending: BTreeMap::new(),
            src_ip,
            dst_ip,
        }
    }

    fn process_data(&mut self, seq: u32, data: &[u8]) {
        let data_len = data.len() as u32;
        if data_len == 0 {
            return;
        }

        if self.next_seq == 0 && self.buffer.is_empty() && self.pending.is_empty() {
            self.next_seq = seq;
        }

        let end_seq = seq + data_len;

        if end_seq <= self.next_seq {
            return;
        }

        if seq <= self.next_seq {
            let offset = (self.next_seq - seq) as usize;
            if offset < data.len() {
                let new_data = &data[offset..];
                self.buffer.extend_from_slice(new_data);
                self.next_seq = end_seq;
                self.process_pending();
            }
        } else {
            self.pending.insert(seq, data.to_vec());
        }
    }

    fn process_pending(&mut self) {
        while let Some(seq) = self.pending.keys().next().copied() {
            if seq > self.next_seq {
                break;
            }
            let data = self.pending.remove(&seq).unwrap();
            self.process_data(seq, &data);
        }
    }

    pub fn parse_http(&mut self) -> Option<HttpMessage> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut result = None;

        // Try parsing as request
        let mut req = httparse::Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(len)) = req.parse(&self.buffer) {
            if let (Some(method), Some(path), Some(version)) = (req.method, req.path, req.version) {
                let http_headers = req
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                result = Some(HttpMessage {
                    src_ip: self.src_ip,
                    dst_ip: self.dst_ip,
                    method: Some(method.to_string()),
                    path: Some(path.to_string()),
                    version: Some(version),
                    status_code: None,
                    reason: None,
                    headers: http_headers,
                });

                self.buffer.drain(0..len);
                return result;
            }
        }

        // Try parsing as response
        let mut res = httparse::Response::new(&mut headers);
        if let Ok(httparse::Status::Complete(len)) = res.parse(&self.buffer) {
            if let (Some(version), Some(code)) = (res.version, res.code) {
                let http_headers = res
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                result = Some(HttpMessage {
                    src_ip: self.src_ip,
                    dst_ip: self.dst_ip,
                    method: None,
                    path: None,
                    version: Some(version),
                    status_code: Some(code),
                    reason: res.reason.map(|s| s.to_string()),
                    headers: http_headers,
                });

                self.buffer.drain(0..len);
            }
        }

        result
    }
}

/// Parse given pcap file into http/1.x message with HttpFilter.
/// When f_print set to true, it will print all http message and return None,
/// otherwise, it will print nothing and reture a Vec<HttpMessage>
pub fn f_process_http_1_x(
    mut cap: Capture<Offline>,
    filter: HttpFilter,
    f_print: bool,
) -> Option<Vec<HttpMessage>> {
    let mut streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpStream> = HashMap::new();
    let mut messages = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        let eth = match EthernetPacket::new(data) {
            Some(e) => e,
            None => continue,
        };

        // Process IP and TCP in the same match block to maintain proper lifetimes
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip = match Ipv4Packet::new(eth.payload()) {
                    Some(i) => i,
                    None => continue,
                };
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }

                let tcp = match TcpPacket::new(ip.payload()) {
                    Some(t) => t,
                    None => continue,
                };

                let src_ip = IpAddr::V4(ip.get_source());
                let dst_ip = IpAddr::V4(ip.get_destination());
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let key = (src_ip, src_port, dst_ip, dst_port);
                let payload = tcp.payload();

                if payload.is_empty() {
                    continue;
                }

                let stream = streams
                    .entry(key)
                    .or_insert_with(|| TcpStream::new(src_ip, dst_ip));

                stream.process_data(tcp.get_sequence(), payload);

                if let Some(message) = stream.parse_http() {
                    if filter.matches(&message) {
                        if f_print {
                            message.print();
                        } else {
                            messages.push(message);
                        }
                    }
                }
            }
            EtherTypes::Ipv6 => {
                let ip = match Ipv6Packet::new(eth.payload()) {
                    Some(i) => i,
                    None => continue,
                };
                if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                    continue;
                }

                let tcp = match TcpPacket::new(ip.payload()) {
                    Some(t) => t,
                    None => continue,
                };

                let src_ip = IpAddr::V6(ip.get_source());
                let dst_ip = IpAddr::V6(ip.get_destination());
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let key = (src_ip, src_port, dst_ip, dst_port);
                let payload = tcp.payload();

                if payload.is_empty() {
                    continue;
                }

                let stream = streams
                    .entry(key)
                    .or_insert_with(|| TcpStream::new(src_ip, dst_ip));

                stream.process_data(tcp.get_sequence(), payload);

                if let Some(message) = stream.parse_http() {
                    if filter.matches(&message) {
                        if f_print {
                            message.print();
                        } else {
                            messages.push(message);
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    if f_print { None } else { Some(messages) }
}
