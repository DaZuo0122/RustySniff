use pcap::Capture;
use pcap::Offline;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::IpAddr;

type ConnectionKey = (String, u16, String, u16, u32);
type Quad = (String, u16, String, u16); // (src_ip, src_port, dst_ip, dst_port)

pub struct RttStats {
    pub count: usize,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub squared_sum: f64,
}

pub struct RttEstimator {
    pub pending: HashMap<ConnectionKey, f64>,
    pub stats: HashMap<String, RttStats>,
}

pub struct NetworkStats {
    pub rtt_stats: RttStats,
    pub retrans_count: u32,
    pub fast_retrans_count: u32,
    pub dup_ack_count: u32,
    pub lost_segment_count: u32,
    pub window_stats: WindowStats,
}

pub struct WindowStats {
    pub min: u16,
    pub max: u16,
    pub sum: u64,
    pub count: u32,
}

#[derive(Debug)]
pub struct TcpFlow {
    pub packets: Vec<TcpPacketInfo>,
    pub state: ConnectionState,
}

#[derive(Debug, Clone)]
pub struct TcpPacketInfo {
    pub timestamp: f64,
    pub direction: Direction,
    pub flags: String,
    pub seq: u32,
    pub ack: u32,
    pub payload_len: usize,
    pub window: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Init,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    Closing,
    Closed,
}

impl RttStats {
    pub fn new() -> Self {
        RttStats {
            count: 0,
            sum: 0.0,
            min: f64::MAX,
            max: f64::MIN,
            squared_sum: 0.0,
        }
    }

    pub fn add_sample(&mut self, rtt: f64) {
        self.count += 1;
        self.sum += rtt;
        self.min = self.min.min(rtt);
        self.max = self.max.max(rtt);
        self.squared_sum += rtt * rtt;
    }

    pub fn average(&self) -> f64 {
        if self.count > 0 {
            self.sum / self.count as f64
        } else {
            0.0
        }
    }

    pub fn std_dev(&self) -> f64 {
        if self.count > 1 {
            let mean = self.average();
            let variance = (self.squared_sum / self.count as f64) - (mean * mean);
            variance.sqrt()
        } else {
            0.0
        }
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        RttEstimator {
            pending: HashMap::new(),
            stats: HashMap::new(),
        }
    }

    pub fn process_ipv4(&mut self, payload: &[u8], ts: f64, network_stats: &mut NetworkStats) {
        if let Some(ipv4) = Ipv4Packet::new(payload) {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                // Record window size
                network_stats.record_window(tcp.get_window());

                let payload_len = tcp.payload().len();

                if payload_len > 0 {
                    let src_ip = ipv4.get_source().to_string();
                    let dst_ip = ipv4.get_destination().to_string();
                    let seq = tcp.get_sequence();
                    let ack_num = seq.wrapping_add(payload_len as u32);
                    let key = (
                        dst_ip.clone(),
                        tcp.get_destination(),
                        src_ip.clone(),
                        tcp.get_source(),
                        ack_num,
                    );
                    self.pending.insert(key, ts);
                }

                if parse_flags(tcp.get_flags()).contains("ACK") {
                    let src_ip = ipv4.get_source().to_string();
                    let dst_ip = ipv4.get_destination().to_string();
                    let ack_num = tcp.get_acknowledgement();
                    let key = (
                        src_ip.clone(),
                        tcp.get_source(),
                        dst_ip.clone(),
                        tcp.get_destination(),
                        ack_num,
                    );

                    if let Some(sent_ts) = self.pending.remove(&key) {
                        let rtt = ts - sent_ts;
                        let (pair, _) = normalize_connection(&dst_ip, &src_ip);
                        let entry = self.stats.entry(pair).or_insert(RttStats::new());
                        entry.add_sample(rtt);
                        network_stats.record_rtt(rtt);
                    }
                }
            }
        }
    }

    pub fn process_ipv6(&mut self, payload: &[u8], ts: f64, network_stats: &mut NetworkStats) {
        if let Some(ipv6) = Ipv6Packet::new(payload) {
            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                // Record window size
                network_stats.record_window(tcp.get_window());

                let payload_len = tcp.payload().len();

                if payload_len > 0 {
                    let src_ip = format!("[{}]", ipv6.get_source());
                    let dst_ip = format!("[{}]", ipv6.get_destination());
                    let seq = tcp.get_sequence();
                    let ack_num = seq.wrapping_add(payload_len as u32);
                    let key = (
                        dst_ip.clone(),
                        tcp.get_destination(),
                        src_ip.clone(),
                        tcp.get_source(),
                        ack_num,
                    );
                    self.pending.insert(key, ts);
                }

                if parse_flags(tcp.get_flags()).contains("ACK") {
                    let src_ip = format!("[{}]", ipv6.get_source());
                    let dst_ip = format!("[{}]", ipv6.get_destination());
                    let ack_num = tcp.get_acknowledgement();
                    let key = (
                        src_ip.clone(),
                        tcp.get_source(),
                        dst_ip.clone(),
                        tcp.get_destination(),
                        ack_num,
                    );

                    if let Some(sent_ts) = self.pending.remove(&key) {
                        let rtt = ts - sent_ts;
                        let (pair, _) = normalize_connection(&dst_ip, &src_ip);
                        let entry = self.stats.entry(pair).or_insert(RttStats::new());
                        entry.add_sample(rtt);
                        network_stats.record_rtt(rtt);
                    }
                }
            }
        }
    }

    pub fn print(&self) {
        let mut pairs: Vec<_> = self.stats.iter().collect();
        pairs.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        println!(
            "{:<35} {:>8} {:>10} {:>10} {:>10} {:>10}",
            "IP Pair", "Samples", "Avg (ms)", "Min (ms)", "Max (ms)", "StdDev"
        );

        for (addr, stat) in pairs {
            if stat.count > 0 {
                println!(
                    "{:<35} {:>8} {:>10.2} {:>10.2} {:>10.2} {:>10.2}",
                    addr,
                    stat.count,
                    stat.average() * 1000.0,
                    stat.min * 1000.0,
                    stat.max * 1000.0,
                    stat.std_dev() * 1000.0
                );
            }
        }
    }
}

impl NetworkStats {
    pub fn new() -> Self {
        NetworkStats {
            rtt_stats: RttStats::new(),
            retrans_count: 0,
            fast_retrans_count: 0,
            dup_ack_count: 0,
            lost_segment_count: 0,
            window_stats: WindowStats {
                min: u16::MAX,
                max: u16::MIN,
                sum: 0,
                count: 0,
            },
        }
    }

    pub fn avg_window(&self) -> f64 {
        if self.window_stats.count > 0 {
            self.window_stats.sum as f64 / self.window_stats.count as f64
        } else {
            0.0
        }
    }

    pub fn record_rtt(&mut self, rtt: f64) {
        self.rtt_stats.add_sample(rtt);
    }

    pub fn record_retrans(&mut self) {
        self.retrans_count += 1;
    }

    pub fn record_fast_retrans(&mut self) {
        self.fast_retrans_count += 1;
    }

    pub fn record_dup_ack(&mut self) {
        self.dup_ack_count += 1;
    }

    pub fn record_lost_segment(&mut self) {
        self.lost_segment_count += 1;
    }

    pub fn record_window(&mut self, window: u16) {
        self.window_stats.min = self.window_stats.min.min(window);
        self.window_stats.max = self.window_stats.max.max(window);
        self.window_stats.sum += window as u64;
        self.window_stats.count += 1;
    }

    pub fn print(&self) {
        println!("Network Statistics Overview:");
        println!("================================================");
        println!("{:<30} {:>10}", "Metric", "Value");
        println!("------------------------------------------------");
        println!(
            "{:<30} {:>10.3} ms",
            "Average RTT",
            self.rtt_stats.average() * 1000.0
        );
        println!("{:<30} {:>10}", "Retransmission Count", self.retrans_count);
        println!(
            "{:<30} {:>10}",
            "Fast Retransmission Count", self.fast_retrans_count
        );
        println!("{:<30} {:>10}", "Duplicate ACK Count", self.dup_ack_count);
        println!(
            "{:<30} {:>10}",
            "Lost Segment Count", self.lost_segment_count
        );
        println!("{:<30} {:>10}", "Min Window Size", self.window_stats.min);
        println!("{:<30} {:>10}", "Max Window Size", self.window_stats.max);
        if self.window_stats.count > 0 {
            println!(
                "{:<30} {:>10.1}",
                "Avg Window Size",
                self.window_stats.sum as f64 / self.window_stats.count as f64
            );
        }
        println!("================================================");
    }
}

/// Generate RTT estimator for tcp connections with given pcap file.
/// When f_print set to True, it'll print the all rtt stats and reture None,
/// otherwise it'll print nothing and reture a RttEstimator.
pub fn gen_rtt_estimator(
    mut cap: Capture<Offline>,
    f_print: bool,
) -> Result<Option<RttEstimator>, Box<dyn Error>> {
    let mut estimator = RttEstimator::new();
    let mut network_stats = NetworkStats::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;

        if let Some(eth) = EthernetPacket::new(packet.data) {
            match eth.get_ethertype() {
                EtherTypes::Ipv4 => estimator.process_ipv4(eth.payload(), ts, &mut network_stats),
                EtherTypes::Ipv6 => estimator.process_ipv6(eth.payload(), ts, &mut network_stats),
                _ => (),
            }
        }
    }

    if f_print {
        estimator.print();
        Ok(None)
    } else {
        Ok(Some(estimator))
    }
}

/// Estimate RTT for given address pair with RttEstimator, return error if given pair cannot found.
/// When f_print set to True, it'll print the rtt stats and reture None,
/// otherwise it'll print nothing and reture a Vec<f64>.
/// The Vec<f64> has 5 elements, "Samples", "Avg (ms)", "Min (ms)", "Max (ms)", "StdDev" (from index 0 to 4).
pub fn f_estimate_rtt(
    src: &str,
    dst: &str,
    estimator: &RttEstimator,
    f_print: bool,
) -> Result<Option<Vec<f64>>, Box<dyn Error>> {
    let (key, _) = normalize_connection(src, dst);

    if let Some(stat) = estimator.stats.get(&key) {
        if f_print {
            println!(
                "{:<35} {:>8} {:>10} {:>10} {:>10} {:>10}",
                "IP Pair", "Samples", "Avg (ms)", "Min (ms)", "Max (ms)", "StdDev"
            );
            println!(
                "{:<35} {:>8} {:>10.2} {:>10.2} {:>10.2} {:>10.2}",
                key,
                stat.count,
                stat.average() * 1000.0,
                stat.min * 1000.0,
                stat.max * 1000.0,
                stat.std_dev() * 1000.0
            );
            Ok(None)
        } else {
            let res = vec![
                stat.count as f64,
                stat.average() * 1000.0,
                stat.min * 1000.0,
                stat.max * 1000.0,
                stat.std_dev() * 1000.0,
            ];
            Ok(Some(res))
        }
    } else {
        Err("Address pair not found".into())
    }
}

/// Trace a tcp connection with given pcap file.
/// When f_print set to True, it'll print the connection and reture None,
/// otherwise it'll print nothing and reture a HashMap.
pub fn f_trace_tcp_conn(
    mut cap: Capture<Offline>,
    f_print: bool,
) -> Option<HashMap<String, TcpFlow>> {
    let mut connections = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let header = packet.header;
        let timestamp = header.ts.tv_sec as f64 + header.ts.tv_usec as f64 / 1_000_000.0;

        if let Some(eth_frame) = EthernetPacket::new(packet.data) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 => process_ipv4(eth_frame.payload(), timestamp, &mut connections),
                EtherTypes::Ipv6 => process_ipv6(eth_frame.payload(), timestamp, &mut connections),
                _ => (),
            }
        }
    }

    if f_print {
        for (key, flow) in &connections {
            print_connection(key, flow);
        }
        None
    } else {
        Some(connections)
    }
}

fn process_ipv4(payload: &[u8], timestamp: f64, connections: &mut HashMap<String, TcpFlow>) {
    if let Some(ipv4) = Ipv4Packet::new(payload) {
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            let src = format!("{}:{}", ipv4.get_source(), tcp.get_source());
            let dst = format!("{}:{}", ipv4.get_destination(), tcp.get_destination());
            process_tcp_packet(&src, &dst, timestamp, tcp, connections);
        }
    }
}

fn process_ipv6(payload: &[u8], timestamp: f64, connections: &mut HashMap<String, TcpFlow>) {
    if let Some(ipv6) = Ipv6Packet::new(payload) {
        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
            let src = format!("[{}]:{}", ipv6.get_source(), tcp.get_source());
            let dst = format!("[{}]:{}", ipv6.get_destination(), tcp.get_destination());
            process_tcp_packet(&src, &dst, timestamp, tcp, connections);
        }
    }
}

fn process_tcp_packet(
    src: &str,
    dst: &str,
    timestamp: f64,
    tcp: TcpPacket,
    connections: &mut HashMap<String, TcpFlow>,
) {
    let flags = parse_flags(tcp.get_flags());
    let (conn_key, direction) = normalize_connection(src, dst);

    let packet_info = TcpPacketInfo {
        timestamp,
        direction,
        flags,
        seq: tcp.get_sequence(),
        ack: tcp.get_acknowledgement(),
        payload_len: tcp.payload().len(),
        window: tcp.get_window(),
    };

    let flow = connections
        .entry(conn_key.clone())
        .or_insert_with(|| TcpFlow {
            packets: Vec::new(),
            state: ConnectionState::Init,
        });

    flow.packets.push(packet_info);
    update_connection_state(flow);
}

fn parse_flags(flags: u8) -> String {
    let mut f = Vec::new();
    if flags & 0x01 != 0 {
        f.push("FIN");
    }
    if flags & 0x02 != 0 {
        f.push("SYN");
    }
    if flags & 0x04 != 0 {
        f.push("RST");
    }
    if flags & 0x08 != 0 {
        f.push("PSH");
    }
    if flags & 0x10 != 0 {
        f.push("ACK");
    }
    if flags & 0x20 != 0 {
        f.push("URG");
    }
    if flags & 0x40 != 0 {
        f.push("ECE");
    }
    if flags & 0x80 != 0 {
        f.push("CWR");
    }
    f.join("|")
}

fn normalize_connection(a: &str, b: &str) -> (String, Direction) {
    if a <= b {
        (format!("{} <-> {}", a, b), Direction::ClientToServer)
    } else {
        (format!("{} <-> {}", b, a), Direction::ServerToClient)
    }
}

fn update_connection_state(flow: &mut TcpFlow) {
    let last_packet = flow.packets.last().unwrap();

    flow.state = match (
        &flow.state,
        last_packet.flags.as_str(),
        last_packet.direction.clone(),
    ) {
        (ConnectionState::Init, "SYN", Direction::ClientToServer) => ConnectionState::SynSent,
        (ConnectionState::SynSent, "SYN|ACK", Direction::ServerToClient) => {
            ConnectionState::SynReceived
        }
        (ConnectionState::SynReceived, "ACK", Direction::ClientToServer) => {
            ConnectionState::Established
        }
        (ConnectionState::Established, "FIN", _) => ConnectionState::FinWait1,
        (ConnectionState::FinWait1, "FIN|ACK", Direction::ServerToClient) => {
            ConnectionState::Closing
        }
        (ConnectionState::Closing, "ACK", Direction::ClientToServer) => ConnectionState::Closed,
        _ => flow.state.clone(),
    };
}

pub fn print_connection(conn_key: &str, flow: &TcpFlow) {
    println!("\nTCP Connection: {}", conn_key);
    println!("State: {:?}", flow.state);
    println!(
        "{:<6} {:<12} {:<8} {:<10} {:<10} {:<10} {:<6}",
        "No.", "Time", "Dir", "Flags", "Seq", "Ack", "Win"
    );

    for (i, pkt) in flow.packets.iter().enumerate() {
        let dir = match pkt.direction {
            Direction::ClientToServer => "-->",
            Direction::ServerToClient => "<--",
        };
        println!(
            "{:4} {:8.3} {:4} {:10} {:10} {:10} {:5} ({})",
            i + 1,
            pkt.timestamp,
            dir,
            pkt.flags,
            pkt.seq,
            pkt.ack,
            pkt.window,
            pkt.payload_len
        );
    }
}

/// Analyze network traffic and provide comprehensive statistics
pub fn f_analyze_tcp_network(mut cap: Capture<Offline>) -> Result<NetworkStats, Box<dyn Error>> {
    let mut estimator = RttEstimator::new();
    let mut network_stats = NetworkStats::new();
    let mut seq_tracker: HashMap<Quad, HashSet<u32>> = HashMap::new();
    let mut ack_tracker: HashMap<Quad, u32> = HashMap::new();
    let mut dup_ack_counts: HashMap<Quad, u32> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;

        if let Some(eth) = EthernetPacket::new(packet.data) {
            match eth.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let src_ip = ipv4.get_source().to_string();
                            let dst_ip = ipv4.get_destination().to_string();
                            let quad = (
                                src_ip.clone(),
                                tcp.get_source(),
                                dst_ip.clone(),
                                tcp.get_destination(),
                            );

                            // Detect retransmissions
                            let seq = tcp.get_sequence();
                            let quad_key = quad.clone();
                            let seen_set = seq_tracker
                                .entry(quad_key.clone())
                                .or_insert(HashSet::new());

                            if seen_set.contains(&seq) {
                                network_stats.record_retrans();

                                // Detect fast retransmissions (triggered by 3 duplicate ACKs)
                                let rev_quad = (quad.2.clone(), quad.3, quad.0.clone(), quad.1);

                                if let Some(count) = dup_ack_counts.get(&rev_quad) {
                                    if *count >= 3 {
                                        network_stats.record_fast_retrans();
                                    }
                                }
                            } else {
                                seen_set.insert(seq);
                            }

                            // Detect duplicate ACKs
                            if tcp.get_flags() & 0x10 != 0 {
                                // ACK flag set
                                let ack_num = tcp.get_acknowledgement();
                                let rev_quad = (quad.2.clone(), quad.3, quad.0.clone(), quad.1);

                                if let Some(last_ack) = ack_tracker.get(&rev_quad) {
                                    if *last_ack == ack_num {
                                        network_stats.record_dup_ack();

                                        // Track consecutive duplicate ACKs
                                        let count =
                                            dup_ack_counts.entry(rev_quad.clone()).or_insert(0);
                                        *count += 1;
                                    } else {
                                        // Reset duplicate counter when new ACK arrives
                                        dup_ack_counts.insert(rev_quad.clone(), 0);
                                    }
                                }
                                ack_tracker.insert(rev_quad, ack_num);
                            }

                            // Detect lost segments (using RST as heuristic)
                            if tcp.get_flags() & 0x04 != 0 {
                                // RST flag
                                network_stats.record_lost_segment();
                            }
                        }
                    }
                    estimator.process_ipv4(eth.payload(), ts, &mut network_stats);
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                            let src_ip = format!("[{}]", ipv6.get_source());
                            let dst_ip = format!("[{}]", ipv6.get_destination());
                            let quad = (
                                src_ip.clone(),
                                tcp.get_source(),
                                dst_ip.clone(),
                                tcp.get_destination(),
                            );

                            // Detect retransmissions
                            let seq = tcp.get_sequence();
                            let quad_key = quad.clone();
                            let seen_set = seq_tracker
                                .entry(quad_key.clone())
                                .or_insert(HashSet::new());

                            if seen_set.contains(&seq) {
                                network_stats.record_retrans();

                                // Detect fast retransmissions
                                let rev_quad = (quad.2.clone(), quad.3, quad.0.clone(), quad.1);

                                if let Some(count) = dup_ack_counts.get(&rev_quad) {
                                    if *count >= 3 {
                                        network_stats.record_fast_retrans();
                                    }
                                }
                            } else {
                                seen_set.insert(seq);
                            }

                            // Detect duplicate ACKs
                            if tcp.get_flags() & 0x10 != 0 {
                                // ACK flag set
                                let ack_num = tcp.get_acknowledgement();
                                let rev_quad = (quad.2.clone(), quad.3, quad.0.clone(), quad.1);

                                if let Some(last_ack) = ack_tracker.get(&rev_quad) {
                                    if *last_ack == ack_num {
                                        network_stats.record_dup_ack();

                                        // Track consecutive duplicate ACKs
                                        let count =
                                            dup_ack_counts.entry(rev_quad.clone()).or_insert(0);
                                        *count += 1;
                                    } else {
                                        // Reset duplicate counter
                                        dup_ack_counts.insert(rev_quad.clone(), 0);
                                    }
                                }
                                ack_tracker.insert(rev_quad, ack_num);
                            }

                            // Detect lost segments
                            if tcp.get_flags() & 0x04 != 0 {
                                // RST flag
                                network_stats.record_lost_segment();
                            }
                        }
                    }
                    estimator.process_ipv6(eth.payload(), ts, &mut network_stats);
                }
                _ => (),
            }
        }
    }

    Ok(network_stats)
}
