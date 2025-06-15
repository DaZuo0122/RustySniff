use pcap::Capture;
use pcap::Offline;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::collections::HashMap;
use std::error::Error;

type StatsTuple = (usize, f64, f64, f64, f64, f64, f64, f64);

/// Count and print Top X src/dst ip address.
pub fn count_sd_addr(mut cap: Capture<Offline>, top: u8) -> Result<(), Box<dyn Error>> {
    let mut src_ips = HashMap::new();
    let mut dst_ips = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        if let Some(eth_frame) = EthernetPacket::new(packet.data) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth_frame.payload()) {
                        let src = ipv4.get_source().to_string();
                        let dst = ipv4.get_destination().to_string();

                        *src_ips.entry(src).or_insert(0) += 1;
                        *dst_ips.entry(dst).or_insert(0) += 1;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth_frame.payload()) {
                        let src = ipv6.get_source().to_string();
                        let dst = ipv6.get_destination().to_string();

                        *src_ips.entry(src).or_insert(0) += 1;
                        *dst_ips.entry(dst).or_insert(0) += 1;
                    }
                }
                _ => {}
            }
        }
    }

    let mut src_counts: Vec<_> = src_ips.into_iter().collect();
    let mut dst_counts: Vec<_> = dst_ips.into_iter().collect();

    src_counts.sort_by(|a, b| b.1.cmp(&a.1));
    dst_counts.sort_by(|a, b| b.1.cmp(&a.1));

    println!("Top {} Source IP Addresses:", &top);
    for (i, (ip, count)) in src_counts.iter().take(top as usize).enumerate() {
        println!("{:2}. {:15} - {} packets", i + 1, ip, count);
    }

    println!("\nTop {} Destination IP Addresses:", &top);
    for (i, (ip, count)) in dst_counts.iter().take(top as usize).enumerate() {
        println!("{:2}. {:15} - {} packets", i + 1, ip, count);
    }

    Ok(())
}

/// Pandas dataframe like describe method.
/// It will skip non-IP traffic.
pub fn f_describe(mut cap: Capture<Offline>) -> Result<(), Box<dyn Error>> {
    let mut start_time = None;
    let mut end_time = None;
    let mut prev_time = None;
    let mut inter_arrivals = Vec::new();
    let mut packet_sizes = Vec::new();
    let mut protocols = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let header = packet.header;
        let current_time = header.ts.tv_sec as f64 + header.ts.tv_usec as f64 / 1_000_000.0;

        // Track start/end times
        start_time.get_or_insert(current_time);
        end_time = Some(current_time);

        // Calculate inter-arrival times
        if let Some(prev) = prev_time {
            inter_arrivals.push(current_time - prev);
        }
        prev_time = Some(current_time);

        // Collect packet size
        packet_sizes.push(header.len as f64);

        // Parse protocol information
        let protocol = parse_protocol(packet.data);
        *protocols.entry(protocol).or_insert(0) += 1;
    }

    // Calculate statistics
    let total_packets = packet_sizes.len();
    let duration = end_time.unwrap_or(0.0) - start_time.unwrap_or(0.0);
    let packet_rate = if duration > 0.0 {
        total_packets as f64 / duration
    } else {
        0.0
    };

    let size_stats = calculate_stats(&packet_sizes);
    let inter_stats = calculate_stats(&inter_arrivals);

    // Prepare protocol distribution
    let mut protocol_counts: Vec<_> = protocols.into_iter().collect();
    protocol_counts.sort_by(|a, b| b.1.cmp(&a.1));

    // Print report
    println!("General Statistics:");
    println!("===================");
    println!("{:<25} {:>10}", "Total packets:", total_packets);
    println!("{:<25} {:>10.3} sec", "Capture duration:", duration);
    println!("{:<25} {:>10.3} pkt/s", "Average rate:", packet_rate);
    println!();

    println!("Packet Size Statistics (bytes):");
    println!("===============================");
    print_stat_table(size_stats);
    println!();

    println!("Inter-Arrival Time Statistics (s):");
    println!("==================================");
    print_stat_table(inter_stats);
    println!();

    println!("Protocol Distribution:");
    println!("======================");
    for (proto, count) in protocol_counts {
        let percent = (count as f64 / total_packets as f64) * 100.0;
        println!("{:<20} {:>6} ({:5.1}%)", proto, count, percent);
    }

    Ok(())
}

fn parse_protocol(data: &[u8]) -> String {
    let mut protocol = String::new();

    if let Some(eth) = EthernetPacket::new(data) {
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                protocol.push_str("IPv4");
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => protocol.push_str("/TCP"),
                        IpNextHeaderProtocols::Udp => protocol.push_str("/UDP"),
                        IpNextHeaderProtocols::Icmp => protocol.push_str("/ICMP"),
                        p => protocol.push_str(&format!("/Proto-{}", p.0)),
                    }
                }
            }
            EtherTypes::Ipv6 => {
                protocol.push_str("IPv6");
                if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                    match ipv6.get_next_header() {
                        IpNextHeaderProtocols::Tcp => protocol.push_str("/TCP"),
                        IpNextHeaderProtocols::Udp => protocol.push_str("/UDP"),
                        IpNextHeaderProtocols::Icmpv6 => protocol.push_str("/ICMPv6"),
                        p => protocol.push_str(&format!("/Proto-{}", p.0)),
                    }
                }
            }
            EtherTypes::Arp => protocol.push_str("ARP"),
            EtherTypes::Vlan => protocol.push_str("VLAN"),
            _ => protocol.push_str(&format!("Unknown")),
        }
    } else {
        protocol.push_str("Unknown");
    }

    protocol
}

fn calculate_stats(data: &[f64]) -> StatsTuple {
    if data.is_empty() {
        return (0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }

    let count = data.len();
    let sum: f64 = data.iter().sum();
    let mean = sum / count as f64;
    let variance = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (count - 1) as f64;
    let std_dev = variance.sqrt();
    let min = data.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max = data.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));

    let mut sorted = data.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let p25 = percentile(&sorted, 25.0);
    let p50 = percentile(&sorted, 50.0);
    let p75 = percentile(&sorted, 75.0);

    (count, mean, std_dev, min, p25, p50, p75, max)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[index]
}

fn print_stat_table(stats: StatsTuple) {
    println!("{:<6} {:>12.6}", "count", stats.0 as f64);
    println!("{:<6} {:>12.6}", "mean", stats.1);
    println!("{:<6} {:>12.6}", "std", stats.2);
    println!("{:<6} {:>12.6}", "min", stats.3);
    println!("{:<6} {:>12.6}", "25%", stats.4);
    println!("{:<6} {:>12.6}", "50%", stats.5);
    println!("{:<6} {:>12.6}", "75%", stats.6);
    println!("{:<6} {:>12.6}", "max", stats.7);
}
