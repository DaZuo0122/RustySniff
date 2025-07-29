use crate::gfw::gtcp::buffer::get_buf;
use pcap::Capture;
use pcap::Offline;
use std::net::IpAddr;

// FETAnalyzer stands for "Fully Encrypted Traffic" analyzer.
// It implements an algorithm to detect fully encrypted proxy protocols
// such as Shadowsocks, mentioned in the following paper:
// https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf
pub struct FETAnalyzer {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    // Ex1–Ex5 metrics
    pub ex1: f32,   // average pop‐count
    pub ex2: bool,  // first 6 printable
    pub ex3: f32,   // printable percentage
    pub ex4: usize, // longest contiguous printable
    pub ex5: bool,  // TLS or HTTP signature

    pub is_fet: bool, // final decision
}

impl FETAnalyzer {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr) -> Self {
        FETAnalyzer {
            src_ip,
            dst_ip,
            ex1: 0.0,
            ex2: false,
            ex3: 0.0,
            ex4: 0,
            ex5: false,
            is_fet: false,
        }
    }

    pub fn print(&self) {
        if self.is_fet {
            println!("––– FET Detected –––");
            println!("Source IP       : {}", self.src_ip);
            println!("Destination IP  : {}", self.dst_ip);
            println!();

            println!("Ex1 (avg pop-count)    : {:.4}", self.ex1);
            println!("Ex2 (first 6 printable) : {}", self.ex2);
            println!("Ex3 (printable %)       : {:.2}", self.ex3 * 100.0);
            println!("Ex4 (max printable run) : {}", self.ex4);
            println!("Ex5 (TLS/HTTP sig)      : {}", self.ex5);
            println!();

            println!("––––––––––––––––––––––––––––––––––––––");
        }
    }
}

/// Count set bits in a byte.
fn pop_count(mut b: u8) -> u32 {
    let mut cnt = 0;
    while b != 0 {
        cnt += (b & 1) as u32;
        b >>= 1;
    }
    cnt
}

/// Ex1: average pop‐count
fn average_pop_count(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let sum: u32 = bytes.iter().map(|&b| pop_count(b)).sum();
    sum as f32 / bytes.len() as f32
}

/// Ex2: first six printable ASCII
fn is_first_six_printable(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    bytes[..6].iter().all(|&b| is_printable(b))
}

/// Ex3: percentage of printable ASCII
fn printable_percentage(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let count = bytes.iter().filter(|&&b| is_printable(b)).count();
    count as f32 / bytes.len() as f32
}

/// Ex4: longest contiguous run of printable ASCII
fn contiguous_printable(bytes: &[u8]) -> usize {
    let mut max_run = 0;
    let mut cur = 0;
    for &b in bytes {
        if is_printable(b) {
            cur += 1;
        } else {
            max_run = max_run.max(cur);
            cur = 0;
        }
    }
    max_run.max(cur)
}

/// Ex5: TLS “0x16/0x17 0x03 0x00‥0x09” or common HTTP verbs
fn is_tls_or_http(bytes: &[u8]) -> bool {
    if bytes.len() >= 3 {
        // TLS pattern
        let [b0, b1, b2] = [bytes[0], bytes[1], bytes[2]];
        if (0x16..=0x17).contains(&b0) && b1 == 0x03 && b2 <= 0x09 {
            return true;
        }
        // HTTP verbs
        let s = &bytes[..3];
        if let Ok(prefix) = std::str::from_utf8(s) {
            matches!(
                prefix,
                "GET" | "HEA" | "POS" | "PUT" | "DEL" | "CON" | "OPT" | "TRA" | "PAT"
            )
        } else {
            false
        }
    } else {
        false
    }
}

/// Printable ASCII?
fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

pub fn f_analyze_fet(mut cap: Capture<Offline>, f_print: bool) -> Option<Vec<FETAnalyzer>> {
    let mut res = Vec::new();
    let connections = get_buf(cap, 8192);
    for ((src_ip, dst_ip), payload) in connections {
        let mut fet = FETAnalyzer::new(src_ip, dst_ip);

        fet.ex1 = average_pop_count(&payload);
        fet.ex2 = is_first_six_printable(&payload);
        fet.ex3 = printable_percentage(&payload);
        fet.ex4 = contiguous_printable(&payload);
        fet.ex5 = is_tls_or_http(&payload);

        let exempt = (fet.ex1 <= 3.4 || fet.ex1 >= 4.6)
            || fet.ex2
            || fet.ex3 > 0.5
            || (fet.ex4 as f32) > 20.0
            || fet.ex5;
        fet.is_fet = !exempt;

        res.push(fet);
    }

    if f_print {
        for fet_result in res {
            fet_result.print();
        }
        None
    } else {
        Some(res)
    }
}
