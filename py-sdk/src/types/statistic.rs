// src/statistic_wrapper.rs
use network::statistic;
use pcap::Capture;
use pyo3::exceptions;
use pyo3::prelude::*;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

// Simple output capture without stdout redirection
struct OutputCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl OutputCapture {
    fn new() -> Self {
        OutputCapture {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn run<F>(&self, func: F) -> io::Result<String>
    where
        F: FnOnce() -> io::Result<()>,
    {
        // Clear previous buffer
        let mut buffer = self.buffer.lock().unwrap();
        buffer.clear();

        // Run function
        func()?;

        // Return captured output
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }
}

impl Write for OutputCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.flush()
    }
}

#[pyclass]
pub struct TopIPs {
    #[pyo3(get)]
    pub src_ips: Vec<(String, usize)>,
    #[pyo3(get)]
    pub dst_ips: Vec<(String, usize)>,
}

#[derive(Clone)]
#[pyclass]
pub struct ProtocolStat {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub count: usize,
    #[pyo3(get)]
    pub percentage: f64,
}

#[pyclass]
pub struct NetworkSummary {
    #[pyo3(get)]
    pub total_packets: usize,
    #[pyo3(get)]
    pub duration: f64,
    #[pyo3(get)]
    pub packet_rate: f64,
    #[pyo3(get)]
    pub protocol_distribution: Vec<ProtocolStat>,
}

// Module initialization
#[pymodule]
pub fn statisticpy(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TopIPs>()?;
    m.add_class::<ProtocolStat>()?;
    m.add_class::<NetworkSummary>()?;

    #[pyfn(m)]
    fn count_sd_addr_data(file_path: &str, top: u8) -> PyResult<TopIPs> {
        let cap = Capture::from_file(file_path)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;

        let capture = OutputCapture::new();
        let output = {
            let mut guard = capture;
            guard.run(|| {
                statistic::count_sd_addr(cap, top)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            })
        }
        .map_err(|e| exceptions::PyRuntimeError::new_err(e.to_string()))?;

        let mut src_ips = Vec::new();
        let mut dst_ips = Vec::new();
        let mut current_section = None;

        for line in output.lines() {
            if line.starts_with("Top") {
                if line.contains("Source") {
                    current_section = Some("src");
                } else if line.contains("Destination") {
                    current_section = Some("dst");
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix(|c: char| c.is_ascii_digit() || c == '.') {
                if let Some((ip, count)) = parse_ip_count(rest) {
                    match current_section {
                        Some("src") => src_ips.push((ip, count)),
                        Some("dst") => dst_ips.push((ip, count)),
                        _ => (),
                    }
                }
            }
        }

        Ok(TopIPs { src_ips, dst_ips })
    }

    #[pyfn(m)]
    fn f_describe_data(file_path: &str) -> PyResult<NetworkSummary> {
        let cap = Capture::from_file(file_path)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;

        let capture = OutputCapture::new();
        let output = {
            let mut guard = capture;
            guard.run(|| {
                statistic::f_describe(cap)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            })
        }
        .map_err(|e| exceptions::PyRuntimeError::new_err(e.to_string()))?;

        let mut total_packets = 0;
        let mut duration = 0.0;
        let mut packet_rate = 0.0;
        let mut protocol_distribution = Vec::new();
        let mut in_protocol_section = false;

        for line in output.lines() {
            if line.starts_with("Total packets:") {
                if let Some(value) = line.split(':').nth(1) {
                    total_packets = value.trim().parse().unwrap_or(0);
                }
            } else if line.starts_with("Capture duration:") {
                if let Some(value) = line.split_whitespace().nth(2) {
                    duration = value.parse().unwrap_or(0.0);
                }
            } else if line.starts_with("Average rate:") {
                if let Some(value) = line.split_whitespace().nth(2) {
                    packet_rate = value.parse().unwrap_or(0.0);
                }
            } else if line == "Protocol Distribution:" {
                in_protocol_section = true;
            } else if in_protocol_section && !line.is_empty() {
                if let Some(stat) = parse_protocol_line(line) {
                    protocol_distribution.push(stat);
                }
            } else if line.is_empty() {
                in_protocol_section = false;
            }
        }

        Ok(NetworkSummary {
            total_packets,
            duration,
            packet_rate,
            protocol_distribution,
        })
    }

    Ok(())
}

fn parse_ip_count(line: &str) -> Option<(String, usize)> {
    let cleaned = line
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
        .trim();
    let parts: Vec<&str> = cleaned.split('-').collect();
    if parts.len() < 2 {
        return None;
    }

    let ip = parts[0].trim().to_string();
    let count_str = parts[1].trim().split_whitespace().next()?;
    count_str.parse().ok().map(|count| (ip, count))
}

fn parse_protocol_line(line: &str) -> Option<ProtocolStat> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let count_str = parts.next()?;
    let percentage_str = parts.next()?;

    let count = count_str.parse().ok()?;
    let percentage = percentage_str
        .trim_matches(|c| c == '(' || c == '%' || c == ')')
        .parse()
        .unwrap_or(0.0);

    Some(ProtocolStat {
        name,
        count,
        percentage,
    })
}
