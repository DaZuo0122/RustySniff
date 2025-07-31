use clap::builder::TypedValueParser as _;
use clap::{ArgGroup, Parser};
use network::gfw::gtcp::fet::{FETAnalyzer, f_analyze_fet};
use network::gfw::gtcp::trojan::{TrojanAnalyzer, f_analyze_trojan, match_trojan};
use network::statistic::{count_sd_addr, f_describe};
use network::types::dns::{DnsFilter, DnsRecord, f_process_dns};
use network::types::http::{HttpFilter, HttpMessage, f_process_http_1_x};
use network::types::tcp::{NetworkStats, RttEstimator, TcpFlow};
use network::types::tcp::{
    f_analyze_tcp_network, f_estimate_rtt, f_trace_tcp_conn, gen_rtt_estimator,
};
// use network::types::tls::{TlsFilter, TlsHandshake, f_analyze_handshake};
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{Editor, Result as RustylineResult};
use shlex::split;
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
// use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "A lightweight REPL network traffic analyzer")]
struct Cli {
    /// The pcap file to analyze
    pcap_file: PathBuf,
}

#[derive(clap::Parser)]
struct ReplCommand {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Parser, Debug)]
#[command(group(ArgGroup::new("gfw").required(true).multiple(false)))]
struct GFWArgs {
    /// Detect FET (Fully Encrypted Traffic) proxy protocols (eg. vmess)
    #[arg(long, group = "gfw")]
    fet: bool,
    /// Detect trojan-like protocols traffic (tls-in-tls patterns)
    #[arg(long, group = "gfw")]
    trojan: bool,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Show RTT statistics
    Rtt {
        /// Optional source and destination addresses (format: src dst)
        pair: Vec<String>,
    },
    /// Trace TCP connections
    Trace,
    /// Show network overview statistics
    Overview,
    /// Set BPF filter for subsequent commands
    /// Example usage: filter "tcp port 443"
    Filter {
        /// BPF filter expression
        filter: String,
    },
    /// Show current filter
    ShowFilter,
    /// Clear current filter
    ClearFilter,
    /// Analyze HTTP traffic
    Http {
        /// Filter by source IP address
        #[arg(long)]
        src_ip: Option<String>,
        /// Filter by destination IP address
        #[arg(long)]
        dst_ip: Option<String>,
        /// Filter by HTTP method (e.g., GET, POST)
        #[arg(long)]
        method: Option<String>,
        /// Filter by status code (for responses)
        #[arg(long)]
        status_code: Option<u16>,
        /// Filter by path containing a string (for requests)
        #[arg(long)]
        path_contains: Option<String>,
    },
    /// Analyze DNS traffic
    Dns {
        /// Filter by domain (query or answer contains)
        #[arg(long)]
        domain: Option<String>,
        /// Filter by response (true) or query (false)
        #[arg(long)]
        response: Option<bool>,
        /// Filter by response code (0-10)
        #[arg(long)]
        rcode: Option<u8>,
        /// Filter by query type (A, AAAA, MX, etc.)
        #[arg(long)]
        qtype: Option<String>,
        /// Filter by minimum number of answers
        #[arg(long)]
        min_answers: Option<usize>,
        /// Filter by protocol (UDP or TCP)
        #[arg(long)]
        protocol: Option<String>,
    },
    /*
    Tls {
        /// Filter by minimum version
        #[arg(long)]
        min_version: Option<u16>,
        /// Filter by maximum version
        #[arg(long)]
        max_version: Option<u16>,
        /// Filter by cipher suit offered
        #[arg(long)]
        cipher_offered: Option<Vec<u16>>,
        /// Filter by cipher suit chosen
        #[arg(long)]
        cipher_chosen: Option<u16>,
        #[arg(long)]
        sni_contains: Option<String>,
        #[arg(long)]
        alpn_contains: Option<String>,
        #[arg(long)]
        ja3_hash: Option<String>,
    },*/
    /// Act like GFW (China's Great fireWall), detecting proxy protocols
    Gfw(GFWArgs),
    /// Show top source/destination IP addresses
    Top {
        /// Number of top IPs to show (default: 10)
        #[arg(short, long, default_value_t = 10)]
        count: u8,
    },
    /// Show statistical summary of network traffic(pandas-like describe)
    Describe,
    /// Exit the REPL
    Exit,
}

struct AppState {
    pcap_path: String,
    pcap_name: String,
    bpf_filter: Option<String>,
    rtt_estimator: Option<RttEstimator>,
    traced_conns: Option<HashMap<String, TcpFlow>>,
    network_stats: Option<NetworkStats>,
}

fn open_pcap(
    pcap_path: &str,
    filter: Option<&str>,
) -> Result<pcap::Capture<pcap::Offline>, Box<dyn Error>> {
    let mut cap = pcap::Capture::from_file(pcap_path)?;
    if let Some(f) = filter {
        cap.filter(f, true)?;
    }
    Ok(cap)
}

fn get_rtt_estimator(
    pcap_path: &str,
    filter: Option<&str>,
) -> Result<RttEstimator, Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    Ok(gen_rtt_estimator(cap, false)
        .unwrap()
        .map(|opt| opt)
        .unwrap())
}

fn get_traced_conns(
    pcap_path: &str,
    filter: Option<&str>,
) -> Result<HashMap<String, TcpFlow>, Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    Ok(f_trace_tcp_conn(cap, false).unwrap())
}

fn get_network_stats(
    pcap_path: &str,
    filter: Option<&str>,
) -> Result<NetworkStats, Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    f_analyze_tcp_network(cap)
}

/*
fn get_tls_handshake(
    pcap_path: &str,
    filter: Option<&str>,
    tls_filter: TlsFilter,
) -> Result<Option<Vec<TlsHandshake>>, Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    Ok(f_analyze_handshake(cap, tls_filter, true))
}*/

fn get_fet_result(pcap_path: &str, filter: Option<&str>) -> Result<(), Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    f_analyze_fet(cap, true);
    Ok(())
}

fn get_trojan_result(pcap_path: &str, filter: Option<&str>) -> Result<(), Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    f_analyze_trojan(cap, true);
    Ok(())
}

fn get_prompt(pcap_name: &str, filter: Option<&String>) -> String {
    match filter {
        Some(f) => format!("{} [filter:{}] >>> ", pcap_name, f),
        None => format!("{} >>> ", pcap_name),
    }
}

fn process_http(
    pcap_path: &str,
    filter: Option<&str>,
    http_filter: HttpFilter,
) -> Result<(), Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    f_process_http_1_x(cap, http_filter, true);
    Ok(())
}

fn describe_network(pcap_path: &str, filter: Option<&str>) -> Result<(), Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    f_describe(cap)
}

fn top_ips(pcap_path: &str, filter: Option<&str>, count: u8) -> Result<(), Box<dyn Error>> {
    let cap = open_pcap(pcap_path, filter)?;
    count_sd_addr(cap, count)
}

pub fn run_app() -> RustylineResult<()> {
    let cli = Cli::parse();
    let pcap_path = cli.pcap_file.to_string_lossy().to_string();
    let pcap_name = cli
        .pcap_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capture.pcap")
        .to_string();

    let mut editor = Editor::<(), DefaultHistory>::new()?;
    let mut app_state = AppState {
        pcap_path,
        pcap_name,
        bpf_filter: None,
        rtt_estimator: None,
        traced_conns: None,
        network_stats: None,
    };

    println!("Network Analysis REPL for {}", app_state.pcap_name);
    println!("Type 'help' for available commands");

    loop {
        let prompt = get_prompt(&app_state.pcap_name, app_state.bpf_filter.as_ref());
        let readline = editor.readline(&prompt);

        match readline {
            Ok(line) => {
                editor.add_history_entry(&line);
                let args = match split(&line) {
                    Some(args) => args,
                    None => {
                        println!("Error: Invalid command syntax");
                        continue;
                    }
                };

                if args.is_empty() {
                    continue;
                }

                let cmd = match ReplCommand::try_parse_from(
                    std::iter::once("").chain(args.iter().map(|s: &String| s.as_str())),
                ) {
                    Ok(cmd) => cmd,
                    Err(e) => {
                        println!("{}", e);
                        continue;
                    }
                };

                match cmd.cmd {
                    Command::Rtt { pair } => {
                        if app_state.rtt_estimator.is_none() {
                            println!("Processing RTT data...");
                            match get_rtt_estimator(
                                &app_state.pcap_path,
                                app_state.bpf_filter.as_deref(),
                            ) {
                                Ok(estimator) => {
                                    app_state.rtt_estimator = Some(estimator);
                                    println!("RTT data processed");
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                    continue;
                                }
                            }
                        }

                        let estimator = app_state.rtt_estimator.as_ref().unwrap();
                        if pair.is_empty() {
                            estimator.print();
                        } else if pair.len() == 2 {
                            let src = &pair[0];
                            let dst = &pair[1];
                            match f_estimate_rtt(src, dst, estimator, true) {
                                Ok(_) => {}
                                Err(e) => println!("Error: {}", e),
                            }
                        } else {
                            println!("Error: rtt command requires either 0 or 2 arguments");
                        }
                    }
                    Command::Trace => {
                        if app_state.traced_conns.is_none() {
                            println!("Tracing connections...");
                            match get_traced_conns(
                                &app_state.pcap_path,
                                app_state.bpf_filter.as_deref(),
                            ) {
                                Ok(conns) => {
                                    app_state.traced_conns = Some(conns);
                                    println!("Connections traced");
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                    continue;
                                }
                            }
                        }

                        let conns = app_state.traced_conns.as_ref().unwrap();
                        for (key, flow) in conns {
                            network::types::tcp::print_connection(key, flow);
                        }
                    }
                    Command::Overview => {
                        if app_state.network_stats.is_none() {
                            println!("Analyzing network...");
                            match get_network_stats(
                                &app_state.pcap_path,
                                app_state.bpf_filter.as_deref(),
                            ) {
                                Ok(stats) => {
                                    app_state.network_stats = Some(stats);
                                    println!("Network analysis complete");
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                    continue;
                                }
                            }
                        }

                        let stats = app_state.network_stats.as_ref().unwrap();
                        stats.print();
                    }
                    Command::Filter { filter } => {
                        app_state.bpf_filter = Some(filter.clone());
                        app_state.rtt_estimator = None;
                        app_state.traced_conns = None;
                        app_state.network_stats = None;
                        println!("BPF filter set to: '{}'", filter);
                        println!("Caches cleared - data will be reprocessed with filter");
                    }
                    Command::ShowFilter => match &app_state.bpf_filter {
                        Some(f) => println!("Current BPF filter: '{}'", f),
                        None => println!("No BPF filter is currently set"),
                    },
                    Command::ClearFilter => {
                        if app_state.bpf_filter.is_some() {
                            app_state.bpf_filter = None;
                            app_state.rtt_estimator = None;
                            app_state.traced_conns = None;
                            app_state.network_stats = None;
                            println!("BPF filter cleared");
                            println!("Caches cleared - data will be reprocessed without filter");
                        } else {
                            println!("No filter was set");
                        }
                    }
                    Command::Http {
                        src_ip,
                        dst_ip,
                        method,
                        status_code,
                        path_contains,
                    } => {
                        // Parse IP addresses if provided
                        let src_ip = src_ip
                            .map(|s| IpAddr::from_str(&s))
                            .transpose()
                            .map_err(|e| format!("Invalid source IP: {}", e))
                            .unwrap();

                        let dst_ip = dst_ip
                            .map(|s| IpAddr::from_str(&s))
                            .transpose()
                            .map_err(|e| format!("Invalid destination IP: {}", e))
                            .unwrap();

                        let http_filter = HttpFilter {
                            src_ip,
                            dst_ip,
                            method,
                            status_code,
                            path_contains,
                        };

                        match process_http(
                            &app_state.pcap_path,
                            app_state.bpf_filter.as_deref(),
                            http_filter,
                        ) {
                            Ok(_) => println!("HTTP analysis completed"),
                            Err(e) => println!("Error processing HTTP: {}", e),
                        }
                    }
                    Command::Dns {
                        domain,
                        response,
                        rcode,
                        qtype,
                        min_answers,
                        protocol,
                    } => {
                        let dns_filter = DnsFilter {
                            domain,
                            is_response: response,
                            rcode,
                            query_type: qtype,
                            min_answers,
                            protocol,
                        };

                        match f_process_dns(
                            &app_state.pcap_path,
                            app_state.bpf_filter.as_deref(),
                            Some(dns_filter),
                        ) {
                            Ok(records) => {
                                for record in &records {
                                    record.print();
                                }
                                println!("Found {} DNS records.", records.len());
                            }
                            Err(e) => println!("Error processing DNS: {}", e),
                        }
                    } /*
                    Command::Tls {
                    min_version,
                    max_version,
                    cipher_offered,
                    cipher_chosen,
                    sni_contains,
                    alpn_contains,
                    ja3_hash,
                    } => {
                    let tls_filter = TlsFilter {
                    min_version,
                    max_version,
                    cipher_offered,
                    cipher_chosen,
                    sni_contains,
                    alpn_contains,
                    ja3_hash,
                    min_duration: None,
                    max_duration: None,
                    };
                    match get_tls_handshake(
                    &app_state.pcap_path,
                    app_state.bpf_filter.as_deref(),
                    tls_filter,
                    ) {
                    Ok(_) => println!("TLS handshake analysis completed"),
                    Err(e) => println!("Error: {}", e),
                    }
                    }*/
                    Command::Gfw(gfw_opt) => {
                        if gfw_opt.fet {
                            match get_fet_result(
                                &app_state.pcap_path,
                                app_state.bpf_filter.as_deref(),
                            ) {
                                Ok(_) => println!("FET analysis completed"),
                                Err(e) => println!("Error: {}", e),
                            }
                        } else if gfw_opt.trojan {
                            match get_trojan_result(
                                &app_state.pcap_path,
                                app_state.bpf_filter.as_deref(),
                            ) {
                                Ok(_) => println!("Trojan protocol analysis completed"),
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                    }
                    Command::Top { count } => {
                        match top_ips(&app_state.pcap_path, app_state.bpf_filter.as_deref(), count)
                        {
                            Ok(_) => println!("Top IP analysis completed"),
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    Command::Describe => {
                        match describe_network(
                            &app_state.pcap_path,
                            app_state.bpf_filter.as_deref(),
                        ) {
                            Ok(_) => println!("Statistical analysis completed"),
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    Command::Exit => {
                        println!("Exiting...");
                        process::exit(0);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}
