use crate::network::types::tcp1::{NetworkStats, RttEstimator, TcpFlow};
use crate::network::types::tcp1::{
    f_analyze_tcp_network, f_estimate_rtt, f_trace_tcp_conn, gen_rtt_estimator,
};
use clap::Parser;
use clap::builder::TypedValueParser as _;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{Editor, Result as RustylineResult};
use shlex::split;
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The pcap file to analyze
    pcap_file: PathBuf,
}

#[derive(clap::Parser)]
struct ReplCommand {
    #[command(subcommand)]
    cmd: Command,
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

fn get_prompt(pcap_name: &str, filter: Option<&String>) -> String {
    match filter {
        Some(f) => format!("{} [filter:{}] >>> ", pcap_name, f),
        None => format!("{} >>> ", pcap_name),
    }
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
                            crate::network::types::tcp1::print_connection(key, flow);
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
