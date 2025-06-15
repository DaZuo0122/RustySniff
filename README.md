# RustySniff - Network Analysis REPL
RustySniff is a powerful command-line network analysis tool that provides a REPL (Read-Eval-Print Loop) interface for analyzing PCAP files. Built in Rust for performance and reliability, it offers various network analysis capabilities including TCP, HTTP, and statistical analysis.

## Features
- **Interactive REPL interface** for exploring network captures
- **TCP analysis**: RTT estimation, connection tracing
- **HTTP/1.x analysis** with request/response inspection
- **Statistical summaries** of network traffic
- **Top talkers identification** by IP address
- **BPF filter support** for focused analysis

## Installation
### Dependencies
RustySniff requires `libpcap` for packet capture functionality. Install it for your platform:  
**macOS (using Homebrew)**  
```bash
brew install libpcap
```
**Ubuntu/Debian**
```bash
sudo apt-get install libpcap-dev
```
**Fedora/CentOS/RHEL**
```bash
sudo dnf install libpcap-devel
# or
sudo yum install libpcap-devel
```
**Windows**  
Install [Npcap](https://npcap.com/#download) (select "Install in WinPcap API-compatible Mode" during installation)

### Installation Methods
**Install via Cargo (from GitHub)**
```bash
cargo install --git https://github.com/DaZuo0122/RustySniff.git
```
**Build from Source**
  1. Install Rust toolchain: [rustup.rs](https://rustup.rs/)
  2. Install libpcap dependencies
  >[!TIP]
  > Also install corresponding SDK if you want to dive into development.  
  > On windows it's [Npcap SDK](https://npcap.com/#download), compile it from source if you are using **gnu toolchain**(Pre-built only supports msvc ).
  3. Clone repository:
  ```bash
  git clone https://github.com/DaZuo0122/RustySniff.git
  cd rustysniff
  ```
  4. Build with Cargo:
  ```bash
  cargo build --release
  ```

## Usage
Start RustySniff with a PCAP file:
```bash
rustysniff capture.pcap
```
You'll enter the REPL environment:
```text
Network Analysis REPL for capture.pcap
Type 'help' for available commands
capture.pcap >>>
```

## Commands
| Command | Description | Example Usage | 
| ----------- | ----------- | ----------- |
| `rtt` | Show RTT statistics | `rtt` or `rtt 192.168.1.1 10.0.0.1` |
| `trace` | Trace TCP connections | `trace`|
| `overview` | Show network overview statistics | `overview` |
| `http` | Analyze HTTP traffic with filters | `http --method GET` |
| `top` | Show top source/destination IPs | `top --count 20` |
| `describe`| Similar to pandas `df.describe()`, show statistical summary of traffic | `describe`|
| `filter` | Set BPF filter for subsequent commands	| `filter "tcp port 443"` |
| `show-filter` | Show current BPF filter | `show-filter` |
| `clear-filter` | Clear current BPF filter | `clear-filter` |
| `exit` | Exit REPL | `exit` |

## HTTP Analysis Options
When using the `http` command, you can filter results with:

- `--src-ip`: Filter by source IP address

- `--dst-ip`: Filter by destination IP address

- `--method`: Filter by HTTP method (e.g., GET, POST)

- `--status-code`: Filter by HTTP status code (e.g., 404)

- `--path-contains`: Filter by path containing string (e.g., "login")

Example:
```bash
http --src-ip 192.168.1.100 --path-contains admin
```

## Roadmap
- Python Scripting Support:
  - Embed Python interpreter for custom analysis scripts
  - Scriptable packet processing pipelines
  - Extensible analysis framework
  - Use DS/ML libraries for further analysis
- TLS/SSL decryption support (with provided keys)

## Contributing
Contributions are welcome! 
