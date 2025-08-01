# RustySniff - Network Analysis REPL
RustySniff is a powerful command-line network analysis tool that provides a REPL (Read-Eval-Print Loop) interface for analyzing PCAP files. Built in Rust for performance and reliability, it offers various network analysis capabilities including TCP, HTTP, and statistical analysis.

## Features
- **Interactive REPL interface** for exploring network captures
- **TCP analysis**: RTT estimation, connection tracing
- **HTTP/1.x analysis** with request/response inspection
- **DNS analysis** with request/response inspection
- **GFW-like detections(*experimental*)**, try improving your proxies
- **Statistical summaries** of network traffic
- **Top talkers identification** by IP address
- **BPF filter support** for focused analysis

## Installation
### Dependencies
RustySniff requires `libpcap` for packet analysis functionality. Install it for your platform:  
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
  cd RustySniff
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
| `dns` | Analyze DNS traffic with filters | `dns` or `dns --qtype A |
| `gfw` | Act as GFW (China's Great fireWall) to detect proxy traffic | `gfw --fet` |
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

## DNS Analysis Options
When using the `dns` command, you can filter results with:

- `--domain`: Filter by domain (query or answer contains)

- `--response`: Filter by response (true) or query (false) [possible values: true, false]

- `--rcode`: Filter by response code (0-10)

- `--qtype`: Filter by query type (A, AAAA, MX, etc.)

- `--min-answers`: Filter by minimum number of answers

- `--protocol`: Filter by protocol (UDP or TCP)

Example:
```bash
dns --qtype A
```

## GFW
**NB**: It's an experimental feature.  
As GFW is a black-box, this feature was implemented based on public-known informations (mainly comes from [GFW Report](https://gfw.report)).  
It now supports detection of two types of proxy protocol, FET (Fully Encrypted Traffic, see [this paper](https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf)) and Trojan (inspired by [XTLS/Trojan-killer](https://github.com/XTLS/Trojan-killer)).  
Feel free to test with your protocols.

Command `gfw` requires an option, you can choose one of the followings:

- `--fet`: Detect FET (Fully Encrypted Traffic) proxy protocols (eg. vmess)

- `--trojan`: Detect trojan-like protocols traffic (tls-in-tls patterns)

Example:
```bash
gfw --fet
```

## Roadmap
- Python Scripting Support:
  - Embed Python interpreter for custom analysis scripts
  - Scriptable packet processing pipelines
  - Extensible analysis framework
  - Use DS/ML libraries for further analysis
- TLS handshake analysis
- More GFW abilities

## Contributing
Contributions are welcome! 
>[!TIP]
> If you are using **GNU toolchain**(MinGw) on windows, please follow the instructions below to build libpcap dependency (this requires you have at least a linux VM).

**NB**: This instruction uses **Ubuntu/Debian** commands as an example.  
  1. Make sure you have `cmake` and GNU toolchain installed.  
  2. Install build dependencies
     ```bash
     sudo apt install mingw-w64

     # and

     sudo apt install flex bison
     ```
  3. Download [Npcap SDK source code](https://npcap.com/#download) and create a new folder under `path/to/npcap/wpcap`.
     ```bash
     mkdir build-win64 && cd ./build-win64
     ```
  4. Run build command
     ```bash
     cmake -DCMAKE_SYSTEM_NAME=Windows  -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc  -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++  -DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE  -DOpenSSL_FOUND=FALSE  -DLIBRARY_NAME=wpcap  -DPCAP_TYPE=null ../libpcap/

     # and

     make
     ```
  5. Check built SDK
     ```bash
     ls libwpcap.a
     ```
     You should get following if built successful
     ```text
     libwpcap.a  # It's all you need, would better rename it as wpcap.a
     ```
  6. Create a folder named `.cargo` under `path/to/RustySniff` and then create `.cargo/config.toml`. In `config.toml`, write the following:
     ```toml
     [build]
     rustflags = ["-L", "path/to/folder/contains/wpcap.a"]
     ```
### Building py-sdk
**NB**: This instruction uses **uv** commands as an example.
  1. Install [maturin](https://www.maturin.rs/)
  2. Build wheels for python
     ```bash
     cd py-sdk
     # and
     maturin build --release
     # wheels locates at ../target/wheels/
     ```
  3. Install built wheels (example `rustysniff_pysdk-0.1.0-cp312-cp312-win_amd64.whl`)
     ```bash
     # In your python virtual environment
     uv pip install path/to/wheels
     ```
  4. Using it in python
     ```python
     from rustysniffpy import *
     ```
