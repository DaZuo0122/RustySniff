use network::types::tcp::{self, ConnectionState, Direction, NetworkStats, RttEstimator, TcpFlow};
use pyo3::exceptions;
use pyo3::prelude::*;
use std::collections::HashMap;

// Wrapper for Direction enum
#[pyclass]
#[derive(Clone)]
pub enum PyDirection {
    ClientToServer,
    ServerToClient,
}

impl From<Direction> for PyDirection {
    fn from(d: Direction) -> Self {
        match d {
            Direction::ClientToServer => PyDirection::ClientToServer,
            Direction::ServerToClient => PyDirection::ServerToClient,
        }
    }
}

// Wrapper for ConnectionState enum
#[pyclass]
#[derive(Clone)]
pub enum PyConnectionState {
    Init,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    Closing,
    Closed,
}

impl From<ConnectionState> for PyConnectionState {
    fn from(cs: ConnectionState) -> Self {
        match cs {
            ConnectionState::Init => PyConnectionState::Init,
            ConnectionState::SynSent => PyConnectionState::SynSent,
            ConnectionState::SynReceived => PyConnectionState::SynReceived,
            ConnectionState::Established => PyConnectionState::Established,
            ConnectionState::FinWait1 => PyConnectionState::FinWait1,
            ConnectionState::Closing => PyConnectionState::Closing,
            ConnectionState::Closed => PyConnectionState::Closed,
        }
    }
}

// Wrapper for TcpPacketInfo
#[pyclass]
#[derive(Clone)]
pub struct PyTcpPacketInfo {
    #[pyo3(get)]
    timestamp: f64,
    #[pyo3(get)]
    direction: PyDirection,
    #[pyo3(get)]
    flags: String,
    #[pyo3(get)]
    seq: u32,
    #[pyo3(get)]
    ack: u32,
    #[pyo3(get)]
    payload_len: usize,
    #[pyo3(get)]
    window: u16,
}

impl From<tcp::TcpPacketInfo> for PyTcpPacketInfo {
    fn from(pkt: tcp::TcpPacketInfo) -> Self {
        PyTcpPacketInfo {
            timestamp: pkt.timestamp,
            direction: pkt.direction.into(),
            flags: pkt.flags,
            seq: pkt.seq,
            ack: pkt.ack,
            payload_len: pkt.payload_len,
            window: pkt.window,
        }
    }
}

// Wrapper for TcpFlow
#[pyclass]
pub struct PyTcpFlow {
    #[pyo3(get)]
    packets: Vec<PyTcpPacketInfo>,
    #[pyo3(get)]
    state: PyConnectionState,
}

impl From<tcp::TcpFlow> for PyTcpFlow {
    fn from(flow: tcp::TcpFlow) -> Self {
        PyTcpFlow {
            packets: flow.packets.into_iter().map(|p| p.into()).collect(),
            state: flow.state.into(),
        }
    }
}

// Wrapper for RttStats
#[derive(Clone, Copy)]
#[pyclass]
pub struct PyRttStats {
    #[pyo3(get)]
    count: usize,
    #[pyo3(get)]
    min: f64,
    #[pyo3(get)]
    max: f64,
    #[pyo3(get)]
    average: f64,
    #[pyo3(get)]
    std_dev: f64,
}

impl From<tcp::RttStats> for PyRttStats {
    fn from(stats: tcp::RttStats) -> Self {
        PyRttStats {
            count: stats.count,
            min: stats.min * 1000.0,
            max: stats.max * 1000.0,
            average: stats.average() * 1000.0,
            std_dev: stats.std_dev() * 1000.0,
        }
    }
}

// Wrapper for NetworkStats
#[pyclass]
pub struct PyNetworkStats {
    #[pyo3(get)]
    rtt_stats: PyRttStats,
    #[pyo3(get)]
    retrans_count: u32,
    #[pyo3(get)]
    fast_retrans_count: u32,
    #[pyo3(get)]
    dup_ack_count: u32,
    #[pyo3(get)]
    lost_segment_count: u32,
    #[pyo3(get)]
    min_window: u16,
    #[pyo3(get)]
    max_window: u16,
    #[pyo3(get)]
    avg_window: f64,
}

impl From<tcp::NetworkStats> for PyNetworkStats {
    fn from(ns: tcp::NetworkStats) -> Self {
        let avg_window = if ns.window_stats.count > 0 {
            ns.window_stats.sum as f64 / ns.window_stats.count as f64
        } else {
            0.0
        };

        PyNetworkStats {
            rtt_stats: ns.rtt_stats.into(),
            retrans_count: ns.retrans_count,
            fast_retrans_count: ns.fast_retrans_count,
            dup_ack_count: ns.dup_ack_count,
            lost_segment_count: ns.lost_segment_count,
            min_window: ns.window_stats.min,
            max_window: ns.window_stats.max,
            avg_window,
        }
    }
}

// Wrapper for RttEstimator (opaque type)
#[pyclass]
pub struct PyRttEstimator {
    inner: tcp::RttEstimator,
}

// PyO3 Module
#[pymodule]
pub fn tcpy(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDirection>()?;
    m.add_class::<PyConnectionState>()?;
    m.add_class::<PyTcpPacketInfo>()?;
    m.add_class::<PyTcpFlow>()?;
    m.add_class::<PyRttStats>()?;
    m.add_class::<PyNetworkStats>()?;
    m.add_class::<PyRttEstimator>()?;

    #[pyfn(m)]
    #[pyo3(signature = (file_path, f_print))]
    fn gen_rtt_estimator(file_path: &str, f_print: bool) -> PyResult<Option<PyRttEstimator>> {
        let cap = pcap::Capture::from_file(file_path)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;
        let res = tcp::gen_rtt_estimator(cap, f_print)
            .map_err(|e| exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(res.map(|inner| PyRttEstimator { inner }))
    }

    #[pyfn(m)]
    #[pyo3(signature = (src, dst, estimator, f_print))]
    fn f_estimate_rtt(
        src: &str,
        dst: &str,
        estimator: &PyRttEstimator,
        f_print: bool,
    ) -> PyResult<Option<Vec<f64>>> {
        tcp::f_estimate_rtt(src, dst, &estimator.inner, f_print)
            .map_err(|e| exceptions::PyValueError::new_err(e.to_string()))
    }

    #[pyfn(m)]
    #[pyo3(signature = (file_path, f_print))]
    fn f_trace_tcp_conn(
        file_path: &str,
        f_print: bool,
    ) -> PyResult<Option<HashMap<String, PyTcpFlow>>> {
        let cap = pcap::Capture::from_file(file_path)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;
        let res = tcp::f_trace_tcp_conn(cap, f_print);
        Ok(res.map(|conn_map| conn_map.into_iter().map(|(k, v)| (k, v.into())).collect()))
    }

    #[pyfn(m)]
    #[pyo3(signature = (file_path))]
    fn f_analyze_tcp_network(file_path: &str) -> PyResult<PyNetworkStats> {
        let cap = pcap::Capture::from_file(file_path)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;
        let stats = tcp::f_analyze_tcp_network(cap)
            .map_err(|e| exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(stats.into())
    }

    Ok(())
}
