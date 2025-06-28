from typing import Dict, List, Optional, Tuple

class PyDirection: ...
    ClientToServer: PyDirection
    ServerToClient: PyDirection

class PyConnectionState: ...
    Init: PyConnectionState
    SynSent: PyConnectionState
    SynReceived: PyConnectionState
    Established: PyConnectionState
    FinWait1: PyConnectionState
    Closing: PyConnectionState
    Closed: PyConnectionState

class PyTcpPacketInfo:
    timestamp: float
    direction: PyDirection
    flags: str
    seq: int
    ack: int
    payload_len: int
    window: int

class PyTcpFlow:
    packets: List[PyTcpPacketInfo]
    state: PyConnectionState

class PyRttStats:
    count: int
    min: float
    max: float
    average: float
    std_dev: float

class PyNetworkStats:
    rtt_stats: PyRttStats
    retrans_count: int
    fast_retrans_count: int
    dup_ack_count: int
    lost_segment_count: int
    min_window: int
    max_window: int
    avg_window: float

class PyRttEstimator: ...

def gen_rtt_estimator(
    file_path: str,
    f_print: bool
) -> Optional[PyRttEstimator]: ...

def f_estimate_rtt(
    src: str,
    dst: str,
    estimator: PyRttEstimator,
    f_print: bool
) -> Optional[List[float]]: ...

def f_trace_tcp_conn(
    file_path: str,
    f_print: bool
) -> Optional[Dict[str, PyTcpFlow]]: ...

def f_analyze_tcp_network(file_path: str) -> PyNetworkStats: ...
