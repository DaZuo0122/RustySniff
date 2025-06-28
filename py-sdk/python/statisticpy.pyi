from typing import List, Tuple

class TopIPs:
    src_ips: List[Tuple[str, int]]
    dst_ips: List[Tuple[str, int]]

class ProtocolStat:
    name: str
    count: int
    percentage: float

class NetworkSummary:
    total_packets: int
    duration: float
    packet_rate: float
    protocol_distribution: List[ProtocolStat]

def count_sd_addr_data(file_path: str, top: int) -> TopIPs: ...

def f_describe_data(file_path: str) -> NetworkSummary: ...
