from typing import Optional, Tuple, List

class PyHttpMessage:
    src_ip: str
    dst_ip: str
    method: Optional[str]
    path: Optional[str]
    version: Optional[int]
    status_code: Optional[int]
    reason: Optional[str]
    headers: List[Tuple[str, str]]

    def __repr__(self) -> str: ...

class PyHttpFilter:
    src_ip: Optional[str]
    dst_ip: Optional[str]
    method: Optional[str]
    status_code: Optional[int]
    path_contains: Optional[str]

    def __init__(self) -> None: ...
    def set_src_ip(self, ip: str) -> None: ...
    def set_dst_ip(self, ip: str) -> None: ...
    def set_method(self, method: str) -> None: ...
    def set_status_code(self, code: int) -> None: ...
    def set_path_contains(self, substring: str) -> None: ...

def process_http_1_x(
    file_path: str,
    filter: PyHttpFilter,
    f_print: bool
) -> Optional[List[PyHttpMessage]]: ...
