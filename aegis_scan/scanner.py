import socket
import concurrent.futures
import platform
import subprocess
from typing import List, Tuple


def ping_host(host: str, timeout: int = 1000) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(max(timeout / 1000, 1))), host]
    try:
        completed = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return completed.returncode == 0
    except Exception:
        return False


def _try_connect(addr: Tuple[str, int], timeout: float = 1.0) -> Tuple[int, bool]:
    host, port = addr
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return port, True
    except Exception:
        return port, False
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_ports(host: str, ports: List[int], timeout: float = 0.8, workers: int = 100) -> List[int]:
    if not ports:
        return []
    open_ports: List[int] = []
    addrs = [(host, p) for p in ports]
    workers = max(1, min(workers, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_try_connect, a, timeout) for a in addrs]
        for fut in concurrent.futures.as_completed(futures):
            port, ok = fut.result()
            if ok:
                open_ports.append(port)
    open_ports.sort()
    return open_ports


def grab_banner(host: str, port: int, timeout: float = 1.0, recv_len: int = 2048) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            data = s.recv(recv_len)
            return data.decode(errors="ignore").strip()
        except Exception:
            return ""
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass
