"""Windows-specific, agent-less checks.

These helpers perform safe, non-destructive checks such as common port
enumeration for Windows services and optional deeper checks when
dependencies (like `impacket`) are installed.

All functions are best-effort and will not attempt credentials or destructive
actions. Use only on systems you are authorized to test.
"""
from typing import Dict, List
from . import scanner
import socket


COMMON_WINDOWS_PORTS = {
    "rpc_epmap": 135,
    "netbios_ssn": 139,
    "smb": 445,
    "rdp": 3389,
    "winrm_http": 5985,
    "winrm_https": 5986,
}


def check_common_windows_ports(host: str, timeout: float = 0.8, workers: int = 10) -> Dict[str, bool]:
    """Return a mapping of common Windows service -> whether port is open."""
    ports = list(COMMON_WINDOWS_PORTS.values())
    open_ports = set(scanner.scan_ports(host, ports, timeout=timeout, workers=workers))
    return {name: (port in open_ports) for name, port in COMMON_WINDOWS_PORTS.items()}


def smb_anonymous_share_list(host: str, timeout: float = 2.0) -> List[str]:
    """Attempt to list SMB shares using anonymous auth if `impacket` is available.

    Returns a list of share names, or an empty list / message if not available.
    This is a best-effort, non-destructive check.
    """
    try:
        from impacket.smbconnection import SMBConnection
    except Exception:
        return []

    shares = []
    try:
        # impacket expects remoteName and remoteHost. Use host for both.
        smb = SMBConnection(host, host, sess_port=445)
        # anonymous login
        smb.login('', '')
        try:
            for s in smb.listShares():
                try:
                    shares.append(s['shi1_netname'].decode('utf-8').rstrip('\x00'))
                except Exception:
                    # older impacket versions return a different structure
                    try:
                        shares.append(s.getName())
                    except Exception:
                        pass
        finally:
            try:
                smb.logoff()
            except Exception:
                pass
    except Exception:
        # Could be not allowed, filtered, or impacket API differences
        return []
    return shares


def winrm_service_probe(host: str, timeout: float = 1.0) -> Dict[str, str]:
    """Best-effort detection for WinRM: checks if ports are open and whether
    a simple HTTP GET returns a response on the WinRM endpoints.

    Does not attempt authentication.
    """
    results = {}
    for name in ("winrm_http", "winrm_https"):
        port = COMMON_WINDOWS_PORTS.get(name)
        ok = False
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            ok = True
            try:
                # attempt a small recv to see if server speaks immediately
                s.settimeout(0.5)
                data = s.recv(256)
                banner = data.decode(errors='ignore').strip()
            except Exception:
                pass
        except Exception:
            ok = False
        finally:
            try:
                s.close()
            except Exception:
                pass
        results[name] = "open" if ok else "closed"
        if banner:
            results[name + "_banner"] = banner
    return results
