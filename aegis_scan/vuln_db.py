"""A tiny vulnerability mapping used to produce severity scores for findings.

This module provides a best-effort mapping from common service ports to a
representative CVSS score (0.0-10.0). It's intentionally simple: a real
implementation would use a signature database and fingerprints.

The assess_port function returns a dict compatible with severity.classify_vulnerability.
"""
from typing import Dict
from . import severity

# Representative CVSS scores for common services (defaults)
# These are illustrative only and should be replaced with a proper vulnerability DB.
DEFAULT_PORT_CVSS = {
    135: 6.5,     # MS RPC / EpMap
    139: 6.0,     # NetBIOS SSN
    445: 9.8,     # SMB (critical historically)
    3389: 7.8,    # RDP
    5985: 6.0,    # WinRM (HTTP)
    5986: 6.0,    # WinRM (HTTPS)
    22: 5.0,      # SSH
    80: 4.0,      # HTTP
    443: 4.0,     # HTTPS
}


def assess_port(port: int, banner: str = "") -> Dict:
    """Assess a port and return a severity dict: {cvss, score, label, note}.

    If no mapping exists, we return a low/medium default (CVSS 3.0).
    """
    cvss = DEFAULT_PORT_CVSS.get(port, 3.0)
    note = ""
    if banner:
        note = f"Banner: {banner[:120]}"
    return severity.classify_vulnerability(cvss, extra_info=note)


def summarize_findings(findings: Dict[int, Dict]) -> Dict[int, int]:
    """Given a mapping port->finding (each with 'score'), return counts per score 1..10."""
    counts = {i: 0 for i in range(1, 11)}
    for info in findings.values():
        s = info.get("score") if isinstance(info, dict) else None
        if isinstance(s, int) and 1 <= s <= 10:
            counts[s] += 1
        else:
            counts[1] += 1
    return counts
