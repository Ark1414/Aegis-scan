"""Report building utilities for AegisScan.

Provides functions to assemble a JSON-serializable report including findings
and severity information, and to write the report to disk.
"""
from typing import Dict, List, Any
import json
from datetime import datetime


def build_report(target: str, open_ports: List[int], findings: Dict[int, Dict], metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Assemble a report structure.

    findings: mapping port -> dict containing at least score/label/note/banner
    """
    metadata = metadata or {}
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "metadata": metadata,
        "findings": [],
    }
    for p in sorted(open_ports):
        info = findings.get(p, {})
        entry = {
            "port": p,
            "score": info.get("score"),
            "label": info.get("label"),
            "note": info.get("note", ""),
            "banner": info.get("banner", ""),
        }
        report["findings"].append(entry)

    # summary counts
    counts = {str(i): 0 for i in range(1, 11)}
    for f in report["findings"]:
        s = f.get("score")
        try:
            s_i = int(s)
        except Exception:
            s_i = 1
        counts[str(max(1, min(10, s_i)))] += 1
    report["summary"] = {"by_severity": counts, "total_findings": len(report["findings"])}
    return report


def write_json_report(report: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
