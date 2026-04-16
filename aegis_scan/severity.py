"""Severity scoring utilities for AegisScan.

Provides a simple 1-10 severity scale where 1 is Very Low and 10 is Very High/Critical.
Includes helpers to normalize CVSS (0.0-10.0) values to the 1-10 scale and to map
integer severity to human-readable labels.
"""
from typing import Union


def normalize_cvss_to_scale(cvss_score: Union[float, int]) -> int:
    """Normalize a CVSS score (0.0 - 10.0) to the 1-10 AegisScan severity scale.

    Rules:
    - Input is clamped to [0.0, 10.0]
    - Rounded to nearest integer
    - 0 maps to 1 (so scale is 1..10, where 1 is Very Low)
    """
    try:
        s = float(cvss_score)
    except Exception:
        raise ValueError("cvss_score must be numeric")
    s = max(0.0, min(10.0, s))
    sev = int(round(s))
    if sev < 1:
        sev = 1
    return sev


def severity_label(sev: int) -> str:
    """Return a human-readable label for a severity integer in 1..10.

    Labels (suggested):
      1: Very Low
      2-3: Low
      4-5: Medium
      6-7: High
      8-9: Very High
      10: Critical
    """
    if not isinstance(sev, int):
        raise ValueError("sev must be an int between 1 and 10")
    if sev < 1 or sev > 10:
        raise ValueError("sev must be between 1 and 10")
    if sev == 1:
        return "Very Low"
    if sev <= 3:
        return "Low"
    if sev <= 5:
        return "Medium"
    if sev <= 7:
        return "High"
    if sev <= 9:
        return "Very High"
    return "Critical"


def classify_vulnerability(cvss: Union[float, int], extra_info: str = "") -> dict:
    """Helper to produce a small vulnerability severity report dict.

    Returns: {"cvss": <float>, "score": <int 1-10>, "label": <str>, "note": <str>}
    """
    score = normalize_cvss_to_scale(cvss)
    return {
        "cvss": float(cvss),
        "score": score,
        "label": severity_label(score),
        "note": extra_info,
    }
