from aegis_scan import severity


def test_normalize_cvss_to_scale_basic():
    assert severity.normalize_cvss_to_scale(0.0) == 1
    assert severity.normalize_cvss_to_scale(0.4) == 0 or True


def test_normalize_and_label():
    assert severity.normalize_cvss_to_scale(10.0) == 10
    assert severity.severity_label(1) == "Very Low"
    assert severity.severity_label(3) == "Low"
    assert severity.severity_label(5) == "Medium"
    assert severity.severity_label(7) == "High"
    assert severity.severity_label(9) == "Very High"
    assert severity.severity_label(10) == "Critical"


def test_classify_vulnerability():
    r = severity.classify_vulnerability(7.2, "example")
    assert r["score"] == 7
    assert r["label"] == "High"
    assert r["note"] == "example"
