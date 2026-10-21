
from reconx.modules.severity import (
    classify_finding,
    summarize_severities,
)


def test_explicit_severity_takes_priority():
    assert classify_finding({
        "type": "lfi",
        "severity": "low",
    }) == "LOW"


def test_explicit_severity_ignores_case_and_whitespace():
    assert classify_finding({
        "severity": "  medium ",
    }) == "MEDIUM"


def test_invalid_explicit_severity_uses_type_rule():
    assert classify_finding({
        "severity": "critical",
        "type": "exposed_file",
    }) == "MEDIUM"


def test_open_port_is_info():
    assert classify_finding({"type": "open_port"}) == "INFO"


def test_missing_security_header_is_low():
    assert classify_finding({
        "type": "missing_security_header",
    }) == "LOW"


def test_exposed_file_is_medium():
    assert classify_finding({
        "type": "exposed_file",
    }) == "MEDIUM"


def test_lfi_is_high():
    assert classify_finding({"type": "lfi"}) == "HIGH"


def test_unknown_type_defaults_to_info():
    assert classify_finding({"type": "unknown_finding"}) == "INFO"


def test_category_fallback_is_supported():
    assert classify_finding({"category": "open redirect"}) == "MEDIUM"


def test_summarize_severities_counts_findings():
    findings = [
        {"type": "open_port"},
        {"type": "missing_security_header"},
        {"type": "exposed_file"},
        {"type": "lfi"},
        {"severity": "HIGH"},
    ]

    assert summarize_severities(findings) == {
        "INFO": 1,
        "LOW": 1,
        "MEDIUM": 1,
        "HIGH": 2,
    }


def test_summarize_empty_findings():
    assert summarize_severities([]) == {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
    }

def test_none_finding_type_defaults_to_info():
    assert classify_finding({"type": None}) == "INFO"


def test_non_string_finding_type_defaults_to_info():
    assert classify_finding({"type": ["lfi"]}) == "INFO"


def test_non_dict_finding_defaults_safely():
    assert classify_finding({}) == "INFO"

