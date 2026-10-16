
from typing import Any


SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH")


def classify_finding(finding: dict[str, Any]) -> str:
    """Classify a finding using explicit severity or a conservative type-based rule."""

    explicit = finding.get("severity")

    if isinstance(explicit, str):
        explicit = explicit.strip().upper()
        if explicit in SEVERITY_LEVELS:
            return explicit

    finding_type = str(
        finding.get("type", finding.get("category", ""))
    ).strip().lower()

    rules = {
        "info": "INFO",
        "information": "INFO",
        "open_port": "INFO",
        "open port": "INFO",
        "missing_security_header": "LOW",
        "missing security header": "LOW",
        "directory": "LOW",
        "directory_found": "LOW",
        "exposed_file": "MEDIUM",
        "exposed file": "MEDIUM",
        "open_redirect": "MEDIUM",
        "open redirect": "MEDIUM",
        "lfi": "HIGH",
        "local_file_inclusion": "HIGH",
        "local file inclusion": "HIGH",
    }

    return rules.get(finding_type, "INFO")


def summarize_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity."""

    counts = {level: 0 for level in SEVERITY_LEVELS}

    for finding in findings:
        severity = classify_finding(finding)
        counts[severity] += 1

    return counts

