from typing import Any


CONFIDENCE_LEVELS = ("Low", "Medium", "High")
SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH")


def assess_confidence(finding: dict[str, Any]) -> str:
    """Estimate confidence from available detection evidence."""

    matched = finding.get("matched", [])
    evidence = finding.get("evidence", "")
    status = finding.get("status")

    if not isinstance(matched, list):
        matched = []

    valid_matches = [
        item for item in matched
        if isinstance(item, str) and item.strip()
    ]

    if isinstance(evidence, list):
        valid_evidence = [
            item for item in evidence
            if isinstance(item, str) and item.strip()
        ]
    elif isinstance(evidence, str) and evidence.strip():
        valid_evidence = [evidence]
    else:
        valid_evidence = []

    evidence_count = len(valid_matches) + len(valid_evidence)

    if evidence_count >= 2 and status == 200:
        return "High"

    if evidence_count >= 1:
        return "Medium"

    return "Low"

def assess_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a finding with confidence metadata."""

    assessed = dict(finding)
    assessed["confidence"] = assess_confidence(finding)

    matched = finding.get("matched", [])
    if not isinstance(matched, list):
        matched = []

    assessed["evidence_count"] = sum(
        1
        for item in matched
        if isinstance(item, str) and item.strip()
    )

    return assessed


def normalize_finding(
    finding: dict[str, Any],
    finding_type: str,
    severity: str = "INFO",
    remediation: str = "",
) -> dict[str, Any]:
    """Add consistent metadata while preserving original finding fields."""

    normalized = dict(finding)

    normalized["type"] = finding_type
    normalized["severity"] = (
        severity.upper()
        if severity.upper() in SEVERITY_LEVELS
        else "INFO"
    )

    if "confidence" not in normalized:
        normalized["confidence"] = assess_confidence(normalized)

    matched = normalized.get("matched", [])
    if not isinstance(matched, list):
        matched = []

    evidence = normalized.get("evidence", [])
    if isinstance(evidence, list):
        valid_evidence = [
            item for item in evidence
            if isinstance(item, str) and item.strip()
        ]
    elif isinstance(evidence, str) and evidence.strip():
        valid_evidence = [evidence]
    else:
        valid_evidence = []

    normalized["evidence_count"] = (
        sum(
            1 for item in matched
            if isinstance(item, str) and item.strip()
        )
        + len(valid_evidence)
    )

    normalized["remediation"] = remediation
    return normalized
