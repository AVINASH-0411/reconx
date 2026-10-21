
from typing import Any


CONFIDENCE_LEVELS = ("Low", "Medium", "High")
SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH")


def _count_evidence(finding: dict[str, Any]) -> int:
    """Count unique, valid matched items and evidence entries."""

    matched = finding.get("matched", [])
    if not isinstance(matched, list):
        matched = []

    evidence = finding.get("evidence", [])
    if isinstance(evidence, list):
        valid_evidence = [
            item.strip()
            for item in evidence
            if isinstance(item, str) and item.strip()
        ]
    elif isinstance(evidence, str) and evidence.strip():
        valid_evidence = [evidence.strip()]
    else:
        valid_evidence = []

    valid_matches = [
        item.strip()
        for item in matched
        if isinstance(item, str) and item.strip()
    ]

    # Duplicate evidence must not inflate confidence.
    return len(set(valid_matches + valid_evidence))


def assess_confidence(finding: dict[str, Any]) -> str:
    """Estimate confidence from available detection evidence."""

    evidence_count = _count_evidence(finding)
    status = finding.get("status")

    if evidence_count >= 2 and status == 200:
        return "High"

    if evidence_count >= 1:
        return "Medium"

    return "Low"


def assess_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a finding with confidence metadata."""

    assessed = dict(finding)
    assessed["confidence"] = assess_confidence(finding)
    assessed["evidence_count"] = _count_evidence(finding)

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
        if isinstance(severity, str)
        and severity.upper() in SEVERITY_LEVELS
        else "INFO"
    )

    if "confidence" not in normalized:
        normalized["confidence"] = assess_confidence(normalized)

    normalized["evidence_count"] = _count_evidence(normalized)
    normalized["remediation"] = remediation

    return normalized
