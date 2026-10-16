
from typing import Any


CONFIDENCE_LEVELS = ("Low", "Medium", "High")


def assess_confidence(finding: dict[str, Any]) -> str:
    """Estimate confidence from the available detection evidence."""

    matched = finding.get("matched", [])
    evidence = finding.get("evidence", "")
    status = finding.get("status")

    if not isinstance(matched, list):
        matched = []

    valid_matches = [
        item for item in matched
        if isinstance(item, str) and item.strip()
    ]

    has_evidence = (
        isinstance(evidence, str)
        and bool(evidence.strip())
    )

    if len(valid_matches) >= 2 and has_evidence and status == 200:
        return "High"

    if valid_matches or has_evidence:
        return "Medium"

    return "Low"


def assess_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a finding with normalized confidence metadata."""

    assessed = dict(finding)
    assessed["confidence"] = assess_confidence(finding)
    assessed["evidence_count"] = len(
        [
            item for item in finding.get("matched", [])
            if isinstance(item, str) and item.strip()
        ]
    )
    return assessed

