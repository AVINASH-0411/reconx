from reconx.modules.finding_assessment import (
    assess_confidence,
    assess_finding,
    normalize_finding,
)

def test_invalid_severity_defaults_to_info():
    result = normalize_finding(
        {"evidence": []},
        finding_type="exposed_file",
        severity="CRITICAL",
    )

    assert result["severity"] == "INFO"


def test_normalize_finding_preserves_existing_confidence():
    finding = {
        "status": 200,
        "evidence": ["DB_PASSWORD"],
        "confidence": "Low",
    }

    result = normalize_finding(
        finding,
        finding_type="exposed_file",
    )

    assert result["confidence"] == "Low"


def test_non_string_evidence_is_ignored():
    finding = {
        "status": 200,
        "evidence": [None, 123, ""],
    }

    result = normalize_finding(
        finding,
        finding_type="exposed_file",
    )

    assert result["confidence"] == "Low"
    assert result["evidence_count"] == 0

def test_high_confidence_with_multiple_evidence_items():
    finding = {
        "status": 200,
        "evidence": ["DB_PASSWORD", "SECRET_KEY"],
    }

    assert assess_confidence(finding) == "High"


def test_medium_confidence_with_one_evidence_item():
    finding = {
        "status": 200,
        "evidence": ["DB_PASSWORD"],
    }

    assert assess_confidence(finding) == "Medium"


def test_low_confidence_without_evidence():
    finding = {
        "status": 404,
        "evidence": [],
    }

    assert assess_confidence(finding) == "Low"


def test_normalize_finding_adds_metadata():
    finding = {
        "path": "/.env",
        "status": 200,
        "evidence": ["DB_PASSWORD"],
    }

    result = normalize_finding(
        finding,
        finding_type="exposed_file",
        severity="MEDIUM",
        remediation="Restrict access to sensitive files.",
    )

    assert result["type"] == "exposed_file"
    assert result["severity"] == "MEDIUM"
    assert result["confidence"] == "Medium"
    assert result["evidence_count"] == 1
    assert result["remediation"] == (
        "Restrict access to sensitive files."
    )


def test_normalize_finding_preserves_original_fields():
    finding = {
        "path": "/.env",
        "status": 200,
        "evidence": ["DB_PASSWORD"],
    }

    result = normalize_finding(
        finding,
        finding_type="exposed_file",
    )

    assert result["path"] == "/.env"
    assert result["status"] == 200
    assert "path" not in finding or finding["path"] == "/.env"

def test_assess_confidence_with_evidence_but_no_status():
    finding = {"evidence": ["DB_PASSWORD", "SECRET_KEY"]}

    assert assess_confidence(finding) == "Medium"


def test_assess_confidence_ignores_invalid_evidence():
    finding = {
        "matched": ["", None, 123],
        "evidence": ["", None, 456],
        "status": 200,
    }

    assert assess_confidence(finding) == "Low"


def test_assess_finding_counts_matched_and_evidence_items():
    finding = {
        "matched": ["DB_PASSWORD", "SECRET_KEY"],
        "evidence": ["credentials found"],
        "status": 200,
    }

    assessed = assess_finding(finding)

    assert assessed["confidence"] == "High"
    assert assessed["evidence_count"] == 3

def test_duplicate_evidence_does_not_inflate_confidence():
    finding = {
        "status": 200,
        "evidence": ["DB_PASSWORD", "DB_PASSWORD"],
    }

    assert assess_confidence(finding) == "Medium"
