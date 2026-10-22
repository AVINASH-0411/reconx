import csv
import json

import pytest

from reconx.modules.report import (
    save_csv_report,
    save_json_report,
)


def test_json_report_is_valid(tmp_path):
    output = tmp_path / "report.json"
    results = {"finding_count": 1, "findings": []}

    save_json_report(
        "http://localhost",
        "exposed_files",
        results,
        str(output),
    )

    report = json.loads(output.read_text())

    assert report["tool"] == "ReconX"
    assert report["target"] == "http://localhost"
    assert report["results"]["finding_count"] == 1


def test_csv_report_is_valid(tmp_path):
    output = tmp_path / "report.csv"
    results = {"finding_count": 1}

    save_csv_report(
        "http://localhost",
        "exposed_files",
        results,
        str(output),
    )

    with output.open(newline="", encoding="utf-8") as file:
        rows = list(csv.reader(file))

    assert rows[0] == [
        "target",
        "scan_type",
        "generated_at",
        "result_key",
        "result_value",
    ]
    assert rows[1][0] == "http://localhost"
    assert rows[1][3:] == ["finding_count", "1"]


def test_json_report_rejects_wrong_extension(tmp_path):
    output = tmp_path / "report.txt"

    with pytest.raises(ValueError, match="must end with .json"):
        save_json_report(
            "http://localhost",
            "test",
            {},
            str(output),
        )


def test_csv_report_rejects_directory(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        save_csv_report(
            "http://localhost",
            "test",
            {},
            str(tmp_path),
        )

def test_json_report_preserves_findings_and_summary(tmp_path):
    output = tmp_path / "report.json"

    findings = [
        {
            "type": "exposed_file",
            "severity": "MEDIUM",
            "path": "/.env",
            "confidence": "High",
            "remediation": "Restrict public access.",
        }
    ]
    summary = {
        "total_findings": 1,
        "severity_counts": {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 0,
        },
    }
    results = {
        "findings": findings,
        "finding_count": 1,
        "summary": summary,
    }

    save_json_report(
        "http://localhost",
        "exposed_file_detection",
        results,
        str(output),
    )

    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["results"]["findings"] == findings
    assert report["results"]["finding_count"] == 1
    assert report["results"]["summary"] == summary

def test_json_report_handles_empty_results(tmp_path):
    output = tmp_path / "empty-report.json"

    save_json_report(
        "http://localhost",
        "test",
        {},
        str(output),
    )

    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["results"] == {}
    assert report["tool"] == "ReconX"
    assert report["report_version"] == "1.0"

def test_json_report_preserves_unicode_and_nested_data(tmp_path):
    output = tmp_path / "unicode-report.json"
    results = {
        "findings": [
            {
                "path": "/café",
                "evidence": ["Sensitive file detected"],
            }
        ],
        "metadata": {
            "region": "Chennai",
            "checks": ["headers", "exposed_files"],
        },
    }

    save_json_report(
        "http://localhost",
        "test",
        results,
        str(output),
    )

    report_text = output.read_text(encoding="utf-8")
    report = json.loads(report_text)

    assert "café" in report_text
    assert "Sensitive file detected" in report_text
    assert report["results"] == results

def test_csv_report_preserves_nested_findings_and_special_characters(
    tmp_path,
):
    output = tmp_path / "special-report.csv"
    results = {
        "findings": [
            {
                "path": "/config,backup",
                "evidence": ['Found "sensitive" data'],
            }
        ]
    }

    save_csv_report(
        "http://localhost",
        "test",
        results,
        str(output),
    )

    with output.open(newline="", encoding="utf-8") as file:
        rows = list(csv.reader(file))

    assert rows[0] == [
        "target",
        "scan_type",
        "generated_at",
        "result_key",
        "result_value",
    ]

    findings_row = next(
        row for row in rows[1:] if row[3] == "findings"
    )
    exported_findings = json.loads(findings_row[4])

    assert exported_findings == results["findings"]

def test_json_report_rejects_unserializable_results(tmp_path):
    output = tmp_path / "invalid-report.json"
    results = {"invalid_value": object()}

    with pytest.raises(TypeError):
        save_json_report(
            "http://localhost",
            "test",
            results,
            str(output),
        )
