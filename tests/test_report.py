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
