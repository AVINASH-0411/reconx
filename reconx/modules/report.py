import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def save_json_report(
    target: str,
    scan_type: str,
    results: dict[str, Any],
    output: str = "reconx-report.json",
) -> str:
    """Save scan results as a JSON report."""

    report = {
        "tool": "ReconX",
        "report_version": "1.0",
        "target": target,
        "scan_type": scan_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4, ensure_ascii=False)
        report_file.write("\n")

    return str(output_path)

