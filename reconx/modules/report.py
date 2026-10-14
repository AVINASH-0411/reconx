
import json
import re
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

    if not output or not output.strip():
        raise ValueError("Output path cannot be empty.")

    if not isinstance(results, dict):
        raise ValueError("Results must be a dictionary.")

    # Keep the requested path, but reject paths that point to a directory.
    output_path = Path(output).expanduser()

    if output_path.exists() and output_path.is_dir():
        raise ValueError("Output path points to a directory, not a file.")

    if output_path.suffix.lower() != ".json":
        raise ValueError("Report filename must end with .json.")

    report = {
        "tool": "ReconX",
        "report_version": "1.0",
        "target": target,
        "scan_type": scan_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4, ensure_ascii=False)
            report_file.write("\n")

    except OSError as error:
        raise OSError(f"Unable to write report '{output_path}': {error}") from error

    return str(output_path)
