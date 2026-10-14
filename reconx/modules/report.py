
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _validate_report(
    results: dict[str, Any],
    output: str,
    extension: str,
) -> Path:
    """Validate report data and output path."""

    if not output or not output.strip():
        raise ValueError("Output path cannot be empty.")

    if not isinstance(results, dict):
        raise ValueError("Results must be a dictionary.")

    output_path = Path(output).expanduser()

    if output_path.exists() and output_path.is_dir():
        raise ValueError("Output path points to a directory, not a file.")

    if output_path.suffix.lower() != extension:
        raise ValueError(f"Report filename must end with {extension}.")

    return output_path


def save_json_report(
    target: str,
    scan_type: str,
    results: dict[str, Any],
    output: str = "reconx-report.json",
) -> str:
    """Save scan results as a JSON report."""

    output_path = _validate_report(results, output, ".json")

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
        raise OSError(
            f"Unable to write report '{output_path}': {error}"
        ) from error

    return str(output_path)


def save_csv_report(
    target: str,
    scan_type: str,
    results: dict[str, Any],
    output: str = "reconx-report.csv",
) -> str:
    """Save scan results as a CSV report."""

    output_path = _validate_report(results, output, ".csv")

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open(
            "w", newline="", encoding="utf-8"
        ) as report_file:
            writer = csv.writer(report_file)
            writer.writerow(
                ["target", "scan_type", "generated_at", "result_key", "result_value"]
            )

            generated_at = datetime.now(timezone.utc).isoformat()

            for key, value in results.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)

                writer.writerow(
                    [target, scan_type, generated_at, key, value]
                )

    except OSError as error:
        raise OSError(
            f"Unable to write report '{output_path}': {error}"
        ) from error

    return str(output_path)

