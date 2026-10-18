
import sys
from unittest.mock import patch

import pytest

from reconx.main import cli, parse_ports, show_help


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_multiple_and_sorted():
    assert parse_ports("443, 22,80,22") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("80-83") == [80, 81, 82, 83]


@pytest.mark.parametrize(
    "port_spec",
    ["", "80,,443", "0", "65536", "-1"],
)
def test_parse_ports_invalid(port_spec):
    with pytest.raises(ValueError):
        parse_ports(port_spec)

@pytest.mark.parametrize(
    "port_spec",
    ["abc-xyz", "80-", "abc-80", "80-xyz"],
)
def test_parse_ports_malformed_ranges(port_spec):
    with pytest.raises(ValueError):
        parse_ports(port_spec)

def test_parse_ports_reversed_range():
    with pytest.raises(
        ValueError,
        match="Port range start cannot be greater than end",
    ):
        parse_ports("90-80")


def test_parse_ports_non_numeric():
    with pytest.raises(ValueError):
        parse_ports("abc")


def test_show_help(capsys):
    show_help()
    output = capsys.readouterr().out
    assert "Usage: reconx" in output
    assert "--version" in output
    assert "--help" in output


def test_cli_no_arguments(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reconx"])
    cli()
    assert "Usage: reconx" in capsys.readouterr().out


@pytest.mark.parametrize("option", ["--help", "-h"])
def test_cli_help_options(monkeypatch, capsys, option):
    monkeypatch.setattr(sys, "argv", ["reconx", option])
    cli()
    assert "Usage: reconx" in capsys.readouterr().out


@pytest.mark.parametrize("option", ["--version", "-v"])
def test_cli_version(monkeypatch, capsys, option):
    monkeypatch.setattr(sys, "argv", ["reconx", option])
    cli()
    assert "ReconX version 0.1.0" in capsys.readouterr().out


def test_cli_web_routes_to_analysis(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["reconx", "web", "http://example.test"])
    with patch("reconx.main.run_web_analysis") as mock_run:
        cli()
    mock_run.assert_called_once_with("http://example.test", None)


def test_cli_web_output_option(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", "web", "http://example.test", "-o", "report.json"],
    )
    with patch("reconx.main.run_web_analysis") as mock_run:
        cli()
    mock_run.assert_called_once_with(
        "http://example.test",
        "report.json",
    )


def test_cli_web_missing_target(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reconx", "web"])
    cli()
    assert "Usage: reconx web" in capsys.readouterr().out


def test_cli_web_invalid_arguments(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", "web", "http://example.test", "--bad"],
    )
    cli()
    assert "Error: invalid web arguments." in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "function_name"),
    [
        ("lfi", "run_lfi"),
        ("files", "run_exposed_files"),
    ],
)
def test_cli_lfi_and_files_routes(monkeypatch, command, function_name):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", command, "http://example.test"],
    )
    with patch(f"reconx.main.{function_name}") as mock_run:
        cli()
    mock_run.assert_called_once_with("http://example.test", None)


def test_cli_lfi_missing_target(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reconx", "lfi"])
    cli()
    assert "Usage: reconx lfi" in capsys.readouterr().out


def test_cli_lfi_invalid_arguments(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", "lfi", "http://example.test", "--bad"],
    )
    cli()
    assert "Error: invalid arguments." in capsys.readouterr().out


def test_cli_routes_to_port_scan(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", "http://example.test", "-p", "80,443"],
    )
    with patch("reconx.main.run_scan") as mock_run:
        cli()
    mock_run.assert_called_once_with(
        "http://example.test",
        "80,443",
        None,
    )


def test_cli_routes_to_aggregate_scan(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", "http://example.test", "-a"],
    )
    with patch("reconx.main.run_aggregate_scan") as mock_run:
        cli()
    mock_run.assert_called_once_with(
        "http://example.test",
        "1-1000",
        None,
    )


def test_cli_invalid_option(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["reconx", "http://example.test", "--bad"],
    )
    cli()
    assert "Error: invalid or incomplete option" in capsys.readouterr().out


@patch("reconx.main.scan_ports")
@patch("reconx.main.detect_service")
@patch("reconx.main.write_report")
def test_run_scan_with_open_ports(
    mock_report,
    mock_detect,
    mock_scan,
    capsys,
):
    from reconx.main import run_scan

    mock_scan.return_value = [22, 80]
    mock_detect.side_effect = ["SSH", "HTTP"]

    run_scan("127.0.0.1", "22,80", "report.json")

    output = capsys.readouterr().out
    assert "Scanning 127.0.0.1..." in output
    assert "Open ports found    : 2" in output
    assert "22" in output
    assert "80" in output

    mock_scan.assert_called_once_with(
        "127.0.0.1",
        [22, 80],
    )
    mock_detect.assert_any_call("127.0.0.1", 22)
    mock_detect.assert_any_call("127.0.0.1", 80)
    mock_report.assert_called_once()


@patch("reconx.main.scan_ports")
@patch("reconx.main.write_report")
def test_run_scan_with_no_open_ports(
    mock_report,
    mock_scan,
    capsys,
):
    from reconx.main import run_scan

    mock_scan.return_value = []

    run_scan("127.0.0.1", "80,443")

    output = capsys.readouterr().out
    assert "No open TCP ports found." in output
    assert "Open ports found    : 0" in output
    assert "Closed/filtered     : 2" in output

    mock_report.assert_called_once()


@patch("reconx.main.scan_ports")
def test_run_scan_invalid_ports(mock_scan, capsys):
    from reconx.main import run_scan

    run_scan("127.0.0.1", "invalid")

    output = capsys.readouterr().out
    assert "Port scan error:" in output
    mock_scan.assert_not_called()


@patch("reconx.main.scan_ports")
def test_run_scan_handles_scan_error(mock_scan, capsys):
    from reconx.main import run_scan

    mock_scan.side_effect = OSError("connection failed")

    run_scan("127.0.0.1", "22")

    assert "Port scan error: connection failed" in capsys.readouterr().out


@patch("reconx.main.scan_ports")
@patch("reconx.main.detect_service")
@patch("reconx.main.write_report")
def test_run_scan_report_contents(
    mock_report,
    mock_detect,
    mock_scan,
):
    from reconx.main import run_scan

    mock_scan.return_value = [443]
    mock_detect.return_value = "HTTPS"

    run_scan("127.0.0.1", "443", "output.csv")

    args = mock_report.call_args.args
    assert args[0] == "127.0.0.1"
    assert args[1] == "tcp_port_scan"
    assert args[2]["ports_scanned"] == 1
    assert args[2]["open_ports"][0]["service"] == "HTTPS"
    assert args[2]["summary"]["open_ports_count"] == 1
    assert args[3] == "output.csv"


@patch("reconx.main.save_json_report")
def test_write_report_json(mock_save, capsys):
    from reconx.main import write_report

    mock_save.return_value = "results.json"
    results = {"open_ports": []}

    write_report("127.0.0.1", "tcp_port_scan", results, "results.json")

    mock_save.assert_called_once_with(
        "127.0.0.1",
        "tcp_port_scan",
        results,
        "results.json",
    )
    assert "JSON report saved: results.json" in capsys.readouterr().out


@patch("reconx.main.save_csv_report")
def test_write_report_csv(mock_save, capsys):
    from reconx.main import write_report

    mock_save.return_value = "results.csv"
    results = {"open_ports": []}

    write_report("127.0.0.1", "tcp_port_scan", results, "results.csv")

    mock_save.assert_called_once_with(
        "127.0.0.1",
        "tcp_port_scan",
        results,
        "results.csv",
    )
    assert "CSV report saved: results.csv" in capsys.readouterr().out


@patch("reconx.main.save_json_report")
def test_write_report_accepts_uppercase_extension(mock_save, capsys):
    from reconx.main import write_report

    mock_save.return_value = "RESULTS.JSON"

    write_report("127.0.0.1", "scan", {}, "RESULTS.JSON")

    mock_save.assert_called_once()
    assert "JSON report saved: RESULTS.JSON" in capsys.readouterr().out


def test_write_report_without_output_does_nothing():
    from reconx.main import write_report

    with (
        patch("reconx.main.save_json_report") as mock_json,
        patch("reconx.main.save_csv_report") as mock_csv,
    ):
        write_report("127.0.0.1", "scan", {}, None)
        write_report("127.0.0.1", "scan", {}, "")

    mock_json.assert_not_called()
    mock_csv.assert_not_called()


def test_write_report_rejects_unsupported_extension(capsys):
    from reconx.main import write_report

    write_report("127.0.0.1", "scan", {}, "results.txt")

    assert "Report filename must end with .json or .csv." in (
        capsys.readouterr().out
    )


@pytest.mark.parametrize(
    "error",
    [
        OSError("disk error"),
        ValueError("invalid report data"),
        TypeError("unsupported report data"),
    ],
)
@patch("reconx.main.save_json_report")
def test_write_report_handles_save_errors(
    mock_save,
    error,
    capsys,
):
    from reconx.main import write_report

    mock_save.side_effect = error

    write_report("127.0.0.1", "scan", {}, "results.json")

    assert f"Could not save report: {error}" in capsys.readouterr().out

@patch("reconx.main.write_report")
@patch("reconx.main.analyze_http")
def test_run_web_analysis_success(mock_analyze, mock_report, capsys):
    from reconx.main import run_web_analysis

    mock_analyze.return_value = {
        "status_code": 200,
        "title": "Test Page",
        "server": "N/A",
        "content_type": "text/html",
        "content_length": 100,
        "redirects": [],
        "https": True,
        "response_time": 0.125,
        "final_url": "https://example.com",
        "security_headers": {
            "CSP": True,
            "X-Frame-Options": True,
            "X-Content-Type-Options": True,
            "HSTS": True,
            "Referrer-Policy": True,
            "Permissions-Policy": True,
        },
    }

    run_web_analysis("https://example.com", "web.json")

    output = capsys.readouterr().out
    assert "ReconX HTTP Analyzer" in output
    assert "Status Code      : 200" in output
    assert "Page Title       : Test Page" in output
    assert "HTTPS            : Yes" in output
    assert "No obvious HTTP security issues detected" in output
    assert "HTTP analysis completed." in output

    mock_analyze.assert_called_once_with("https://example.com")
    mock_report.assert_called_once_with(
        "https://example.com",
        "http_analysis",
        mock_analyze.return_value,
        "web.json",
    )


@pytest.mark.parametrize(
    "error",
    [
        ValueError("invalid target"),
        OSError("connection failed"),
    ],
)
@patch("reconx.main.analyze_http")
def test_run_web_analysis_handles_errors(mock_analyze, error, capsys):
    from reconx.main import run_web_analysis

    mock_analyze.side_effect = error

    run_web_analysis("https://example.com")

    output = capsys.readouterr().out
    assert f"[!] HTTP Error: {error}" in output


@patch("reconx.main.write_report")
@patch("reconx.main.analyze_http")
def test_run_web_analysis_reports_security_observations(
    mock_analyze,
    mock_report,
    capsys,
):
    from reconx.main import run_web_analysis

    mock_analyze.return_value = {
        "status_code": 200,
        "title": "Insecure Test",
        "server": "Apache",
        "content_type": "text/html",
        "content_length": 100,
        "redirects": [],
        "https": False,
        "response_time": 0.5,
        "final_url": "http://example.com",
        "security_headers": {
            "CSP": False,
            "X-Frame-Options": False,
            "X-Content-Type-Options": False,
            "HSTS": False,
            "Referrer-Policy": False,
            "Permissions-Policy": False,
        },
    }

    run_web_analysis("http://example.com")

    output = capsys.readouterr().out
    assert "HTTPS is not enabled" in output
    assert "Content-Security-Policy is missing" in output
    assert "X-Frame-Options is missing" in output
    assert "Server information is disclosed" in output
    mock_report.assert_called_once()


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.test_lfi")
def test_run_lfi_with_findings(
    mock_test_lfi,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_lfi

    finding = {
        "parameter": "file",
        "candidate": "/etc/passwd",
        "traversal": "../../../../etc/passwd",
        "status": 200,
        "evidence": "root:x:0:0",
        "matched": ["root:"],
        "confidence": "high",
    }
    mock_test_lfi.return_value = [finding]
    mock_summary.return_value = {"High": 1}

    run_lfi("http://example.com", "lfi.json")

    output = capsys.readouterr().out
    assert "ReconX LFI Detector" in output
    assert "Possible LFI detected" in output
    assert "Parameter  : file" in output
    assert "Candidate  : /etc/passwd" in output
    assert "LFI findings : 1" in output
    assert "LFI analysis completed." in output

    mock_test_lfi.assert_called_once_with("http://example.com")
    mock_summary.assert_called_once_with([{"type": "lfi", **finding}])
    mock_report.assert_called_once_with(
        "http://example.com",
        "lfi_detection",
        {
            "findings": [finding],
            "finding_count": 1,
            "summary": {
                "total_findings": 1,
                "severity_counts": {"High": 1},
            },
        },
        "lfi.json",
    )


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.test_lfi")
def test_run_lfi_with_no_findings(
    mock_test_lfi,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_lfi

    mock_test_lfi.return_value = []
    mock_summary.return_value = {}

    run_lfi("http://example.com")

    output = capsys.readouterr().out
    assert "No convincing LFI evidence found." in output
    assert "LFI findings : 0" in output
    mock_summary.assert_called_once_with([])
    mock_report.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [
        ValueError("invalid target"),
        OSError("connection failed"),
    ],
)
@patch("reconx.main.test_lfi")
def test_run_lfi_handles_errors(mock_test_lfi, error, capsys):
    from reconx.main import run_lfi

    mock_test_lfi.side_effect = error

    run_lfi("http://example.com")

    assert f"[!] LFI Error: {error}" in capsys.readouterr().out


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.scan_directories")
def test_run_directory_scan_with_findings(
    mock_scan,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_directory_scan

    findings = [
        {
            "path": "/admin",
            "status": 200,
            "size": 512,
            "severity": "Medium",
        }
    ]
    mock_scan.return_value = findings
    mock_summary.return_value = {"Medium": 1}

    run_directory_scan(
        "http://example.com",
        "wordlist.txt",
        10,
        "php,html",
        "200,403",
        "directory.json",
    )

    output = capsys.readouterr().out
    assert "ReconX Directory Scanner" in output
    assert "[200] /admin (512 bytes)" in output
    assert "Directory findings : 1" in output
    assert "Directory scan completed. Findings: 1" in output

    mock_scan.assert_called_once_with(
        target="http://example.com",
        wordlist="wordlist.txt",
        threads=10,
        extensions="php,html",
        status_codes="200,403",
    )
    mock_summary.assert_called_once_with(findings)
    mock_report.assert_called_once_with(
        "http://example.com",
        "directory_scan",
        {
            "findings": findings,
            "finding_count": 1,
            "summary": {
                "total_findings": 1,
                "severity_counts": {"Medium": 1},
            },
        },
        "directory.json",
    )


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.scan_directories")
def test_run_directory_scan_with_no_findings(
    mock_scan,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_directory_scan

    mock_scan.return_value = []
    mock_summary.return_value = {}

    run_directory_scan(
        "http://example.com",
        "wordlist.txt",
        5,
        None,
        None,
    )

    output = capsys.readouterr().out
    assert "No matching paths discovered." in output
    assert "Directory findings : 0" in output
    assert "Directory scan completed. Findings: 0" in output
    mock_summary.assert_called_once_with([])
    mock_report.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [
        ValueError("invalid scan options"),
        OSError("wordlist unavailable"),
    ],
)
@patch("reconx.main.scan_directories")
def test_run_directory_scan_handles_errors(
    mock_scan,
    error,
    capsys,
):
    from reconx.main import run_directory_scan

    mock_scan.side_effect = error

    run_directory_scan(
        "http://example.com",
        "wordlist.txt",
        5,
        None,
        None,
    )

    assert f"[!] Directory Scan Error: {error}" in (
        capsys.readouterr().out
    )


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.detect_exposed_files")
def test_run_exposed_files_with_findings(
    mock_detect,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_exposed_files

    findings = [
        {
            "path": "/.env",
            "url": "http://example.com/.env",
            "status": 200,
            "content_type": "text/plain",
            "evidence": ["APP_KEY=", "DB_HOST="],
            "severity": "High",
        }
    ]
    mock_detect.return_value = findings
    mock_summary.return_value = {"High": 1}

    run_exposed_files("http://example.com", "files.json")

    output = capsys.readouterr().out
    assert "ReconX Exposed File Detection" in output
    assert "Possible exposed file detected" in output
    assert "Path         : /.env" in output
    assert "APP_KEY=, DB_HOST=" in output
    assert "Exposed-file findings: 1" in output
    assert "Exposed-file analysis completed." in output

    mock_detect.assert_called_once_with("http://example.com")
    mock_summary.assert_called_once_with(
        [{"type": "exposed_file", **findings[0]}]
    )
    mock_report.assert_called_once_with(
        "http://example.com",
        "exposed_file_detection",
        {
            "findings": findings,
            "finding_count": 1,
            "summary": {
                "total_findings": 1,
                "severity_counts": {"High": 1},
            },
        },
        "files.json",
    )


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.detect_exposed_files")
def test_run_exposed_files_with_no_findings(
    mock_detect,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_exposed_files

    mock_detect.return_value = []
    mock_summary.return_value = {}

    run_exposed_files("http://example.com")

    output = capsys.readouterr().out
    assert "No convincing exposed-file evidence found." in output
    assert "Exposed-file findings: 0" in output
    mock_summary.assert_called_once_with([])
    mock_report.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [
        ValueError("invalid target"),
        OSError("connection failed"),
    ],
)
@patch("reconx.main.detect_exposed_files")
def test_run_exposed_files_handles_errors(
    mock_detect,
    error,
    capsys,
):
    from reconx.main import run_exposed_files

    mock_detect.side_effect = error

    run_exposed_files("http://example.com")

    assert f"[!] Exposed File Error: {error}" in (
        capsys.readouterr().out
    )


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.scan_ports")
def test_run_aggregate_scan_with_no_open_ports(
    mock_scan,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_aggregate_scan

    mock_scan.return_value = []
    mock_summary.return_value = {}

    run_aggregate_scan("127.0.0.1", "80,443", "aggregate.json")

    output = capsys.readouterr().out
    assert "ReconX Aggregate Scan" in output
    assert "No open TCP ports found." in output
    assert "Open ports found    : 0" in output
    assert "Aggregate scan completed." in output

    mock_scan.assert_called_once_with("127.0.0.1", [80, 443])
    mock_summary.assert_called_once_with([])
    mock_report.assert_called_once()
    assert mock_report.call_args.args[1] == "aggregate_scan"


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.detect_exposed_files")
@patch("reconx.main.analyze_http")
@patch("reconx.main.detect_service")
@patch("reconx.main.scan_ports")
def test_run_aggregate_scan_with_web_port(
    mock_scan,
    mock_service,
    mock_http,
    mock_exposed,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_aggregate_scan

    mock_scan.return_value = [80]
    mock_service.return_value = "http"
    mock_http.return_value = {
        "status_code": 200,
        "title": "Test",
        "https": False,
    }
    mock_exposed.return_value = []
    mock_summary.return_value = {}

    run_aggregate_scan("127.0.0.1", "80")

    output = capsys.readouterr().out
    assert "80/tcp open http" in output
    assert "HTTP Analysis: http://127.0.0.1:80" in output
    assert "Exposed File Detection: http://127.0.0.1:80" in output
    assert "HTTP targets analyzed: 1" in output
    assert "Aggregate scan completed." in output

    mock_http.assert_called_once_with("http://127.0.0.1:80")
    mock_exposed.assert_called_once_with("http://127.0.0.1:80")
    mock_report.assert_called_once()
    assert mock_report.call_args.args[1] == "aggregate_scan"


@pytest.mark.parametrize(
    "error",
    [
        ValueError("invalid port specification"),
        OSError("scan failed"),
    ],
)
@patch("reconx.main.scan_ports")
def test_run_aggregate_scan_handles_port_errors(
    mock_scan,
    error,
    capsys,
):
    from reconx.main import run_aggregate_scan

    mock_scan.side_effect = error

    run_aggregate_scan("127.0.0.1", "80")

    assert f"[!] Port scan error: {error}" in capsys.readouterr().out


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.analyze_http")
@patch("reconx.main.detect_service")
@patch("reconx.main.scan_ports")
def test_run_aggregate_scan_handles_http_error(
    mock_scan,
    mock_service,
    mock_http,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_aggregate_scan

    mock_scan.return_value = [80]
    mock_service.return_value = "http"
    mock_http.side_effect = OSError("HTTP unavailable")
    mock_summary.return_value = {}

    run_aggregate_scan("127.0.0.1", "80")

    output = capsys.readouterr().out
    assert "HTTP analysis skipped: HTTP unavailable" in output
    assert "Aggregate scan completed." in output
    mock_report.assert_called_once()

@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.detect_exposed_files")
@patch("reconx.main.analyze_http")
@patch("reconx.main.detect_service")
@patch("reconx.main.scan_ports")
def test_run_aggregate_scan_handles_service_error(
    mock_scan,
    mock_service,
    mock_http,
    mock_exposed,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_aggregate_scan

    mock_scan.return_value = [80, 443]
    mock_service.side_effect = [
        OSError("service detection failed"),
        "HTTPS",
    ]
    mock_http.return_value = {
        "status_code": 200,
        "title": "Test",
        "https": True,
    }
    mock_exposed.return_value = []
    mock_summary.return_value = {}

    run_aggregate_scan("127.0.0.1", "80,443")

    output = capsys.readouterr().out

    assert "service detection failed" in output
    assert "443/tcp open HTTPS" in output
    assert "Aggregate scan completed." in output
    mock_http.assert_any_call("http://127.0.0.1:80")
    mock_http.assert_any_call("https://127.0.0.1:443")

@patch("reconx.main.scan_ports")
@patch("reconx.main.detect_service")
@patch("reconx.main.write_report")
def test_run_scan_handles_service_detection_error(
    mock_report,
    mock_detect,
    mock_scan,
    capsys,
):
    from reconx.main import run_scan

    mock_scan.return_value = [22, 80]
    mock_detect.side_effect = [
        OSError("service detection failed"),
        "HTTP",
    ]

    run_scan("127.0.0.1", "22,80", "report.json")

    output = capsys.readouterr().out

    assert "service detection failed" in output
    assert "22" in output
    assert "80" in output
    assert "Open ports found    : 2" in output

    mock_report.assert_called_once()
    report_data = mock_report.call_args.args[2]
    assert report_data["open_ports"][0]["service"] == "unknown"
    assert report_data["open_ports"][1]["service"] == "HTTP"


@patch("reconx.main.write_report")
@patch("reconx.main.summarize_severities")
@patch("reconx.main.detect_exposed_files")
@patch("reconx.main.analyze_http")
@patch("reconx.main.detect_service")
@patch("reconx.main.scan_ports")
def test_run_aggregate_scan_continues_after_http_error(
    mock_scan,
    mock_service,
    mock_http,
    mock_exposed,
    mock_summary,
    mock_report,
    capsys,
):
    from reconx.main import run_aggregate_scan

    mock_scan.return_value = [80, 443]
    mock_service.side_effect = ["HTTP", "HTTPS"]
    mock_http.side_effect = [
        OSError("HTTP unavailable"),
        {
            "status_code": 200,
            "title": "Secure test",
            "https": True,
        },
    ]
    mock_exposed.return_value = []
    mock_summary.return_value = {}

    run_aggregate_scan("127.0.0.1", "80,443")

    output = capsys.readouterr().out

    assert "HTTP analysis skipped: HTTP unavailable" in output
    assert "HTTP Analysis: https://127.0.0.1:443" in output
    assert "Aggregate scan completed." in output

    assert mock_http.call_count == 2
    mock_http.assert_any_call("http://127.0.0.1:80")
    mock_http.assert_any_call("https://127.0.0.1:443")
    mock_exposed.assert_called_once_with("https://127.0.0.1:443")
    mock_report.assert_called_once()
