
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
