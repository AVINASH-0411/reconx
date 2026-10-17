
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
