
from unittest.mock import Mock, patch

import pytest
import requests

from reconx.modules.http_analyzer import (
    analyze_http,
    analyze_security_headers,
    extract_title,
)


def test_extract_title():
    assert extract_title(
        "<html><title>  ReconX   Scanner </title></html>"
    ) == "ReconX Scanner"


def test_extract_title_is_case_insensitive():
    assert extract_title("<TITLE>ReconX</TITLE>") == "ReconX"


def test_extract_title_missing():
    assert extract_title("<html><body>No title</body></html>") == "N/A"


def test_analyze_security_headers():
    headers = requests.structures.CaseInsensitiveDict({
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Server": "ExampleServer",
    })

    result = analyze_security_headers(headers)

    assert result["CSP"] is True
    assert result["X-Frame-Options"] is True
    assert result["HSTS"] is False
    assert result["Permissions-Policy"] is False


def test_analyze_http_rejects_invalid_target():
    with pytest.raises(ValueError, match="Target must start"):
        analyze_http("example.test")


@patch("reconx.modules.http_analyzer.requests.get")
def test_analyze_http_returns_metadata(mock_get):
    response = Mock()
    response.status_code = 200
    response.text = "<html><title>ReconX</title></html>"
    response.content = response.text.encode()
    response.headers = requests.structures.CaseInsensitiveDict({
        "Server": "TestServer",
        "Content-Type": "text/html",
        "X-Frame-Options": "DENY",
    })
    response.history = []
    response.url = "https://example.test"
    mock_get.return_value = response

    result = analyze_http("https://example.test")

    assert result["status_code"] == 200
    assert result["title"] == "ReconX"
    assert result["server"] == "TestServer"
    assert result["content_type"] == "text/html"
    assert result["content_length"] == len(response.content)
    assert result["redirects"] == 0
    assert result["https"] is True
    assert result["final_url"] == "https://example.test"
    assert result["security_headers"]["X-Frame-Options"] is True
    assert result["response_time"] >= 0
    mock_get.assert_called_once_with(
        "https://example.test",
        timeout=5.0,
        allow_redirects=True,
    )


@patch("reconx.modules.http_analyzer.requests.get")
def test_analyze_http_wraps_request_errors(mock_get):
    mock_get.side_effect = requests.ConnectionError("connection failed")

    with pytest.raises(ValueError, match="HTTP request failed"):
        analyze_http("http://example.test")


@patch("reconx.modules.http_analyzer.requests.get")
def test_analyze_http_counts_redirects(mock_get):
    response = Mock()
    response.status_code = 200
    response.text = "<title>Final Page</title>"
    response.content = b"<title>Final Page</title>"
    response.headers = requests.structures.CaseInsensitiveDict({})
    response.history = [Mock(), Mock()]
    response.url = "https://example.test/final"
    mock_get.return_value = response

    result = analyze_http("http://example.test")

    assert result["redirects"] == 2
    assert result["https"] is True
    assert result["final_url"] == "https://example.test/final"

