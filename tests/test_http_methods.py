
import pytest
import requests

from reconx.modules.http_methods import detect_http_methods


def test_rejects_empty_target():
    with pytest.raises(ValueError):
        detect_http_methods("")


def test_rejects_invalid_url():
    with pytest.raises(ValueError):
        detect_http_methods("ftp://example.com")


def test_rejects_url_with_credentials():
    with pytest.raises(ValueError):
        detect_http_methods("https://user:pass@example.com")


def test_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        detect_http_methods("https://example.com", timeout=0)


def test_rejects_boolean_timeout():
    with pytest.raises(ValueError):
        detect_http_methods("https://example.com", timeout=True)


def test_detects_advertised_methods(monkeypatch):
    class FakeResponse:
        status_code = 200
        headers = {
            "Allow": "GET, HEAD, POST, PUT, DELETE"
        }

    def fake_options(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        "reconx.modules.http_methods.requests.options",
        fake_options,
    )

    result = detect_http_methods("https://example.com")

    assert result["status_code"] == 200
    assert result["advertised_methods"] == [
        "DELETE", "GET", "HEAD", "POST", "PUT"
    ]
    assert result["potentially_risky_methods"] == [
        "DELETE", "PUT"
    ]
    assert result["method_detection"] == "advertised"


def test_handles_missing_allow_header(monkeypatch):
    class FakeResponse:
        status_code = 405
        headers = {}

    monkeypatch.setattr(
        "reconx.modules.http_methods.requests.options",
        lambda *args, **kwargs: FakeResponse(),
    )

    result = detect_http_methods("https://example.com")

    assert result["advertised_methods"] == []
    assert result["method_detection"] == "not_disclosed"


def test_handles_request_failure(monkeypatch):
    def fake_options(*args, **kwargs):
        raise requests.ConnectionError("Connection failed")

    monkeypatch.setattr(
        "reconx.modules.http_methods.requests.options",
        fake_options,
    )

    with pytest.raises(ValueError, match="HTTP method detection failed"):
        detect_http_methods("https://example.com")
