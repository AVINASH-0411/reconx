
from unittest.mock import Mock, patch

import pytest
import requests

from reconx.modules.lfi import (
    build_test_url,
    detect_file_evidence,
    detect_parameters,
    generate_traversal_paths,
    required_evidence_matches,
    test_lfi as run_lfi_test,
)


def test_generate_traversal_paths():
    paths = generate_traversal_paths("/etc/passwd")

    assert paths == [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
    ]


def test_detect_passwd_evidence():
    evidence = detect_file_evidence(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    )

    assert "root:x:0:0:" in evidence
    assert "daemon:x:1:1:" in evidence


def test_detect_hostname_evidence():
    assert detect_file_evidence(
        "/etc/hostname",
        "localhost",
    ) == ["localhost"]


def test_detect_hosts_evidence():
    evidence = detect_file_evidence(
        "/etc/hosts",
        "127.0.0.1 localhost",
    )

    assert evidence == ["127.0.0.1", "localhost"]


def test_unrecognized_file_has_no_evidence():
    assert detect_file_evidence(
        "/unknown/file",
        "ordinary page content",
    ) == []


def test_required_evidence_counts():
    assert required_evidence_matches("/etc/passwd") == 2
    assert required_evidence_matches("/etc/hosts") == 2
    assert required_evidence_matches("/etc/hostname") == 1
    assert required_evidence_matches("/unknown/file") == 1


def test_detect_parameters():
    assert detect_parameters(
        "http://example.test/page?file=a&lang=en"
    ) == ["file", "lang"]


def test_build_test_url_replaces_parameter():
    result = build_test_url(
        "http://example.test/page?file=old&lang=en",
        "file",
        "../../etc/passwd",
    )

    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(result)
    parameters = parse_qs(parsed.query)

    assert parsed.scheme == "http"
    assert parsed.netloc == "example.test"
    assert parameters["file"] == ["../../etc/passwd"]
    assert parameters["lang"] == ["en"]


def test_test_lfi_rejects_url_without_parameters():
    with pytest.raises(ValueError, match="No query parameters"):
        run_lfi_test("http://example.test/page")


@patch("reconx.modules.lfi.requests.get")
def test_test_lfi_ignores_request_errors(mock_get):
    mock_get.side_effect = requests.ConnectionError(
        "connection failed"
    )

    findings = run_lfi_test(
        "http://example.test/page?file=test"
    )

    assert findings == []
    assert mock_get.called


@patch("reconx.modules.lfi.requests.get")
def test_test_lfi_detects_passwd_evidence(mock_get):
    response = Mock()
    response.status_code = 200
    response.text = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    )
    mock_get.return_value = response

    findings = run_lfi_test(
        "http://example.test/page?file=test"
    )

    assert len(findings) == 1
    assert findings[0]["parameter"] == "file"
    assert findings[0]["candidate"] == "/etc/passwd"
    assert findings[0]["status"] == 200
    assert len(findings[0]["matched"]) >= 2
    assert findings[0]["confidence"] == "High"
    assert findings[0]["evidence_count"] >= 2


@patch("reconx.modules.lfi.requests.get")
def test_test_lfi_ignores_ordinary_page_content(mock_get):
    response = Mock()
    response.status_code = 200
    response.text = "Welcome to the website"
    mock_get.return_value = response

    findings = run_lfi_test(
        "http://example.test/page?file=test"
    )

    assert findings == []
