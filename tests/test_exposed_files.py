
from unittest.mock import Mock, patch

import pytest

from reconx.modules.exposed_files import (
    check_file_evidence,
    detect_exposed_files,
)


def test_detects_env_file_evidence():
    content = b"DB_PASSWORD=example\nSECRET_KEY=example"

    evidence = check_file_evidence("/.env", content)

    assert "DB_PASSWORD" in evidence
    assert "SECRET_KEY" in evidence


def test_ignores_unrelated_env_content():
    content = b"APP_NAME=MyApplication"

    evidence = check_file_evidence("/.env", content)

    assert evidence == []


def test_detects_git_head_evidence():
    content = b"ref: refs/heads/main"

    evidence = check_file_evidence("/.git/HEAD", content)

    assert evidence == ["ref: refs/"]


def test_detects_backup_zip_signature():
    content = b"PK\x03\x04example archive data"

    evidence = check_file_evidence("/backup.zip", content)

    assert evidence == ["ZIP archive signature"]


def test_ignores_invalid_backup_zip():
    content = b"This is not a ZIP archive"

    evidence = check_file_evidence("/backup.zip", content)

    assert evidence == []


def test_detect_exposed_files_rejects_invalid_target():
    with pytest.raises(ValueError, match="Target must start"):
        detect_exposed_files("127.0.0.1")



@patch("reconx.modules.exposed_files.requests.get")
def test_detect_exposed_files_returns_normalized_finding(mock_get):
    def mock_response_for_url(url, **kwargs):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/plain"}
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)

        if url.endswith("/.env"):
            response.raw.read.return_value = (
                b"DB_PASSWORD=example\nSECRET_KEY=example"
            )
        else:
            response.raw.read.return_value = b"ordinary page content"

        return response

    mock_get.side_effect = mock_response_for_url

    findings = detect_exposed_files("http://example.test")

    assert len(findings) == 1
    assert findings[0]["path"] == "/.env"
    assert findings[0]["type"] == "exposed_file"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["confidence"] == "High"
    assert findings[0]["evidence_count"] == 2
    assert findings[0]["remediation"]

@patch("reconx.modules.exposed_files.requests.get")
def test_detect_exposed_files_ignores_non_200_responses(mock_get):
    response = Mock()
    response.status_code = 404
    response.headers = {}
    mock_get.return_value.__enter__.return_value = response

    findings = detect_exposed_files("http://example.test")

    assert findings == []
