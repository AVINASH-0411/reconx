
from unittest.mock import Mock, patch

import pytest
import requests

from reconx.modules.dirscan import (
    DEFAULT_STATUS_CODES,
    expand_paths,
    load_wordlist,
    normalize_target,
    parse_extensions,
    parse_status_codes,
    scan_directories,
    scan_single_path,
)


def test_load_wordlist_normalizes_paths(tmp_path):
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text(
        "admin\n/login\n\n# comment\nbackup\n",
        encoding="utf-8",
    )

    assert load_wordlist(str(wordlist)) == [
        "/admin",
        "/login",
        "/backup",
    ]


def test_load_wordlist_missing_file():
    with pytest.raises(ValueError, match="Unable to read wordlist"):
        load_wordlist("/missing/wordlist.txt")


def test_load_wordlist_empty_file(tmp_path):
    wordlist = tmp_path / "empty.txt"
    wordlist.write_text("", encoding="utf-8")

    assert load_wordlist(str(wordlist)) == []


def test_normalize_target():
    assert normalize_target("https://example.test///") == "https://example.test"


def test_parse_extensions():
    assert parse_extensions(" .php, html, .txt ") == [
        "php",
        "html",
        "txt",
    ]


def test_parse_extensions_empty():
    assert parse_extensions(None) == []
    assert parse_extensions("") == []


def test_expand_paths_with_extensions():
    result = expand_paths(
        ["/admin", "/index", "/"],
        ["php", "html"],
    )

    assert result == [
        "/",
        "/admin",
        "/admin.html",
        "/admin.php",
        "/index",
        "/index.html",
        "/index.php",
    ]


def test_expand_paths_without_extensions():
    assert expand_paths(["/admin", "/login"], []) == [
        "/admin",
        "/login",
    ]


def test_parse_status_codes_default():
    assert parse_status_codes(None) == DEFAULT_STATUS_CODES
    assert parse_status_codes("") == DEFAULT_STATUS_CODES


def test_parse_status_codes_custom():
    assert parse_status_codes("200, 403, 404,200") == {
        200,
        403,
        404,
    }


@pytest.mark.parametrize("code", ["abc", "99", "600"])
def test_parse_status_codes_invalid(code):
    with pytest.raises(ValueError, match="Invalid HTTP status code"):
        parse_status_codes(code)


@patch("reconx.modules.dirscan.requests.get")
def test_scan_single_path_success(mock_get):
    response = Mock()
    response.status_code = 200
    response.content = b"hello"
    mock_get.return_value = response

    result = scan_single_path(
        "http://example.test",
        "/admin",
        3.0,
    )

    assert result == {
        "path": "/admin",
        "status": 200,
        "size": 5,
        "url": "http://example.test/admin",
    }

    mock_get.assert_called_once_with(
        "http://example.test/admin",
        timeout=3.0,
        allow_redirects=False,
    )


@patch("reconx.modules.dirscan.requests.get")
def test_scan_single_path_request_error(mock_get):
    mock_get.side_effect = requests.ConnectionError(
        "connection failed"
    )

    result = scan_single_path(
        "http://example.test",
        "/admin",
        3.0,
    )

    assert result is None


def test_scan_directories_rejects_invalid_target(tmp_path):
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Target must start"):
        scan_directories(
            "example.test",
            str(wordlist),
        )


def test_scan_directories_rejects_invalid_threads(tmp_path):
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Threads must be at least 1"):
        scan_directories(
            "http://example.test",
            str(wordlist),
            threads=0,
        )


def test_scan_directories_rejects_empty_wordlist(tmp_path):
    wordlist = tmp_path / "empty.txt"
    wordlist.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="Wordlist is empty"):
        scan_directories(
            "http://example.test",
            str(wordlist),
        )


@patch("reconx.modules.dirscan.scan_single_path")
def test_scan_directories_filters_and_sorts_findings(
    mock_scan,
    tmp_path,
):
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text(
        "z-admin\n"
        "login\n"
        "missing\n",
        encoding="utf-8",
    )

    def fake_scan(target, path, timeout):
        results = {
            "/z-admin": {
                "path": "/z-admin",
                "status": 200,
                "size": 10,
                "url": "http://example.test/z-admin",
            },
            "/login": {
                "path": "/login",
                "status": 403,
                "size": 20,
                "url": "http://example.test/login",
            },
            "/missing": {
                "path": "/missing",
                "status": 404,
                "size": 0,
                "url": "http://example.test/missing",
            },
        }
        return results[path]

    mock_scan.side_effect = fake_scan

    findings = scan_directories(
        "http://example.test/",
        str(wordlist),
        threads=2,
        status_codes="200,403",
    )

    assert [item["path"] for item in findings] == [
        "/login",
        "/z-admin",
    ]
    assert all(item["status"] in {200, 403} for item in findings)
    assert mock_scan.call_count == 3
