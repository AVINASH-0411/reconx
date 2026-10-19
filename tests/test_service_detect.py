
from unittest.mock import Mock, patch

import pytest
import socket

from reconx.modules.service_detect import (
    COMMON_SERVICES,
    clean_banner,
    detect_service,
)


def test_clean_banner_removes_control_characters():
    assert clean_banner("SSH\r\nServer\x00") == "SSH Server"


def test_clean_banner_trims_whitespace():
    assert clean_banner("  hello server  ") == "hello server"


def test_clean_banner_limits_length():
    result = clean_banner("A" * 150)
    assert len(result) == 100


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_detect_service_rejects_invalid_port(port):
    with pytest.raises(ValueError, match="Port must be between"):
        detect_service("127.0.0.1", port)


@pytest.mark.parametrize("timeout", [0, -1, -0.5])
def test_detect_service_rejects_invalid_timeout(timeout):
    with pytest.raises(
        ValueError,
        match="Timeout must be a finite positive number",
    ):
        detect_service("127.0.0.1", 22, timeout=timeout)


def mock_socket_with_banner(banner, response=""):
    sock = Mock()
    sock.__enter__ = Mock(return_value=sock)
    sock.__exit__ = Mock(return_value=False)
    sock.recv.side_effect = [
        banner.encode(),
        response.encode(),
    ]
    return sock


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        ("SSH-2.0-OpenSSH_9.0\r\n", "SSH (SSH-2.0-OpenSSH_9.0)"),
        ("220 FTP server ready\r\n", "FTP (220 FTP server ready)"),
        ("220 ESMTP server ready\r\n", "SMTP (220 ESMTP server ready)"),
        ("+OK POP3 server ready\r\n", "POP3"),
        ("* OK IMAP server ready\r\n", "IMAP"),
    ],
)
@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_protocol_greetings(
    mock_connect,
    banner,
    expected,
):
    mock_connect.return_value = mock_socket_with_banner(banner)

    result = detect_service("127.0.0.1", 12345)

    assert result == expected


@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_http_with_server_header(mock_connect):
    sock = mock_socket_with_banner(
        "",
        "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n",
    )
    mock_connect.return_value = sock

    result = detect_service("127.0.0.1", 8080)

    assert result == "HTTP (nginx/1.25)"
    sock.sendall.assert_called_once()


@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_http_without_server_header(mock_connect):
    mock_connect.return_value = mock_socket_with_banner(
        "",
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
    )

    assert detect_service("127.0.0.1", 8080) == "HTTP"


@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_uses_fallback_for_unknown_response(mock_connect):
    mock_connect.return_value = mock_socket_with_banner(
        "",
        "Not an HTTP response",
    )

    assert detect_service("127.0.0.1", 3306) == "MySQL"


@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_uses_unknown_fallback(mock_connect):
    mock_connect.return_value = mock_socket_with_banner(
        "",
        "Not an HTTP response",
    )

    assert detect_service("127.0.0.1", 12345) == "Unknown"


@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_handles_connection_error(mock_connect):
    mock_connect.side_effect = socket.error("connection refused")

    assert detect_service("127.0.0.1", 22) == "SSH"


@patch("reconx.modules.service_detect.socket.create_connection")
def test_detect_service_handles_banner_timeout(mock_connect):
    sock = Mock()
    sock.__enter__ = Mock(return_value=sock)
    sock.__exit__ = Mock(return_value=False)
    sock.recv.side_effect = [
        socket.timeout("timed out"),
        b"HTTP/1.1 200 OK\r\n\r\n",
    ]
    mock_connect.return_value = sock

    assert detect_service("127.0.0.1", 80) == "HTTP"


def test_common_services_contains_expected_ports():
    assert COMMON_SERVICES[22] == "SSH"
    assert COMMON_SERVICES[80] == "HTTP"
    assert COMMON_SERVICES[443] == "HTTPS"
    assert COMMON_SERVICES[3306] == "MySQL"


@pytest.mark.parametrize(
    "timeout",
    [float("inf"), float("nan"), "5", True],
)
def test_detect_service_rejects_invalid_timeout_types_and_values(timeout):
    with pytest.raises(ValueError, match="Timeout"):
        detect_service("127.0.0.1", 22, timeout=timeout)
