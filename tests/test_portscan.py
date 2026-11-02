import socket
from unittest.mock import MagicMock, patch

import pytest

from reconx.modules.portscan import scan_port, scan_ports


def test_scan_port_returns_true_when_port_is_open():
    with patch("reconx.modules.portscan.socket.socket") as mock_socket:
        mock_connection = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_connection
        mock_connection.connect_ex.return_value = 0

        assert scan_port("127.0.0.1", 8080) is True


def test_scan_port_returns_false_when_port_is_closed():
    with patch("reconx.modules.portscan.socket.socket") as mock_socket:
        mock_connection = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_connection
        mock_connection.connect_ex.return_value = 111

        assert scan_port("127.0.0.1", 8080) is False


def test_scan_port_rejects_invalid_port():
    with pytest.raises(ValueError, match="Invalid port"):
        scan_port("127.0.0.1", 70000)


def test_scan_port_rejects_nonpositive_timeout():
    with pytest.raises(ValueError, match="Timeout"):
        scan_port("127.0.0.1", 8080, timeout=0)


def test_scan_ports_returns_only_open_ports():
    def mock_scan_port(target, port, timeout):
        return port in (80, 82)

    with patch(
        "reconx.modules.portscan.scan_port",
        side_effect=mock_scan_port,
    ):
        assert scan_ports("127.0.0.1", [80, 81, 82]) == [80, 82]


def test_scan_port_returns_false_on_socket_error():
    with patch(
        "reconx.modules.portscan.socket.socket",
        side_effect=socket.error("Connection failed"),
    ):
        assert scan_port("127.0.0.1", 8080) is False


@pytest.mark.parametrize(
    "timeout",
    [-1, float("inf"), float("nan"), "5", True],
)
def test_scan_port_rejects_invalid_timeouts(timeout):
    with pytest.raises(ValueError, match="Timeout"):
        scan_port("127.0.0.1", 8080, timeout=timeout)


def test_scan_ports_rejects_invalid_port_before_scanning():
    with patch("reconx.modules.portscan.scan_port") as mock_scan:
        with pytest.raises(ValueError, match="Invalid port"):
            scan_ports("127.0.0.1", [80, 81, 70000])

        mock_scan.assert_not_called()

def test_scan_ports_returns_sorted_open_ports():
    def mock_scan_port(target, port, timeout):
        return port in (2, 4, 6)

    with patch(
        "reconx.modules.portscan.scan_port",
        side_effect=mock_scan_port,
    ):
        result = scan_ports(
            "127.0.0.1",
            [1, 2, 3, 4, 5, 6, 7, 8],
            workers=1,
        )

    assert result == [2, 4, 6]
