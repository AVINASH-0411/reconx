import socket


def scan_port(target: str, port: int, timeout: float = 0.5) -> bool:
    """Check whether a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0
    except socket.error:
        return False


def scan_ports(target: str, ports: list[int]):
    """Scan a list of TCP ports."""
    open_ports = []

    for port in ports:
        if scan_port(target, port):
            open_ports.append(port)

    return open_ports
