
import socket

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    8000: "HTTP-alt",
    8001: "HTTP-alt",
    8080: "HTTP-proxy",
    8443: "HTTPS-alt",
}


def detect_service(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> str:
    """Identify a service using its common port and optional banner."""

    service = COMMON_SERVICES.get(port, "Unknown")

    try:
        with socket.create_connection(
            (target, port),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)

            if port in (80, 8000, 8001, 8080):
                sock.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
                )
                response = sock.recv(1024).decode(
                    "utf-8", errors="replace"
                )

                if "Werkzeug" in response:
                    return "HTTP (Werkzeug)"
                if response.startswith("HTTP/"):
                    return "HTTP"

            elif port == 22:
                banner = sock.recv(256).decode(
                    "utf-8", errors="replace"
                )
                if banner.startswith("SSH-"):
                    return "SSH"

    except (OSError, TimeoutError):
        pass

    return service
