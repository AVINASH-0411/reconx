
import re
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
    8000: "HTTP",
    8001: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
}


def clean_banner(value: str) -> str:
    """Keep banner output short and readable."""
    value = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
    return value.strip()[:100]


def detect_service(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> str:
    """Identify TCP services using protocol responses and banners."""

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    fallback = COMMON_SERVICES.get(port, "Unknown")

    try:
        with socket.create_connection(
            (target, port), timeout=timeout
        ) as sock:
            sock.settimeout(timeout)

            # Try protocols that send a greeting first.
            try:
                banner = sock.recv(512).decode(
                    "utf-8", errors="replace"
                )
            except socket.timeout:
                banner = ""

            first_line = clean_banner(
                banner.splitlines()[0] if banner else ""
            )

            if banner.startswith("SSH-"):
                return f"SSH ({first_line})"

            if banner.startswith("220"):
                if "FTP" in banner.upper():
                    return f"FTP ({first_line})"
                if "SMTP" in banner.upper() or "ESMTP" in banner.upper():
                    return f"SMTP ({first_line})"

            if banner.startswith("+OK"):
                return "POP3"

            if banner.startswith("* OK"):
                return "IMAP"

            # Send a lightweight HTTP request.
            sock.sendall(
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n\r\n".encode()
            )

            response = sock.recv(2048).decode(
                "utf-8", errors="replace"
            )

            if response.startswith("HTTP/"):
                match = re.search(
                    r"^Server:\s*(.+)$",
                    response,
                    flags=re.IGNORECASE | re.MULTILINE,
                )

                if match:
                    server = clean_banner(match.group(1))
                    return f"HTTP ({server})"

                return "HTTP"

    except (OSError, TimeoutError):
        pass

    return fallback


