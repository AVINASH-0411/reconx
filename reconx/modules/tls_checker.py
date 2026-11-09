
import math
import socket
import ssl
from datetime import datetime, timezone


def check_tls(
    target: str,
    port: int = 443,
    timeout: float = 5.0,
) -> dict:
    """Inspect a server's TLS connection and certificate."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target hostname cannot be empty.")

    target = target.strip()

    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("Port must be an integer.")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a finite positive number.")

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (target, port),
            timeout=timeout,
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=target,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher()

                not_before = ssl.cert_time_to_seconds(
                    certificate["notBefore"]
                )

                not_after = ssl.cert_time_to_seconds(
                    certificate["notAfter"]
                )

                valid_from = datetime.fromtimestamp(
                    not_before, tz=timezone.utc
                )

                expires_at = datetime.fromtimestamp(
                    not_after, tz=timezone.utc
                )

                now = datetime.now(timezone.utc)

                days_remaining = (
                    expires_at - now
                ).days

                subject = certificate.get("subject", ())
                issuer = certificate.get("issuer", ())

                return {
                    "target": target,
                    "port": port,
                    "tls_version": tls_socket.version(),
                    "cipher": cipher[0] if cipher else None,
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": valid_from.isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "days_remaining": days_remaining,
                    "certificate_valid": (
                        valid_from <= now <= expires_at
                    ),
                    "hostname_verified": True,
                    "verification": "passed",
                }

    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        raise ValueError(
            f"TLS connection or certificate verification failed: {exc}"
        ) from exc
