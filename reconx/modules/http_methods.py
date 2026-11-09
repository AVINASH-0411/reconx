
import math
from urllib.parse import urlsplit

import requests


HTTP_METHODS = (
    "GET",
    "HEAD",
    "POST",
    "OPTIONS",
    "PUT",
    "DELETE",
    "PATCH",
    "TRACE",
    "CONNECT",
)


def detect_http_methods(
    target: str,
    timeout: float = 5.0,
) -> dict:
    """Detect HTTP methods advertised by a target using OPTIONS."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target URL cannot be empty.")

    target = target.strip()
    parsed = urlsplit(target)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Target must be a valid HTTP or HTTPS URL.")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port.") from exc

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a finite positive number.")

    try:
        response = requests.options(
            target,
            timeout=timeout,
            allow_redirects=True,
        )

    except requests.RequestException as exc:
        raise ValueError(
            f"HTTP method detection failed: {exc}"
        ) from exc

    allow_header = response.headers.get("Allow", "")

    advertised_methods = sorted({
        method.strip().upper()
        for method in allow_header.split(",")
        if method.strip().upper() in HTTP_METHODS
    })

    return {
        "target": target,
        "status_code": response.status_code,
        "allow_header": allow_header,
        "advertised_methods": advertised_methods,
        "potentially_risky_methods": [
            method
            for method in advertised_methods
            if method in ("PUT", "DELETE", "TRACE", "CONNECT")
        ],
        "method_detection": (
            "advertised" if allow_header else "not_disclosed"
        ),
    }
