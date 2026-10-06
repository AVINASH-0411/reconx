import re
import time

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Strict-Transport-Security": "HSTS",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


def extract_title(html: str) -> str:
    """Extract the HTML page title."""

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return "N/A"

    return " ".join(match.group(1).split())


def analyze_security_headers(
    headers: requests.structures.CaseInsensitiveDict,
) -> dict[str, bool]:
    """Check whether common security headers are present."""

    return {
        display_name: bool(headers.get(header_name))
        for header_name, display_name in SECURITY_HEADERS.items()
    }


def analyze_http(
    target: str,
    timeout: float = 5.0,
) -> dict:
    """Analyze HTTP information and security headers."""

    if not target.startswith(("http://", "https://")):
        raise ValueError(
            "Target must start with http:// or https://"
        )

    start_time = time.perf_counter()

    try:
        response = requests.get(
            target,
            timeout=timeout,
            allow_redirects=True,
        )

    except requests.RequestException as error:
        raise ValueError(
            f"HTTP request failed: {error}"
        ) from error

    response_time = time.perf_counter() - start_time

    content = response.content

    security_headers = analyze_security_headers(
        response.headers
    )

    return {
        "status_code": response.status_code,
        "title": extract_title(response.text),
        "server": response.headers.get(
            "Server",
            "N/A",
        ),
        "content_type": response.headers.get(
            "Content-Type",
            "N/A",
        ),
        "content_length": len(content),
        "redirects": len(response.history),
        "https": response.url.startswith("https://"),
        "response_time": response_time,
        "final_url": response.url,
        "security_headers": security_headers,
    }
