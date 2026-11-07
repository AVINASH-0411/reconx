
import math
import re
import time
from urllib.parse import urlsplit

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
    """Check whether common security headers have structurally valid values."""

    def has_valid_value(header_name: str) -> bool:
        value = headers.get(header_name, "")

        if not isinstance(value, str) or not value.strip():
            return False

        normalized = value.strip().lower()

        if header_name == "X-Frame-Options":
            return normalized in {"deny", "sameorigin"}

        if header_name == "X-Content-Type-Options":
            return normalized == "nosniff"

        if header_name == "Strict-Transport-Security":
            return bool(
                re.search(
                    r"(?:^|;)\s*max-age\s*=\s*\d+",
                    normalized,
                )
            )

        if header_name == "Referrer-Policy":
            valid_policies = {
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url",
            }

            tokens = [
                token.strip()
                for token in normalized.split(",")
            ]

            return all(
                token in valid_policies
                for token in tokens
            )

        if header_name == "Content-Security-Policy":
            valid_directives = {
                "default-src",
                "script-src",
                "style-src",
                "img-src",
                "connect-src",
                "font-src",
                "object-src",
                "media-src",
                "frame-src",
                "child-src",
                "worker-src",
                "manifest-src",
                "base-uri",
                "form-action",
                "frame-ancestors",
                "upgrade-insecure-requests",
                "block-all-mixed-content",
                "sandbox",
                "report-uri",
                "report-to",
                "trusted-types",
                "require-trusted-types-for",
                "script-src-elem",
                "script-src-attr",
                "style-src-elem",
                "style-src-attr",
                "prefetch-src",
                "navigate-to",
            }

            directives = [
                directive.strip().lower()
                for directive in value.split(";")
                if directive.strip()
            ]

            if not directives:
                return False

            directive_names = [
                directive.split()[0]
                for directive in directives
            ]

            return (
                all(
                    name in valid_directives
                    for name in directive_names
                )
                and len(directive_names)
                == len(set(directive_names))
            )

        if header_name == "Permissions-Policy":
            valid_features = {
                "accelerometer",
                "autoplay",
                "camera",
                "display-capture",
                "encrypted-media",
                "fullscreen",
                "geolocation",
                "gyroscope",
                "magnetometer",
                "microphone",
                "midi",
                "payment",
                "picture-in-picture",
                "publickey-credentials-get",
                "screen-wake-lock",
                "usb",
                "web-share",
                "xr-spatial-tracking",
            }

            directives = [
                directive.strip().lower()
                for directive in value.split(",")
            ]

            if not directives or any(
                not item for item in directives
            ):
                return False

            allowlist_pattern = (
                r'\(\s*(?:(?:\*|self|src|"(?:[^"\\]|\\.)*")'
                r'(?:\s+(?:\*|self|src|"(?:[^"\\]|\\.)*"))*)?\s*\)'
            )

            for directive in directives:
                if "=" not in directive:
                    return False

                feature, allowlist = directive.split("=", 1)

                feature = feature.strip()
                allowlist = allowlist.strip()

                if feature not in valid_features:
                    return False

                if not re.fullmatch(
                    allowlist_pattern,
                    allowlist,
                ):
                    return False

            return True

        return False

    return {
        display_name: has_valid_value(header_name)
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

    try:
        parsed_url = urlsplit(target)
        hostname = parsed_url.hostname
        parsed_url.port

    except ValueError as error:
        raise ValueError(
            "Target must be a valid URL"
        ) from error

    if not hostname:
        raise ValueError(
            "Target must include a valid hostname"
        )

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(
            "Timeout must be a finite positive number"
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
