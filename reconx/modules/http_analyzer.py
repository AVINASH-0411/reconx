import re
import time

import requests


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


def analyze_http(
    target: str,
    timeout: float = 5.0,
) -> dict:
    """Analyze HTTP information for a target."""

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
    }
