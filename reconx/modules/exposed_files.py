
import math

import requests

from reconx.modules.finding_assessment import normalize_finding


SENSITIVE_FILES = {
    "/.env": [
        "DB_PASSWORD",
        "DATABASE_URL",
        "SECRET_KEY",
        "API_KEY",
    ],
    "/.git/HEAD": [
        "ref: refs/",
    ],
    "/backup.zip": [],
    "/config.php.bak": [
        "<?php",
        "password",
        "database",
    ],
    "/phpinfo.php": [
        "phpinfo()",
        "php version",
        "configuration file",
    ],
}


def check_file_evidence(
    path: str,
    content: bytes,
) -> list[str]:
    """Check response content for file-specific evidence."""
    sample = content[:200_000]
    text = sample.decode("utf-8", errors="ignore")
    lower_text = text.lower()

    if path != "/phpinfo.php" and (
        "<html" in lower_text or "<!doctype html" in lower_text
    ):
        return []

    if path == "/.env":
        return [
            marker
            for marker in SENSITIVE_FILES[path]
            if any(
                line.strip().upper().startswith(marker.upper() + "=")
                for line in text.splitlines()
            )
        ]

    if path == "/.git/HEAD":
        if lower_text.strip().startswith("ref: refs/"):
            return ["ref: refs/"]
        return []

    if path == "/config.php.bak":
        if "<?php" not in lower_text:
            return []

        return [
            marker
            for marker in SENSITIVE_FILES[path]
            if marker.lower() in lower_text
        ]
    if path == "/phpinfo.php":
        markers = [
            marker
            for marker in SENSITIVE_FILES[path]
            if marker in lower_text
        ]

        has_phpinfo_signature = (
            "phpinfo()" in lower_text
            and (
                "<html" in lower_text
                or "<!doctype html" in lower_text
            )
        )

        if has_phpinfo_signature and len(markers) >= 2:
            return markers

        return []
    if path == "/backup.zip":
        if sample.startswith(b"PK\x03\x04"):
            return ["ZIP archive signature"]

    return []


def detect_exposed_files(
    target: str,
    timeout: float = 5.0,
) -> list[dict]:
    """Check common sensitive paths on an authorized web target."""

    if not target.startswith(("http://", "https://")):
        raise ValueError(
            "Target must start with http:// or https://"
        )

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Timeout must be a finite positive number.")

    findings = []

    for path in SENSITIVE_FILES:
        url = f"{target.rstrip('/')}{path}"

        try:
            with requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    continue

                content = response.raw.read(
                    200_000,
                    decode_content=True,
                )

                evidence = check_file_evidence(
                    path,
                    content,
                )

                if not evidence:
                    continue

                finding = {
                    "path": path,
                    "url": url,
                    "status": response.status_code,
                    "content_type": response.headers.get(
                        "Content-Type",
                        "N/A",
                    ),
                    "evidence": evidence,
                }

                findings.append(
                    normalize_finding(
                        finding,
                        finding_type="exposed_file",
                        severity="MEDIUM",
                        remediation=(
                            "Remove public access to sensitive files, "
                            "rotate exposed secrets, and restrict "
                            "access to configuration and backup files."
                        ),
                    )
                )

        except requests.RequestException:
            continue

    return findings
