import ipaddress
import re
import requests
from reconx.modules.finding_assessment import assess_finding
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


CANDIDATE_PATHS = [
    "/etc/passwd",
    "/etc/hosts",
]


def generate_traversal_paths(path: str) -> list[str]:
    """Generate path traversal variants for a candidate file."""

    clean_path = path.lstrip("/")

    return [
        f"../{clean_path}",
        f"../../{clean_path}",
        f"../../../{clean_path}",
        f"../../../../{clean_path}",
    ]

def detect_file_evidence(
    candidate_path: str,
    response_text: str,
) -> list[str]:
    """Return recognizable evidence for the candidate file."""

    if candidate_path == "/etc/passwd":
        patterns = [
            "root:x:0:0:",
            "daemon:x:1:1:",
            "www-data:x:",
        ]

        return [
            pattern
            for pattern in patterns
            if pattern in response_text
        ]

    if candidate_path == "/etc/hosts":
        evidence = []

        for line in response_text.splitlines():
            parts = line.split()

            if len(parts) < 2:
                continue

            try:
                ipaddress.ip_address(parts[0])
            except ValueError:
                continue

            if parts[1].lower() == "localhost":
                evidence.append(line.strip())

        return evidence

    return []

def required_evidence_matches(candidate_path: str) -> int:
    """Return the minimum evidence required for a candidate."""

    if candidate_path == "/etc/passwd":
        return 2

    if candidate_path == "/etc/hosts":
        return 2

    return 1


def build_test_url(
    url: str,
    parameter: str,
    payload: str,
) -> str:
    """Replace a URL parameter value with an LFI test payload."""

    parsed = urlparse(url)

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    updated_parameters = []

    for key, value in parameters:
        if key == parameter:
            updated_parameters.append((key, payload))
        else:
            updated_parameters.append((key, value))

    query = urlencode(updated_parameters)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment,
        )
    )


def detect_parameters(url: str) -> list[str]:
    """Extract query parameters from the target URL."""

    parsed = urlparse(url)

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    return [key for key, _ in parameters]


def test_lfi(
    url: str,
    timeout: float = 5.0,
) -> list[dict]:
    """Test URL parameters for possible LFI."""

    parameters = detect_parameters(url)

    if not parameters:
        raise ValueError(
            "No query parameters found. "
            "LFI testing requires a parameter such as ?file=FUZZ."
        )

    findings = []
    successful_requests = 0
    failed_requests = 0

    for parameter in parameters:

        for candidate_path in CANDIDATE_PATHS:

            traversal_paths = generate_traversal_paths(
                candidate_path
            )

            for traversal in traversal_paths:

                test_url = build_test_url(
                    url,
                    parameter,
                    traversal,
                )

                try:
                    response = requests.get(
                        test_url,
                        timeout=timeout,
                    )

                except requests.RequestException:
                    failed_requests += 1
                    continue
                successful_requests += 1

                if not 200 <= response.status_code < 300:
                    continue

                evidence_matches = detect_file_evidence(
                    candidate_path,
                    response.text,
                )

                minimum_matches = required_evidence_matches(
                    candidate_path
                )

                if len(evidence_matches) >= minimum_matches:

                    finding = {
                        "parameter": parameter,
                        "candidate": candidate_path,
                        "traversal": traversal,
                        "status": response.status_code,
                        "evidence": (
                            f"Evidence for {candidate_path} detected"
                        ),
                        "matched": evidence_matches,
                        "url": test_url,
                    }

                    findings.append(assess_finding(finding))

                    break

    if successful_requests == 0 and failed_requests > 0:
        raise requests.RequestException(
            "All LFI test requests failed. Scan could not complete."
        )

    return findings
