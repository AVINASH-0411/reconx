import requests


def load_wordlist(wordlist: str) -> list[str]:
    """Load paths from a wordlist."""

    try:
        with open(
            wordlist,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            paths = []

            for line in file:
                path = line.strip()

                if not path:
                    continue

                if path.startswith("#"):
                    continue

                if not path.startswith("/"):
                    path = f"/{path}"

                paths.append(path)

            return paths

    except OSError as error:
        raise ValueError(
            f"Unable to read wordlist: {error}"
        ) from error


def normalize_target(target: str) -> str:
    """Normalize the target URL."""

    return target.rstrip("/")


def scan_directories(
    target: str,
    wordlist: str,
    timeout: float = 5.0,
) -> list[dict]:
    """Scan a target using paths from a wordlist."""

    if not target.startswith(
        ("http://", "https://")
    ):
        raise ValueError(
            "Target must start with http:// or https://"
        )

    paths = load_wordlist(wordlist)

    if not paths:
        raise ValueError(
            "Wordlist is empty."
        )

    target = normalize_target(target)

    findings = []

    for path in paths:
        url = f"{target}{path}"

        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
            )

        except requests.RequestException:
            continue

        findings.append(
            {
                "path": path,
                "status": response.status_code,
                "size": len(response.content),
                "url": url,
            }
        )

    return findings
