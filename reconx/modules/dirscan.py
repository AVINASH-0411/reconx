from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


DEFAULT_STATUS_CODES = {
    200,
    204,
    301,
    302,
    307,
    308,
    401,
    403,
}


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


def parse_extensions(
    extensions: str | None,
) -> list[str]:
    """Parse comma-separated file extensions."""

    if not extensions:
        return []

    result = []

    for extension in extensions.split(","):
        extension = extension.strip().lstrip(".")

        if extension:
            result.append(extension)

    return result


def expand_paths(
    paths: list[str],
    extensions: list[str],
) -> list[str]:
    """Expand wordlist paths using requested extensions."""

    expanded = set()

    for path in paths:
        expanded.add(path)

        if not extensions or path.endswith("/"):
            continue

        for extension in extensions:
            expanded.add(
                f"{path}.{extension}"
            )

    return sorted(expanded)


def parse_status_codes(
    status_codes: str | None,
) -> set[int]:
    """Parse comma-separated HTTP status codes."""

    if not status_codes:
        return DEFAULT_STATUS_CODES.copy()

    result = set()

    for code in status_codes.split(","):
        code = code.strip()

        try:
            value = int(code)

        except ValueError as error:
            raise ValueError(
                f"Invalid HTTP status code: {code}"
            ) from error

        if not 100 <= value <= 599:
            raise ValueError(
                f"Invalid HTTP status code: {value}"
            )

        result.add(value)

    return result


def scan_single_path(
    target: str,
    path: str,
    timeout: float,
) -> dict | None:
    """Scan one path."""

    url = f"{target}{path}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
        )

    except requests.RequestException:
        return None

    return {
        "path": path,
        "status": response.status_code,
        "size": len(response.content),
        "url": url,
    }


def display_progress(
    completed: int,
    total: int,
) -> None:
    """Display live directory scan progress."""

    if total == 0:
        return

    percentage = (
        completed / total
    ) * 100

    print(
        f"\rProgress: {completed} / {total} "
        f"({percentage:.2f}%)",
        end="",
        flush=True,
    )


def scan_directories(
    target: str,
    wordlist: str,
    threads: int = 10,
    extensions: str | None = None,
    status_codes: str | None = None,
    timeout: float = 5.0,
) -> list[dict]:
    """Scan a target using a wordlist."""

    if not target.startswith(
        ("http://", "https://")
    ):
        raise ValueError(
            "Target must start with http:// or https://"
        )

    if threads < 1:
        raise ValueError(
            "Threads must be at least 1."
        )

    paths = load_wordlist(wordlist)

    if not paths:
        raise ValueError(
            "Wordlist is empty."
        )

    parsed_extensions = parse_extensions(
        extensions
    )

    paths = expand_paths(
        paths,
        parsed_extensions,
    )

    allowed_status_codes = parse_status_codes(
        status_codes
    )

    target = normalize_target(target)

    total = len(paths)
    completed = 0
    findings = []

    print(
        f"Entries  : {total}"
    )

    print()

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        futures = {
            executor.submit(
                scan_single_path,
                target,
                path,
                timeout,
            ): path
            for path in paths
        }

        for future in as_completed(futures):
            completed += 1

            result = future.result()

            if result is not None:
                if result["status"] in allowed_status_codes:
                    findings.append(result)

            display_progress(
                completed,
                total,
            )

    print()

    findings.sort(
        key=lambda item: item["path"]
    )

    return findings
