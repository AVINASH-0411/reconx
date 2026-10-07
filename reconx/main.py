import sys

import typer

from reconx.modules.dirscan import scan_directories
from reconx.modules.http_analyzer import analyze_http
from reconx.modules.lfi import test_lfi
from reconx.modules.portscan import scan_ports


def parse_ports(port_spec: str) -> list[int]:
    """Parse ports such as 80, 22,80,443, or 1-100."""
    ports = set()

    for part in port_spec.split(","):
        part = part.strip()

        if "-" in part:
            start, end = part.split("-", 1)
            start_port = int(start)
            end_port = int(end)

            if start_port > end_port:
                raise ValueError(
                    "Port range start cannot be greater than end."
                )

            ports.update(range(start_port, end_port + 1))

        else:
            ports.add(int(part))

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid port: {port}"
            )

    return sorted(ports)


def run_scan(target: str, port_spec: str) -> None:
    """Run the TCP port scanner."""

    try:
        ports = parse_ports(port_spec)

    except ValueError as error:
        typer.echo(f"Error: {error}")
        return

    typer.echo(f"Scanning {target}...")
    typer.echo(f"Ports: {len(ports)}")

    open_ports = scan_ports(target, ports)

    if open_ports:
        typer.echo("\nOpen ports:")

        for port in open_ports:
            typer.echo(f"  {port}/tcp")

    else:
        typer.echo("\nNo open TCP ports found.")


web_app = typer.Typer(
    name="web",
    help="Analyze HTTP information for a target."
)


@web_app.command()
def web(
    target: str = typer.Argument(
        ...,
        help="Target URL to analyze."
    )
):
    """Analyze HTTP information for a target."""

    typer.echo("ReconX HTTP Analyzer")
    typer.echo(f"Target: {target}")
    typer.echo()

    try:
        result = analyze_http(target)

    except ValueError as error:
        typer.echo(f"[!] HTTP Error: {error}")
        return

    typer.echo(
        f"Status Code      : {result['status_code']}"
    )

    typer.echo(
        f"Page Title       : {result['title']}"
    )

    typer.echo(
        f"Server           : {result['server']}"
    )

    typer.echo(
        f"Content-Type     : {result['content_type']}"
    )

    typer.echo(
        f"Response Size    : {result['content_length']} bytes"
    )

    typer.echo(
        f"Redirects        : {result['redirects']}"
    )

    typer.echo(
        f"HTTPS            : {'Yes' if result['https'] else 'No'}"
    )

    typer.echo(
        f"Response Time    : {result['response_time']:.3f} seconds"
    )

    typer.echo(
        f"Final URL        : {result['final_url']}"
    )

    typer.echo()
    typer.echo("Security Headers")
    typer.echo("----------------")

    for header, present in result["security_headers"].items():
        status = "Present" if present else "Missing"

        typer.echo(
            f"{header:<20}: {status}"
        )

    typer.echo()
    typer.echo("Security Observations")
    typer.echo("---------------------")

    observations = []

    if not result["https"]:
        observations.append(
            "[!] HTTPS is not enabled"
        )

    if not result["security_headers"]["CSP"]:
        observations.append(
            "[!] Content-Security-Policy is missing"
        )

    if not result["security_headers"]["X-Frame-Options"]:
        observations.append(
            "[!] X-Frame-Options is missing"
        )

    if not result["security_headers"]["X-Content-Type-Options"]:
        observations.append(
            "[!] X-Content-Type-Options is missing"
        )

    if not result["security_headers"]["HSTS"]:
        observations.append(
            "[!] Strict-Transport-Security is missing"
        )

    if not result["security_headers"]["Referrer-Policy"]:
        observations.append(
            "[!] Referrer-Policy is missing"
        )

    if not result["security_headers"]["Permissions-Policy"]:
        observations.append(
            "[!] Permissions-Policy is missing"
        )

    if result["server"] != "N/A":
        observations.append(
            "[!] Server information is disclosed"
        )

    if observations:
        for observation in observations:
            typer.echo(observation)
    else:
        typer.echo(
            "[+] No obvious HTTP security issues detected"
        )

    typer.echo()
    typer.echo("[+] HTTP analysis completed.")


def run_lfi(target: str) -> None:
    """Run the LFI detector."""

    typer.echo("ReconX LFI Detector")
    typer.echo(f"Target: {target}")
    typer.echo("\n[*] Testing parameters...\n")

    try:
        findings = test_lfi(target)

    except ValueError as error:
        typer.echo(f"[!] LFI Error: {error}")
        return

    if findings:
        for finding in findings:
            typer.echo("[!] Possible LFI detected")

            typer.echo(
                f"    Parameter  : {finding['parameter']}"
            )

            typer.echo(
                f"    Candidate  : {finding['candidate']}"
            )

            typer.echo(
                f"    Traversal  : {finding['traversal']}"
            )

            typer.echo(
                f"    Status     : {finding['status']}"
            )

            typer.echo(
                f"    Evidence   : {finding['evidence']}"
            )

            typer.echo(
                f"    Matched    : {', '.join(finding['matched'])}"
            )

            typer.echo(
                f"    Confidence : {finding['confidence']}"
            )

            typer.echo()

    else:
        typer.echo(
            "[-] No convincing LFI evidence found."
        )

    typer.echo(
        "[+] LFI analysis completed."
    )


def run_directory_scan(
    target: str,
    wordlist: str,
    threads: int,
    extensions: str | None,
    status_codes: str | None,
) -> None:
    """Run the directory scanner."""

    typer.echo("ReconX Directory Scanner")
    typer.echo(f"Target   : {target}")
    typer.echo(f"Wordlist : {wordlist}")
    typer.echo(f"Threads  : {threads}")

    if extensions:
        typer.echo(
            f"Extensions: {extensions}"
        )

    if status_codes:
        typer.echo(
            f"Status Codes: {status_codes}"
        )

    typer.echo()
    typer.echo("[*] Starting directory scan...")
    typer.echo()

    try:
        findings = scan_directories(
            target=target,
            wordlist=wordlist,
            threads=threads,
            extensions=extensions,
            status_codes=status_codes,
        )

    except ValueError as error:
        typer.echo(
            f"[!] Directory Scan Error: {error}"
        )
        return

    for finding in findings:
        typer.echo(
            f"[{finding['status']}] "
            f"{finding['path']} "
            f"({finding['size']} bytes)"
        )

    if not findings:
        typer.echo(
            "[-] No matching paths discovered."
        )

    typer.echo()
    typer.echo(
        f"[+] Directory scan completed. "
        f"Findings: {len(findings)}"
    )


dir_app = typer.Typer(
    name="dir",
    help="Scan a web target for directories and files."
)


@dir_app.command()
def directory(
    target: str = typer.Argument(
        ...,
        help="Target URL to scan."
    ),
    wordlist: str = typer.Option(
        ...,
        "-w",
        "--wordlist",
        help="Path to the directory wordlist."
    ),
    threads: int = typer.Option(
        10,
        "-t",
        "--threads",
        help="Number of concurrent requests."
    ),
    extensions: str | None = typer.Option(
        None,
        "-x",
        "--extensions",
        help="Comma-separated file extensions."
    ),
    status_codes: str | None = typer.Option(
        None,
        "-s",
        "--status",
        help="Comma-separated HTTP status codes."
    ),
):
    """Scan a web target for directories and files."""

    run_directory_scan(
        target=target,
        wordlist=wordlist,
        threads=threads,
        extensions=extensions,
        status_codes=status_codes,
    )


def show_help() -> None:
    """Display ReconX help."""

    typer.echo(
        "Usage: reconx [OPTIONS] TARGET\n"
        "       reconx web TARGET\n"
        "       reconx lfi TARGET\n"
        "       reconx dir TARGET -w WORDLIST\n\n"
        "Lightweight reconnaissance and security assessment CLI tool.\n\n"
        "Options:\n"
        "  -p, --port TEXT   "
        "Ports: 80, 22,80,443, or 1-1000.\n"
        "  -v, --version     "
        "Show ReconX version.\n"
        "  --help            "
        "Show this message and exit.\n\n"
        "Commands:\n"
        "  web               "
        "Analyze HTTP information for a target.\n"
        "  lfi               "
        "Test URL parameters for possible LFI.\n"
        "  dir               "
        "Scan a web target for directories and files."
    )


def cli() -> None:
    """ReconX command-line entry point."""

    args = sys.argv[1:]

    if not args or args in (["--help"], ["-h"]):
        show_help()
        return

    if args[0] in ("--version", "-v"):
        typer.echo("ReconX version 0.1.0")
        return

    if args[0] == "web":
        sys.argv = [sys.argv[0]] + args[1:]
        web_app()
        return

    if args[0] == "lfi":
        if len(args) < 2:
            typer.echo(
                'Usage: reconx lfi "URL"'
            )
            return

        run_lfi(args[1])
        return

    if args[0] == "dir":
        if len(args) < 2:
            typer.echo(
                'Usage: reconx dir "URL" -w WORDLIST'
            )
            return

        sys.argv = [sys.argv[0]] + args[1:]
        dir_app()
        return

    target = args[0]

    port_spec = "1-1000"

    if len(args) > 1:

        if args[1] in ("-p", "--port") and len(args) >= 3:
            port_spec = args[2]

        else:
            typer.echo(
                "Error: use -p/--port for port selection."
            )
            return

    run_scan(target, port_spec)


if __name__ == "__main__":
    cli()
