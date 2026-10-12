
import sys

import typer

from reconx.modules.dirscan import scan_directories
from reconx.modules.exposed_files import detect_exposed_files
from reconx.modules.http_analyzer import analyze_http
from reconx.modules.lfi import test_lfi
from reconx.modules.portscan import scan_ports


def parse_ports(port_spec: str) -> list[int]:
    """Parse ports such as 80, 22,80,443, or 1-100."""
    ports = set()

    for part in port_spec.split(","):
        part = part.strip()

        if not part:
            raise ValueError("Empty port specification.")

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
            raise ValueError(f"Invalid port: {port}")

    return sorted(ports)


def run_scan(target: str, port_spec: str) -> None:
    """Run the TCP port scanner."""
    try:
        ports = parse_ports(port_spec)
        open_ports = scan_ports(target, ports)
    except (ValueError, OSError) as error:
        typer.echo(f"[!] Port scan error: {error}")
        return

    typer.echo(f"Scanning {target}...")
    typer.echo(f"Ports: {len(ports)}")

    if open_ports:
        typer.echo("\nOpen ports:")
        for port in open_ports:
            typer.echo(f"  {port}/tcp")
    else:
        typer.echo("\nNo open TCP ports found.")


web_app = typer.Typer(
    name="web",
    help="Analyze HTTP information for a target.",
)


@web_app.command()
def web(
    target: str = typer.Argument(..., help="Target URL to analyze."),
):
    """Analyze HTTP information for a target."""
    typer.echo("ReconX HTTP Analyzer")
    typer.echo(f"Target: {target}\n")

    try:
        result = analyze_http(target)
    except ValueError as error:
        typer.echo(f"[!] HTTP Error: {error}")
        return

    typer.echo(f"Status Code      : {result['status_code']}")
    typer.echo(f"Page Title       : {result['title']}")
    typer.echo(f"Server           : {result['server']}")
    typer.echo(f"Content-Type     : {result['content_type']}")
    typer.echo(f"Response Size    : {result['content_length']} bytes")
    typer.echo(f"Redirects        : {result['redirects']}")
    typer.echo(f"HTTPS            : {'Yes' if result['https'] else 'No'}")
    typer.echo(f"Response Time    : {result['response_time']:.3f} seconds")
    typer.echo(f"Final URL        : {result['final_url']}")

    typer.echo("\nSecurity Headers")
    typer.echo("----------------")

    for header, present in result["security_headers"].items():
        typer.echo(f"{header:<20}: {'Present' if present else 'Missing'}")

    typer.echo("\nSecurity Observations")
    typer.echo("---------------------")

    observations = []

    if not result["https"]:
        observations.append("[!] HTTPS is not enabled")

    header_observations = {
        "CSP": "[!] Content-Security-Policy is missing",
        "X-Frame-Options": "[!] X-Frame-Options is missing",
        "X-Content-Type-Options": "[!] X-Content-Type-Options is missing",
        "HSTS": "[!] Strict-Transport-Security is missing",
        "Referrer-Policy": "[!] Referrer-Policy is missing",
        "Permissions-Policy": "[!] Permissions-Policy is missing",
    }

    for header, message in header_observations.items():
        if not result["security_headers"][header]:
            observations.append(message)

    if result["server"] != "N/A":
        observations.append("[!] Server information is disclosed")

    if observations:
        for observation in observations:
            typer.echo(observation)
    else:
        typer.echo("[+] No obvious HTTP security issues detected")

    typer.echo("\n[+] HTTP analysis completed.")


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
            typer.echo(f"    Parameter  : {finding['parameter']}")
            typer.echo(f"    Candidate  : {finding['candidate']}")
            typer.echo(f"    Traversal  : {finding['traversal']}")
            typer.echo(f"    Status     : {finding['status']}")
            typer.echo(f"    Evidence   : {finding['evidence']}")
            typer.echo(f"    Matched    : {', '.join(finding['matched'])}")
            typer.echo(f"    Confidence : {finding['confidence']}")
            typer.echo()
    else:
        typer.echo("[-] No convincing LFI evidence found.")

    typer.echo("[+] LFI analysis completed.")


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
        typer.echo(f"Extensions: {extensions}")

    if status_codes:
        typer.echo(f"Status Codes: {status_codes}")

    typer.echo("\n[*] Starting directory scan...\n")

    try:
        findings = scan_directories(
            target=target,
            wordlist=wordlist,
            threads=threads,
            extensions=extensions,
            status_codes=status_codes,
        )
    except ValueError as error:
        typer.echo(f"[!] Directory Scan Error: {error}")
        return

    for finding in findings:
        typer.echo(
            f"[{finding['status']}] "
            f"{finding['path']} "
            f"({finding['size']} bytes)"
        )

    if not findings:
        typer.echo("[-] No matching paths discovered.")

    typer.echo(
        f"\n[+] Directory scan completed. Findings: {len(findings)}"
    )


dir_app = typer.Typer(
    name="dir",
    help="Scan a web target for directories and files.",
)


@dir_app.command()
def directory(
    target: str = typer.Argument(..., help="Target URL to scan."),
    wordlist: str = typer.Option(
        ..., "-w", "--wordlist", help="Path to the directory wordlist."
    ),
    threads: int = typer.Option(
        10, "-t", "--threads", help="Number of concurrent requests."
    ),
    extensions: str | None = typer.Option(
        None, "-x", "--extensions", help="Comma-separated file extensions."
    ),
    status_codes: str | None = typer.Option(
        None, "-s", "--status", help="Comma-separated HTTP status codes."
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


def run_exposed_files(target: str) -> None:
    """Run exposed-file detection."""
    typer.echo("ReconX Exposed File Detection")
    typer.echo(f"Target: {target}")
    typer.echo("\n[*] Checking common sensitive-file paths...\n")

    try:
        findings = detect_exposed_files(target)
    except ValueError as error:
        typer.echo(f"[!] Exposed File Error: {error}")
        return

    if findings:
        for finding in findings:
            typer.echo("[!] Possible exposed file detected")
            typer.echo(f"    Path         : {finding['path']}")
            typer.echo(f"    URL          : {finding['url']}")
            typer.echo(f"    Status       : {finding['status']}")
            typer.echo(f"    Content-Type : {finding['content_type']}")
            typer.echo(
                f"    Evidence     : {', '.join(finding['evidence'])}"
            )
            typer.echo()
    else:
        typer.echo("[-] No convincing exposed-file evidence found.")

    typer.echo("[+] Exposed-file analysis completed.")


def run_aggregate_scan(
    target: str,
    port_spec: str = "1-1000",
) -> None:
    """Run a lightweight aggregate scan on an authorized target."""
    typer.echo("ReconX Aggregate Scan")
    typer.echo(f"Target: {target}")
    typer.echo(f"Ports: {port_spec}")
    typer.echo("\n[1/3] TCP Port Scan")

    try:
        ports = parse_ports(port_spec)
        open_ports = scan_ports(target, ports)
    except (ValueError, OSError) as error:
        typer.echo(f"[!] Port scan error: {error}")
        return

    if not open_ports:
        typer.echo("[-] No open TCP ports found.")
        typer.echo("[+] Aggregate scan completed.")
        return

    typer.echo(f"[+] Open TCP ports: {', '.join(map(str, open_ports))}")

    web_ports = {
        80: "http",
        443: "https",
        8000: "http",
        8001: "http",
        8080: "http",
        8443: "https",
    }

    for port in open_ports:
        scheme = web_ports.get(port)

        if scheme is None:
            continue

        url = f"{scheme}://{target}:{port}"
        typer.echo(f"\n[2/3] HTTP Analysis: {url}")

        try:
            result = analyze_http(url)
            typer.echo(f"    Status Code : {result['status_code']}")
            typer.echo(f"    Page Title  : {result['title']}")
            typer.echo(
                f"    HTTPS       : {'Yes' if result['https'] else 'No'}"
            )
        except ValueError as error:
            typer.echo(f"[!] HTTP analysis skipped: {error}")
            continue

        typer.echo(f"\n[3/3] Exposed File Detection: {url}")

        try:
            findings = detect_exposed_files(url)

            if findings:
                for finding in findings:
                    typer.echo(
                        f"[!] Possible exposure: {finding['path']} "
                        f"(HTTP {finding['status']})"
                    )
            else:
                typer.echo(
                    "[-] No convincing exposed-file evidence found."
                )
        except ValueError as error:
            typer.echo(f"[!] Exposed-file check skipped: {error}")

    typer.echo("\n[+] Aggregate scan completed.")


def show_help() -> None:
    """Display ReconX help."""
    typer.echo(
        "Usage: reconx [OPTIONS] TARGET\n"
        "       reconx web TARGET\n"
        "       reconx lfi TARGET\n"
        "       reconx dir TARGET -w WORDLIST\n"
        "       reconx files TARGET\n\n"
        "Lightweight reconnaissance and security assessment CLI tool.\n\n"
        "Options:\n"
        "  -p, --port TEXT   Ports: 80, 22,80,443, or 1-1000.\n"
        "  -a                Run aggregate scan.\n"
        "  -v, --version     Show ReconX version.\n"
        "  --help            Show this message and exit.\n\n"
        "Commands:\n"
        "  web               Analyze HTTP information for a target.\n"
        "  lfi               Test URL parameters for possible LFI.\n"
        "  dir               Scan directories and files.\n"
        "  files             Check for exposed sensitive files."
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
            typer.echo('Usage: reconx lfi "URL"')
            return
        run_lfi(args[1])
        return

    if args[0] == "dir":
        if len(args) < 2:
            typer.echo('Usage: reconx dir "URL" -w WORDLIST')
            return
        sys.argv = [sys.argv[0]] + args[1:]
        dir_app()
        return

    if args[0] == "files":
        if len(args) < 2:
            typer.echo('Usage: reconx files "URL"')
            return
        run_exposed_files(args[1])
        return

    target = args[0]
    aggregate = "-a" in args[1:]
    port_spec = "1-1000"

    remaining = args[1:]

    if "-a" in remaining:
        remaining.remove("-a")

    if remaining:
        if remaining[0] in ("-p", "--port") and len(remaining) >= 2:
            port_spec = remaining[1]
            if len(remaining) > 2:
                typer.echo("Error: unexpected extra arguments.")
                return
        else:
            typer.echo("Error: use -p/--port or -a.")
            return

    if aggregate:
        run_aggregate_scan(target, port_spec)
    else:
        run_scan(target, port_spec)


if __name__ == "__main__":
    cli()

