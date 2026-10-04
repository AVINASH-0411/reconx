import sys

import typer

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


def show_help() -> None:
    """Display ReconX help."""

    typer.echo(
        "Usage: reconx [OPTIONS] TARGET\n"
        "       reconx web TARGET\n"
        "       reconx lfi TARGET\n\n"
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
        "Test URL parameters for possible LFI."
    )


def cli() -> None:
    """ReconX command-line entry point."""

    args = sys.argv[1:]

    # Help
    if not args or args in (["--help"], ["-h"]):
        show_help()
        return

    # Version
    if args[0] in ("--version", "-v"):
        typer.echo("ReconX version 0.1.0")
        return

    # Web command
    if args[0] == "web":
        sys.argv = [sys.argv[0]] + args[1:]
        web_app()
        return

    # LFI command
    if args[0] == "lfi":
        if len(args) < 2:
            typer.echo(
                'Usage: reconx lfi "URL"'
            )
            return

        run_lfi(args[1])
        return

    # Main target
    target = args[0]

    # Default port range
    port_spec = "1-1000"

    # Parse -p / --port
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
