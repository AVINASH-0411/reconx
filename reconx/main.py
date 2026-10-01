import sys
import typer

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
                raise ValueError("Port range start cannot be greater than end.")

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
    except ValueError as error:
        typer.echo(f"Error: {error}")
        raise typer.Exit(code=1)

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
    target: str = typer.Argument(..., help="Target URL to analyze.")
):
    """Analyze HTTP information for a target."""
    typer.echo(f"HTTP Analyzer target: {target}")


def show_help() -> None:
    typer.echo(
        "Usage: reconx [OPTIONS] TARGET\n"
        "       reconx web TARGET\n\n"
        "Lightweight reconnaissance and security assessment CLI tool.\n\n"
        "Options:\n"
        "  -p, --port TEXT   Ports: 80, 22,80,443, or 1-1000.\n"
        "  -v, --version     Show ReconX version.\n"
        "  --help            Show this message and exit.\n\n"
        "Commands:\n"
        "  web               Analyze HTTP information for a target."
    )


def cli() -> None:
    """ReconX command-line entry point."""
    args = sys.argv[1:]

    if not args or args == ["--help"] or args == ["-h"]:
        show_help()
        return

    if args[0] in ("--version", "-v"):
        typer.echo("ReconX version 0.1.0")
        return

    if args[0] == "web":
        sys.argv = [sys.argv[0]] + args[1:]
        web_app()
        return

    target = args[0]
    port_spec = "1-1000"

    if len(args) > 1:
        if args[1] in ("-p", "--port") and len(args) >= 3:
            port_spec = args[2]
        else:
            typer.echo("Error: use -p/--port for port selection.")
            raise typer.Exit(code=1)

    run_scan(target, port_spec)


if __name__ == "__main__":
    cli()
