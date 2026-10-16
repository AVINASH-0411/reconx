
import sys

import typer

from reconx.modules.dirscan import scan_directories
from reconx.modules.exposed_files import detect_exposed_files
from reconx.modules.http_analyzer import analyze_http
from reconx.modules.lfi import test_lfi
from reconx.modules.portscan import scan_ports
from reconx.modules.report import save_csv_report, save_json_report
from reconx.modules.service_detect import detect_service


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
                raise ValueError("Port range start cannot be greater than end.")

            ports.update(range(start_port, end_port + 1))
        else:
            ports.add(int(part))

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")

    return sorted(ports)


def write_report(
    target: str,
    scan_type: str,
    results: dict,
    output: str | None,
) -> None:
    """Save scan results as JSON or CSV."""
    if not output:
        return

    try:
        if output.lower().endswith(".json"):
            path = save_json_report(target, scan_type, results, output)
            typer.echo(f"[+] JSON report saved: {path}")
        elif output.lower().endswith(".csv"):
            path = save_csv_report(target, scan_type, results, output)
            typer.echo(f"[+] CSV report saved: {path}")
        else:
            typer.echo("[!] Report filename must end with .json or .csv.")
    except (OSError, ValueError, TypeError) as error:
        typer.echo(f"[!] Could not save report: {error}")


def run_scan(
    target: str,
    port_spec: str,
    output: str | None = None,
) -> None:
    """Run the TCP port scanner and display summary statistics."""
    try:
        ports = parse_ports(port_spec)
        open_ports = scan_ports(target, ports)
    except (ValueError, OSError) as error:
        typer.echo(f"[!] Port scan error: {error}")
        return

    typer.echo(f"Scanning {target}...")
    typer.echo(f"Ports: {len(ports)}")

    services = []

    if open_ports:
        typer.echo("\nPORT     STATE    SERVICE")

        for port in open_ports:
            service = detect_service(target, port)
            typer.echo(f"{port:<8} open     {service}")
            services.append({
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
            })
    else:
        typer.echo("\nNo open TCP ports found.")

    summary = {
        "total_ports_scanned": len(ports),
        "open_ports_count": len(services),
        "closed_or_filtered_count": len(ports) - len(services),
    }

    typer.echo("\nScan Summary")
    typer.echo("------------")
    typer.echo(f"Total ports scanned : {summary['total_ports_scanned']}")
    typer.echo(f"Open ports found    : {summary['open_ports_count']}")
    typer.echo(f"Closed/filtered     : {summary['closed_or_filtered_count']}")

    write_report(
        target,
        "tcp_port_scan",
        {
            "ports_scanned": len(ports),
            "open_ports": services,
            "summary": summary,
        },
        output,
    )


def run_web_analysis(target: str, output: str | None = None) -> None:
    """Analyze HTTP details and optionally save a report."""
    typer.echo("ReconX HTTP Analyzer")
    typer.echo(f"Target: {target}\n")

    try:
        result = analyze_http(target)
    except (ValueError, OSError) as error:
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

    typer.echo("\nSecurity Observations")
    typer.echo("---------------------")

    if observations:
        for observation in observations:
            typer.echo(observation)
    else:
        typer.echo("[+] No obvious HTTP security issues detected")

    write_report(target, "http_analysis", result, output)
    typer.echo("\n[+] HTTP analysis completed.")


def run_lfi(target: str, output: str | None = None) -> None:
    """Run the LFI detector."""
    typer.echo("ReconX LFI Detector")
    typer.echo(f"Target: {target}")
    typer.echo("\n[*] Testing parameters...\n")

    try:
        findings = test_lfi(target)
    except (ValueError, OSError) as error:
        typer.echo(f"[!] LFI Error: {error}")
        return

    for finding in findings:
        typer.echo("[!] Possible LFI detected")
        typer.echo(f"    Parameter  : {finding['parameter']}")
        typer.echo(f"    Candidate  : {finding['candidate']}")
        typer.echo(f"    Traversal  : {finding['traversal']}")
        typer.echo(f"    Status     : {finding['status']}")
        typer.echo(f"    Evidence   : {finding['evidence']}")
        typer.echo(f"    Matched    : {', '.join(finding['matched'])}")
        typer.echo(f"    Confidence : {finding['confidence']}\n")

    if not findings:
        typer.echo("[-] No convincing LFI evidence found.")

    write_report(
        target,
        "lfi_detection",
        {"findings": findings, "finding_count": len(findings)},
        output,
    )
    typer.echo("[+] LFI analysis completed.")


def run_directory_scan(
    target: str,
    wordlist: str,
    threads: int,
    extensions: str | None,
    status_codes: str | None,
    output: str | None = None,
) -> None:
    """Run the directory scanner."""
    typer.echo("ReconX Directory Scanner")
    typer.echo(f"Target   : {target}")
    typer.echo(f"Wordlist : {wordlist}")
    typer.echo(f"Threads  : {threads}")

    try:
        findings = scan_directories(
            target=target,
            wordlist=wordlist,
            threads=threads,
            extensions=extensions,
            status_codes=status_codes,
        )
    except (ValueError, OSError) as error:
        typer.echo(f"[!] Directory Scan Error: {error}")
        return

    for finding in findings:
        typer.echo(
            f"[{finding['status']}] {finding['path']} "
            f"({finding['size']} bytes)"
        )

    if not findings:
        typer.echo("[-] No matching paths discovered.")

    summary = {
        "total_findings": len(findings),
    }

    typer.echo("\nScan Summary")
    typer.echo("------------")
    typer.echo(f"Directory findings : {summary['total_findings']}")

    write_report(
        target,
        "directory_scan",
        {
            "findings": findings,
            "finding_count": len(findings),
            "summary": summary,
        },
        output,
    )
    typer.echo(f"[+] Directory scan completed. Findings: {len(findings)}")


def run_exposed_files(target: str, output: str | None = None) -> None:
    """Run exposed-file detection."""
    typer.echo("ReconX Exposed File Detection")
    typer.echo(f"Target: {target}")
    typer.echo("\n[*] Checking common sensitive-file paths...\n")

    try:
        findings = detect_exposed_files(target)
    except (ValueError, OSError) as error:
        typer.echo(f"[!] Exposed File Error: {error}")
        return

    for finding in findings:
        typer.echo("[!] Possible exposed file detected")
        typer.echo(f"    Path         : {finding['path']}")
        typer.echo(f"    URL          : {finding['url']}")
        typer.echo(f"    Status       : {finding['status']}")
        typer.echo(f"    Content-Type : {finding['content_type']}")
        typer.echo(f"    Evidence     : {', '.join(finding['evidence'])}\n")

    if not findings:
        typer.echo("[-] No convincing exposed-file evidence found.")

    summary = {
        "total_findings": len(findings),
    }

    typer.echo("\nScan Summary")
    typer.echo("------------")
    typer.echo(f"Exposed-file findings: {summary['total_findings']}")

    write_report(
        target,
        "exposed_file_detection",
        {
            "findings": findings,
            "finding_count": len(findings),
            "summary": summary,
        },
        output,
    )
    typer.echo("[+] Exposed-file analysis completed.")


def run_aggregate_scan(
    target: str,
    port_spec: str = "1-1000",
    output: str | None = None,
) -> None:
    """Run a lightweight aggregate scan."""
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

    results = {
        "ports_scanned": len(ports),
        "open_ports": [],
        "http_analysis": [],
        "exposed_files": [],
    }

    for port in open_ports:
        service = detect_service(target, port)
        typer.echo(f"{port}/tcp open {service}")
        results["open_ports"].append({
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": service,
        })

    if not open_ports:
        typer.echo("[-] No open TCP ports found.")
        results["summary"] = {
            "total_ports_scanned": len(ports),
            "open_ports_count": 0,
            "http_targets_analyzed": 0,
            "exposed_file_findings": 0,
        }
        typer.echo("\nScan Summary")
        typer.echo("------------")
        typer.echo(f"Total ports scanned : {len(ports)}")
        typer.echo("Open ports found    : 0")
        write_report(target, "aggregate_scan", results, output)
        typer.echo("[+] Aggregate scan completed.")
        return

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
            http_result = analyze_http(url)
            results["http_analysis"].append({"url": url, **http_result})
            typer.echo(f"    Status Code : {http_result['status_code']}")
            typer.echo(f"    Page Title  : {http_result['title']}")
            typer.echo(f"    HTTPS       : {'Yes' if http_result['https'] else 'No'}")
        except (ValueError, OSError) as error:
            typer.echo(f"[!] HTTP analysis skipped: {error}")
            continue

        typer.echo(f"\n[3/3] Exposed File Detection: {url}")

        try:
            findings = detect_exposed_files(url)
            results["exposed_files"].extend(findings)

            if not findings:
                typer.echo("[-] No convincing exposed-file evidence found.")
            else:
                for finding in findings:
                    typer.echo(
                        f"[!] Possible exposure: {finding['path']} "
                        f"(HTTP {finding['status']})"
                    )
        except (ValueError, OSError) as error:
            typer.echo(f"[!] Exposed-file check skipped: {error}")

    results["summary"] = {
        "total_ports_scanned": len(ports),
        "open_ports_count": len(results["open_ports"]),
        "http_targets_analyzed": len(results["http_analysis"]),
        "exposed_file_findings": len(results["exposed_files"]),
    }

    typer.echo("\nScan Summary")
    typer.echo("------------")
    typer.echo(f"Total ports scanned : {results['summary']['total_ports_scanned']}")
    typer.echo(f"Open ports found    : {results['summary']['open_ports_count']}")
    typer.echo(f"HTTP targets analyzed: {results['summary']['http_targets_analyzed']}")
    typer.echo(f"Exposed-file findings: {results['summary']['exposed_file_findings']}")

    write_report(target, "aggregate_scan", results, output)
    typer.echo("\n[+] Aggregate scan completed.")


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
    output: str | None = typer.Option(
        None, "-o", "--output", help="Save report as .json or .csv."
    ),
):
    """Scan a web target for directories and files."""
    run_directory_scan(
        target, wordlist, threads, extensions, status_codes, output
    )


def show_help() -> None:
    """Display ReconX help."""
    typer.echo(
        "Usage: reconx [OPTIONS] TARGET\n"
        "       reconx web TARGET [-o REPORT.json|REPORT.csv]\n"
        "       reconx lfi TARGET [-o REPORT.json|REPORT.csv]\n"
        "       reconx dir TARGET -w WORDLIST [-o REPORT.json|REPORT.csv]\n"
        "       reconx files TARGET [-o REPORT.json|REPORT.csv]\n\n"
        "Options:\n"
        "  -p, --port TEXT   Ports: 80, 22,80,443, or 1-1000.\n"
        "  -a                Run aggregate scan.\n"
        "  -o, --output PATH Save results as .json or .csv.\n"
        "  -v, --version     Show ReconX version.\n"
        "  --help            Show this message and exit."
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
        if len(args) < 2:
            typer.echo('Usage: reconx web "URL" [-o REPORT.json|REPORT.csv]')
            return

        target = args[1]
        output = None

        if len(args) > 2:
            if len(args) == 4 and args[2] in ("-o", "--output"):
                output = args[3]
            else:
                typer.echo("Error: invalid web arguments.")
                return

        run_web_analysis(target, output)
        return

    if args[0] in ("lfi", "files"):
        if len(args) < 2:
            typer.echo(f'Usage: reconx {args[0]} "URL" [-o REPORT.json|REPORT.csv]')
            return

        target = args[1]
        output = None

        if len(args) > 2:
            if len(args) == 4 and args[2] in ("-o", "--output"):
                output = args[3]
            else:
                typer.echo("Error: invalid arguments.")
                return

        if args[0] == "lfi":
            run_lfi(target, output)
        else:
            run_exposed_files(target, output)
        return

    if args[0] == "dir":
        sys.argv = [sys.argv[0]] + args[1:]
        dir_app()
        return

    target = args[0]
    remaining = args[1:]
    aggregate = "-a" in remaining

    if aggregate:
        remaining.remove("-a")

    port_spec = "1-1000"
    output = None
    index = 0

    while index < len(remaining):
        option = remaining[index]

        if option in ("-p", "--port") and index + 1 < len(remaining):
            port_spec = remaining[index + 1]
            index += 2
        elif option in ("-o", "--output") and index + 1 < len(remaining):
            output = remaining[index + 1]
            index += 2
        else:
            typer.echo(f"Error: invalid or incomplete option: {option}")
            return

    if aggregate:
        run_aggregate_scan(target, port_spec, output)
    else:
        run_scan(target, port_spec, output)


if __name__ == "__main__":
    cli()
