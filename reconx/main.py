import typer

app = typer.Typer(
    name="reconx",
    help="Lightweight reconnaissance and security assessment CLI tool.",
)


@app.command()
def web(
    target: str = typer.Argument(..., help="Target URL to analyze.")
):
    """Analyze HTTP information for a target."""
    typer.echo(f"HTTP Analyzer target: {target}")


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show ReconX version.",
    )
):
    """ReconX - Security assessment CLI tool."""

    if version:
        typer.echo("ReconX version 0.1.0")


if __name__ == "__main__":
    app()
