"""
CLI for KeyCrawl.

Usage examples:
    python -m keycrawl scan https://example.com
    python -m keycrawl scan https://target.tld --depth 1 --max-pages 25 --json
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from .scanner import ScanResult, crawl_and_scan, find_secrets_in_text, findings_to_safe_dicts
from . import storage

app = typer.Typer(
    name="keycrawl",
    help="Scan websites for API keys, private keys, tokens and other secrets.",
    add_completion=False,
)
console = Console()


def _print_findings_table(findings: list, url: str) -> None:
    if not findings:
        rprint("[green]No secrets found.[/green]")
        return

    table = Table(title=f"Findings for {url}", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Redacted Value", style="yellow")
    table.add_column("URL", style="blue", overflow="fold")
    table.add_column("Context", style="white", overflow="fold")
    table.add_column("Entropy", justify="right", style="magenta")

    for i, f in enumerate(findings, 1):
        table.add_row(
            str(i),
            f.secret_type,
            f.value_redacted,
            f.url,
            f.context[:120] + ("…" if len(f.context) > 120 else ""),
            f"{f.entropy:.2f}" if f.entropy else "-",
        )
    console.print(table)
    rprint(f"\n[bold red]Total findings: {len(findings)}[/bold red]")
    rprint("[dim]WARNING: Treat any real findings as sensitive. Do not commit or share raw values.[/dim]")


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL or domain to scan (https://example.com)"),
    depth: int = typer.Option(2, "--depth", "-d", min=0, max=5, help="Max crawl depth"),
    max_pages: int = typer.Option(35, "--max-pages", "-p", min=1, max=200, help="Hard cap on pages fetched"),
    same_domain: bool = typer.Option(True, "--same-domain/--all-domains", help="Only crawl same registered domain"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output machine readable JSON instead of table"),
    concurrency: int = typer.Option(6, "--concurrency", "-c", min=1, max=20),
    delay: float = typer.Option(0.12, "--delay", help="Politeness delay between requests (seconds)"),
    timeout: float = typer.Option(13.0, "--timeout", help="Per-request timeout"),
    persist: bool = typer.Option(
        False,
        "--persist",
        "--save",
        help="Persist redacted findings to the shared collection database (findings.db). "
             "Raw secret values are NEVER stored — only redacted versions + metadata.",
    ),
):
    """Crawl a site and hunt for secrets.

    Use --persist to add the (redacted) findings to the persistent collection
    that is also shown in the web dashboard at /dashboard.
    """
    rprint(f"[bold]KeyCrawl[/bold] → scanning [blue]{url}[/blue] (depth={depth}, max_pages={max_pages})")

    if persist:
        rprint("[yellow]--persist enabled: only redacted findings will be written to the DB.[/yellow]")

    try:
        result: ScanResult = asyncio.run(
            crawl_and_scan(
                url,
                max_depth=depth,
                max_pages=max_pages,
                same_domain_only=same_domain,
                concurrency=concurrency,
                request_delay=delay,
                timeout_per_page=timeout,
            )
        )
    except KeyboardInterrupt:
        rprint("\n[red]Interrupted by user[/red]")
        raise typer.Exit(130)
    except Exception as exc:
        rprint(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(1)

    # Always prepare a safe (redacted) version
    safe_findings = findings_to_safe_dicts(result.findings)

    if json_output:
        # Never include raw .value
        safe = result.model_dump(mode="json")
        for f in safe.get("findings", []):
            f.pop("value", None)
        print(json.dumps(safe, indent=2, ensure_ascii=False))
        if persist:
            _persist_redacted(result, safe_findings)
        return

    _print_findings_table(result.findings, url)

    stats = result.stats
    rprint(f"\n[dim]Pages crawled: {result.pages_crawled} | Duration: {stats.get('duration_sec')}s | Errors: {len(result.errors)}[/dim]")

    if persist:
        _persist_redacted(result, safe_findings)


def _persist_redacted(result: ScanResult, safe_findings: list[dict]) -> None:
    """Helper to persist redacted findings from CLI."""
    try:
        storage.init_db_sync()
        scan_id = f"cli-{int(time.time())}"
        storage.save_redacted_scan_sync(
            scan_id=scan_id,
            target=result.target,
            started_at=result.started_at,
            finished_at=result.finished_at or time.time(),
            pages_crawled=result.pages_crawled,
            safe_findings=safe_findings,
        )
        rprint(f"[green]✓ Redacted findings persisted to DB (scan_id={scan_id}).[/green]")
        rprint("[dim]Open the web dashboard (/dashboard) or use the web UI to browse the collection by category.[/dim]")
    except Exception as e:
        rprint(f"[red]Failed to persist to DB: {e}[/red]")


@app.command()
def patterns():
    """List all built-in secret detection patterns."""
    from .scanner import PATTERNS

    table = Table(title="KeyCrawl Built-in Patterns")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Multiline", style="dim")

    for name, regex, _, desc, multiline in PATTERNS:
        table.add_row(name, desc, "yes" if multiline else "no")

    console.print(table)
    rprint("\n[dim]Plus high-entropy string heuristic (base64/hex-like, Shannon entropy).[/dim]")


@app.command()
def check(
    text: str = typer.Argument(..., help="Raw text/blob to test against the secret finders (for debugging)"),
):
    """Quickly test the secret finders against a piece of text (no network)."""
    findings = find_secrets_in_text(text, source_url="local:input")
    if not findings:
        rprint("[green]No secrets detected in the provided text.[/green]")
        return
    _print_findings_table(findings, "stdin")


if __name__ == "__main__":
    app()
