from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.syntax import Syntax

from .models import Analysis
from .report import render_reports
from .triage import triage

app = typer.Typer(add_completion=False, help="REAssist: evidence-first RE triage and reporting.")
console = Console()


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")


@app.command("triage")
def triage_cmd(
    binary: str = typer.Argument(..., help="Path to binary or file to triage"),
    out: str = typer.Option("analysis.json", "--out", "-o", help="Output JSON path"),
    min_len: int = typer.Option(10, "--min-len", help="Minimum string length"),
    max_strings: int = typer.Option(8000, "--max-strings", help="Max strings to keep in sample"),
) -> None:
    """Run strings triage, IOC extraction, and import hints."""
    a = triage(binary, min_string_len=min_len, max_strings=max_strings)
    out_path = Path(out)
    _write_json(out_path, a.model_dump())
    console.print(f"Wrote [bold]{out_path}[/bold]")


@app.command("report")
def report_cmd(
    analysis_json: str = typer.Argument(..., help="Path to analysis JSON"),
    out_dir: str = typer.Option("out", "--out-dir", "-o", help="Output directory"),
) -> None:
    """Render HTML and Markdown reports from an analysis JSON."""
    data = json.loads(Path(analysis_json).read_text(encoding="utf-8"))
    a = Analysis.model_validate(data)
    html_path, md_path = render_reports(a, out_dir)
    console.print(f"Wrote [bold]{html_path}[/bold]")
    console.print(f"Wrote [bold]{md_path}[/bold]")


@app.command("merge-ghidra")
def merge_ghidra(
    analysis_json: str = typer.Argument(..., help="Path to analysis JSON"),
    ghidra_json: str = typer.Argument(..., help="Path to Ghidra export JSON"),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Output JSON (default overwrites analysis_json)"),
) -> None:
    """Attach a Ghidra export JSON into an existing analysis JSON."""
    a_path = Path(analysis_json)
    a = Analysis.model_validate(json.loads(a_path.read_text(encoding="utf-8")))
    g = json.loads(Path(ghidra_json).read_text(encoding="utf-8"))
    a.ghidra_export = g
    out_path = Path(out) if out else a_path
    _write_json(out_path, a.model_dump())
    console.print(f"Wrote [bold]{out_path}[/bold]")


@app.command("show")
def show(
    analysis_json: str = typer.Argument(..., help="Path to analysis JSON"),
    max_lines: int = typer.Option(200, "--max-lines", help="Max lines to show"),
) -> None:
    """Pretty print an analysis JSON to the terminal."""
    p = Path(analysis_json)
    text = p.read_text(encoding="utf-8")
    # Keep it readable in terminals
    lines = text.splitlines()
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines] + ["... (truncated)"])
    console.print(Syntax(text, "json", word_wrap=True))


if __name__ == "__main__":
    app()
