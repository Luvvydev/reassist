from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import Analysis
from .util import ensure_dir


def load_analysis(path: str) -> Analysis:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Analysis.model_validate(data)


def render_reports(analysis: Analysis, out_dir: str) -> tuple[str, str]:
    ensure_dir(out_dir)

    templates_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    generated_at = datetime.now(timezone.utc).isoformat()

    html_t = env.get_template("report.html.j2")
    md_t = env.get_template("report.md.j2")

    html = html_t.render(a=analysis, generated_at=generated_at)
    md = md_t.render(a=analysis, generated_at=generated_at)

    html_path = str(Path(out_dir) / "report.html")
    md_path = str(Path(out_dir) / "report.md")

    Path(html_path).write_text(html, encoding="utf-8")
    Path(md_path).write_text(md, encoding="utf-8")

    return html_path, md_path
