"""
Render a Changes AI markdown report to a styled PDF via WeasyPrint.

Public API:
    render_report_html(md_text, css_path=None) -> str
        Convert a Changes AI markdown report into a styled HTML document.

    render_report_html_bundle(md_text, css_path=None) -> dict[str, str]
        Convert a Changes AI markdown report into an HTML bundle with
        index.html and style.css assets.

    render_report_pdf(md_text, css_path=None) -> bytes
        Convert a Changes AI markdown report into PDF bytes via WeasyPrint.
        Drop-in replacement for the previous hand-rolled PDF renderer.

Integration with reporting.py:

    from .render_report import render_report_pdf

    def render_pdf_report(report: dict) -> bytes:
        markdown = render_markdown_report(report)
        return render_report_pdf(markdown)
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import markdown as md_lib

try:
    from . import __version__
except ImportError:  # pragma: no cover - direct script execution path
    from src import __version__

DEFAULT_TEMPLATE = "corporate"
REPORT_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "reports"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
EXEC_SUMMARY_META_PREFIX = "<!-- executive-summary-meta:"


# ---------------------------------------------------------------------------
# Markdown parsing helpers
# ---------------------------------------------------------------------------


def _resolve_css_path(template: str | Path) -> Path:
    """Resolve a template name (e.g. 'corporate') or an explicit path."""
    candidate = Path(template).expanduser()
    if (
        isinstance(template, Path)
        or candidate.suffix == ".css"
        or len(candidate.parts) > 1
    ):
        return candidate
    return REPORT_TEMPLATES_DIR / f"{candidate.name}.css"


def _load_report_css(css_path: str | Path | None = None) -> tuple[Path, str]:
    css_template = css_path or DEFAULT_TEMPLATE
    resolved_css_path = _resolve_css_path(css_template)
    if not resolved_css_path.is_file():
        available_templates = (
            ", ".join(sorted(p.stem for p in REPORT_TEMPLATES_DIR.glob("*.css")))
            or "(none found)"
        )
        raise ValueError(
            f"CSS template not found: {css_template!r} resolved to "
            f"'{resolved_css_path}'. Available built-in templates in "
            f"'{REPORT_TEMPLATES_DIR}': {available_templates}"
        )
    return resolved_css_path, resolved_css_path.read_text(encoding="utf-8")


def _extract_summary(md_text: str) -> dict[str, str]:
    """Pull the executive summary fields out of the markdown so we can
    render them in a structured panel rather than as a bullet list."""
    summary: dict[str, str] = {}
    in_block = False
    for line in md_text.splitlines():
        if line.strip().startswith("## Executive Summary"):
            in_block = True
            continue
        if in_block:
            if line.startswith("##"):
                break
            if line.strip().startswith(EXEC_SUMMARY_META_PREFIX):
                meta = (
                    line.strip()[len(EXEC_SUMMARY_META_PREFIX) :]
                    .removesuffix("-->")
                    .strip()
                )
                try:
                    parsed = json.loads(meta)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, dict):
                    return {str(key): str(value) for key, value in parsed.items()}
            m = re.match(r"^- ([^:]+):\s*(.+)$", line)
            if m:
                summary[m.group(1).strip()] = m.group(2).strip()
    return summary


def _extract_executive_summary_content(md_text: str) -> str:
    """Return the markdown body of the executive summary section."""
    lines: list[str] = []
    in_block = False
    for line in md_text.splitlines():
        if line.strip().startswith("## Executive Summary"):
            in_block = True
            continue
        if in_block:
            if line.startswith("## "):
                break
            if line.strip().startswith(EXEC_SUMMARY_META_PREFIX):
                continue
            lines.append(line)
    return "\n".join(lines).strip()


def _strip_executive_summary(md_text: str) -> str:
    """Remove the executive summary section so we can render it as a
    custom HTML panel instead of a bullet list."""
    lines = md_text.splitlines()
    out: list[str] = []
    skip = False
    for line in lines:
        if line.strip().startswith("## Executive Summary"):
            skip = True
            continue
        if skip and line.startswith("## "):
            skip = False
        if not skip:
            out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML post-processing
# ---------------------------------------------------------------------------


def _wrap_severity_cells(html: str) -> str:
    """Wrap CRITICAL/HIGH/MEDIUM/LOW table cells in a styled pill, but ONLY
    in tables that have a 'Severity' column (not Confidence/Breakage).
    Also tag the parent <tr> for the left-border severity accent."""

    def table_repl(match: re.Match) -> str:
        table_html = match.group(0)
        header_match = re.search(r"<thead>(.*?)</thead>", table_html, re.DOTALL)
        if not header_match:
            return table_html
        header = header_match.group(1)
        if "Severity" not in header:
            return table_html

        def cell_repl(m: re.Match) -> str:
            sev = m.group(1)
            return (
                f'<td class="severity"><span class="pill sev-{sev}">{sev}</span></td>'
            )

        styled = re.sub(
            r"<td>(" + "|".join(SEVERITIES) + r")</td>",
            cell_repl,
            table_html,
        )

        def row_repl(m: re.Match) -> str:
            row_html = m.group(0)
            for sev in SEVERITIES:
                if f"sev-{sev}" in row_html:
                    return row_html.replace("<tr>", f'<tr class="row-{sev}">', 1)
            return row_html

        styled = re.sub(r"<tr>.*?</tr>", row_repl, styled, flags=re.DOTALL)
        return styled

    return re.sub(r"<table>.*?</table>", table_repl, html, flags=re.DOTALL)


def _wrap_remediation_paths(html: str) -> str:
    """Convert each <h3>Path Name</h3> + following content into a styled
    .path block with header, scores, rationale, and table."""
    pattern = re.compile(
        r"(<h3>([^<]+)</h3>\s*<p>Exposure:\s*([\d.]+)\s+Breakage:\s*([\d.]+)\s+Confidence:\s*(\w+)</p>)(.*?)(?=<h3>|<h2>|$)",
        re.DOTALL,
    )

    def repl(match: re.Match) -> str:
        title = match.group(2)
        exposure = match.group(3)
        breakage = match.group(4)
        confidence = match.group(5)
        body = match.group(6)

        nofix_match = re.search(r"<p>No fix:\s*([^<]+)</p>", body)
        nofix_html = ""
        if nofix_match:
            nofix_html = (
                f'<div class="nofix"><span class="label">No Fix Available</span>'
                f"{nofix_match.group(1).strip()}</div>"
            )
            body = body.replace(nofix_match.group(0), "")

        return (
            '<div class="path">'
            '<div class="path-header">'
            f'<h3 class="path-title">{title}</h3>'
            '<div class="path-scores">'
            f'<span class="score-label">Exposure</span>'
            f'<span class="score-value">{exposure}</span>'
            f'<span class="score-label">Breakage</span>'
            f'<span class="score-value">{breakage}</span>'
            f'<span class="score-label">Confidence</span>'
            f'<span class="score-value">{confidence}</span>'
            "</div>"
            "</div>"
            f"{body}"
            f"{nofix_html}"
            "</div>"
        )

    return pattern.sub(repl, html)


def _wrap_limitations(html: str) -> str:
    """Wrap the limitations section in a styled callout."""
    pattern = re.compile(
        r"<h2>Limitations and Confidence Notes</h2>(.*?)(?=<h2>|$)",
        re.DOTALL,
    )

    def repl(match: re.Match) -> str:
        body = match.group(1)
        return (
            '<div class="limitations">'
            "<h2>Limitations and Confidence Notes</h2>"
            f"{body}"
            "</div>"
        )

    return pattern.sub(repl, html)


def _wrap_impact_analysis(html: str) -> str:
    """Wrap the impact evidence list in a dedicated container."""
    pattern = re.compile(
        r"(<h2>Impact Summary</h2>.*?)(<ul>.*?</ul>)(?=(?:\s*<div class=\"section-rule\"></div>\s*<h2>)|\s*<h2>|$)",
        re.DOTALL,
    )

    def repl(match: re.Match) -> str:
        before_list = match.group(1)
        list_html = match.group(2)
        return f'{before_list}<div class="impact-analysis">{list_html}</div>'

    return pattern.sub(repl, html, count=1)


def _add_section_rules(html: str) -> str:
    """Insert a gold accent rule before each h2 (except those already
    inside a .limitations wrapper, which has its own treatment)."""
    return re.sub(
        r'(?<!<div class="section-rule"></div>)\n?<h2>(?!Limitations)',
        '<div class="section-rule"></div>\n<h2>',
        html,
    )


# ---------------------------------------------------------------------------
# Cover page and exec summary builders
# ---------------------------------------------------------------------------


def _render_cover(summary: dict[str, str]) -> str:
    """Build the cover-page HTML."""
    target = html.escape(summary.get("Target", ""))
    run_id = html.escape(summary.get("Run ID", ""))
    pkgs = html.escape(summary.get("Packages analysed", ""))
    vulns = html.escape(summary.get("Vulnerabilities found", ""))
    paths = html.escape(summary.get("Remediation paths", ""))
    gen = datetime.now(timezone.utc).strftime("%d %B %Y · %H:%M UTC")

    return f"""
<section class="cover">
  <div class="navy-band">
    <div class="brand">Changes AI</div>
    <h1>Vulnerability<br>Remediation Report</h1>
    <p class="subtitle">AI-assisted change-impact analysis for Python software dependencies.</p>
    <div class="navy-band-rule"></div>
  </div>
  <div class="body">
    <div class="meta-heading">Report Details</div>
    <div class="metadata">
      <table>
        <tr><td class="label">Run ID</td><td class="value mono"><span class="run-id">{run_id}</span></td></tr>
        <tr><td class="label">Target</td><td class="value mono">{target}</td></tr>
        <tr><td class="label">Packages analysed</td><td class="value">{pkgs}</td></tr>
        <tr><td class="label">Vulnerabilities found</td><td class="value">{vulns}</td></tr>
        <tr><td class="label">Remediation paths</td><td class="value">{paths}</td></tr>
        <tr><td class="label">Generated</td><td class="value"><span class="gen-date">{gen}</span></td></tr>
      </table>
    </div>
    <div class="footer">
      <span class="left">Confidential · Internal Use</span>
            <span class="right">Changes AI - v{__version__}</span>
    </div>
  </div>
</section>
"""


def _render_exec_summary(summary: dict[str, str]) -> str:
    """Build the inline executive summary panel."""
    rows = "".join(
        f'<tr><td class="label">{html.escape(str(label))}</td><td class="value">'
        f"{html.escape(str(value))}"
        f"</td></tr>"
        for label, value in summary.items()
    )
    return f"""
<div class="section-rule"></div>
<h1>Executive Summary</h1>
<div class="exec-summary">
  <table>{rows}</table>
</div>
"""


def _render_exec_summary_narrative(
    summary_markdown: str, summary: dict[str, str]
) -> str:
    """Build the inline executive summary narrative panel."""
    if summary_markdown:
        summary_html = md_lib.markdown(summary_markdown, extensions=["sane_lists"])
        return f"""
<div class="section-rule"></div>
<h1>Executive Summary</h1>
<div class="exec-summary">
    {summary_html}
</div>
"""
    return _render_exec_summary(summary)


def _build_report_html_document(md_text: str, stylesheet_markup: str) -> str:
    summary = _extract_summary(md_text)
    summary_markdown = _extract_executive_summary_content(md_text)
    body_md = _strip_executive_summary(md_text)
    # Strip the top-level H1 (cover renders separately)
    body_md = re.sub(r"^# .+?\n+", "", body_md, count=1)

    body_html = md_lib.markdown(body_md, extensions=["tables", "sane_lists"])
    body_html = _wrap_severity_cells(body_html)
    body_html = _wrap_remediation_paths(body_html)
    body_html = _wrap_limitations(body_html)
    body_html = _wrap_impact_analysis(body_html)
    body_html = _add_section_rules(body_html)

    cover_html = _render_cover(summary)
    exec_html = _render_exec_summary_narrative(summary_markdown, summary)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Changes AI Remediation Report</title>
{stylesheet_markup}
</head>
<body>
{cover_html}
<main>
{exec_html}
{body_html}
</main>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_report_html(md_text: str, css_path: str | Path | None = None) -> str:
    """Convert a Changes AI markdown report into a styled HTML document.

    The returned HTML embeds the CSS inline so it can be passed directly
    to any HTML-to-PDF renderer.
    """
    _, css_text = _load_report_css(css_path)
    return _build_report_html_document(md_text, f"<style>{css_text}</style>")


def render_report_html_bundle(
    md_text: str, css_path: str | Path | None = None
) -> dict[str, str]:
    """Convert a Changes AI markdown report into an HTML asset bundle."""
    _, css_text = _load_report_css(css_path)
    return {
        "index.html": _build_report_html_document(
            md_text,
            '<link rel="stylesheet" href="style.css">',
        ),
        "style.css": css_text,
    }


def render_report_pdf(md_text: str, css_path: str | Path | None = None) -> bytes:
    """Convert a Changes AI markdown report into PDF bytes via WeasyPrint.

    Drop-in replacement for the previous hand-rolled PDF renderer.

    Requires WeasyPrint to be installed:
        pip install weasyprint

    Note: WeasyPrint depends on system libraries (Pango, cairo, GDK-PixBuf).
        macOS:   brew install pango
        Debian:  apt-get install libpango-1.0-0 libpangoft2-1.0-0
        Windows: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html
    """
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint is required for PDF rendering. Install with:\n"
            "    pip install weasyprint\n"
            "See https://doc.courtbouillon.org/weasyprint/ for system dependencies."
        ) from exc

    html_string = render_report_html(md_text, css_path=css_path)
    pdf_bytes = HTML(string=html_string).write_pdf()
    if pdf_bytes is None:
        raise RuntimeError("WeasyPrint did not return PDF bytes")
    return pdf_bytes


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: render_report.py INPUT.md [OUTPUT.pdf|--html]\n"
            "  Default output: input filename with .pdf extension.\n"
            "  --html: emit styled HTML to stdout instead of writing a PDF.",
            file=sys.stderr,
        )
        sys.exit(1)

    input_path = Path(sys.argv[1])
    md_text = input_path.read_text()

    if len(sys.argv) >= 3 and sys.argv[2] == "--html":
        print(render_report_html(md_text))
    else:
        output_path = (
            Path(sys.argv[2]) if len(sys.argv) >= 3 else input_path.with_suffix(".pdf")
        )
        pdf_bytes = render_report_pdf(md_text)
        output_path.write_bytes(pdf_bytes)
        print(f"Wrote {output_path} ({len(pdf_bytes):,} bytes)", file=sys.stderr)
