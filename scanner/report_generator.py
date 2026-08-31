"""
scanner/report_generator.py

Report Generator.

Produces downloadable scan reports in two formats:
  * PDF  - built with reportlab (Executive Summary, Target Info,
           Findings table, Risk Summary, Recommendations)
  * HTML - rendered via a Jinja2 template for in-browser viewing/printing

Both formats share the same sections and data source (a scan record
plus its findings), so the reports stay consistent with each other.
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

SEVERITY_COLORS = {
    "High": colors.HexColor("#e53e3e"),
    "Medium": colors.HexColor("#dd6b20"),
    "Low": colors.HexColor("#d69e2e"),
    "Informational": colors.HexColor("#3182ce"),
}


def _severity_counts(findings):
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def generate_pdf(scan, findings, info=None):
    """Generate a PDF report for the given scan + findings. Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"scan_{scan['id']}_report.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=letter,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#0b1220"))
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#1a2332"),
                               spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9.5, leading=13)

    counts = _severity_counts(findings)
    story = []

    story.append(Paragraph("Web Application Security Scan Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body_style))
    story.append(Spacer(1, 16))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2_style))
    total = len(findings)
    story.append(Paragraph(
        f"This report presents the results of an automated, non-destructive security assessment "
        f"of <b>{scan['target']}</b> performed on {scan['date']}. A total of <b>{total}</b> findings "
        f"were identified: <b>{counts['High']}</b> High, <b>{counts['Medium']}</b> Medium, "
        f"<b>{counts['Low']}</b> Low, and <b>{counts['Informational']}</b> Informational severity.",
        body_style,
    ))
    story.append(Spacer(1, 10))

    # Target Information
    story.append(Paragraph("Target Information", h2_style))
    target_rows = [["Field", "Value"], ["Target URL", scan["target"]], ["Scan Date", scan["date"]],
                   ["Status", scan["status"]], ["Pages Discovered", str(scan.get("pages_discovered", 0))],
                   ["Forms Discovered", str(scan.get("forms_discovered", 0))]]
    if info:
        target_rows.append(["Page Title", str(info.get("title", "N/A"))])
        target_rows.append(["Server", str(info.get("server", "N/A"))])
        target_rows.append(["Technologies", ", ".join(info.get("technologies", [])) or "None identified"])

    t = Table(target_rows, colWidths=[1.8 * inch, 4.4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f8")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Risk Summary
    story.append(Paragraph("Risk Summary", h2_style))
    risk_rows = [["Severity", "Count"]] + [[sev, str(counts[sev])] for sev in
                                            ("High", "Medium", "Low", "Informational")]
    rt = Table(risk_rows, colWidths=[2 * inch, 1 * inch])
    row_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]
    for idx, sev in enumerate(("High", "Medium", "Low", "Informational"), start=1):
        row_styles.append(("TEXTCOLOR", (0, idx), (0, idx), SEVERITY_COLORS[sev]))
        row_styles.append(("FONTNAME", (0, idx), (0, idx), "Helvetica-Bold"))
    rt.setStyle(TableStyle(row_styles))
    story.append(rt)
    story.append(PageBreak())

    # Vulnerability Findings
    story.append(Paragraph("Vulnerability Findings", h2_style))
    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.", body_style))
    for f in findings:
        sev = f["severity"]
        header = f"<font color='{SEVERITY_COLORS.get(sev, colors.black).hexval()}'><b>[{sev}]</b></font> {f['vulnerability']}"
        story.append(Paragraph(header, ParagraphStyle("FindingTitle", parent=styles["Heading3"],
                                                        spaceBefore=10, spaceAfter=2)))
        if f.get("url"):
            story.append(Paragraph(f"<b>Affected URL:</b> {f['url']}", body_style))
        if f.get("description"):
            story.append(Paragraph(f"<b>Description:</b> {f['description']}", body_style))
        if f.get("evidence"):
            story.append(Paragraph(f"<b>Evidence:</b> {f['evidence']}", body_style))
        if f.get("recommendation"):
            story.append(Paragraph(f"<b>Recommendation:</b> {f['recommendation']}", body_style))
        story.append(Spacer(1, 4))

    # Recommendations summary
    story.append(PageBreak())
    story.append(Paragraph("General Recommendations", h2_style))
    story.append(Paragraph(
        "Prioritize remediation of High severity findings first, followed by Medium and Low. "
        "Re-run this scan after remediation to confirm issues are resolved. This automated "
        "scan provides a baseline assessment only and does not replace a manual penetration "
        "test performed by a qualified security professional with proper authorization.",
        body_style,
    ))

    doc.build(story)
    return filepath


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Scan Report - {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0b1220; color: #e2e8f0; margin: 0; padding: 40px; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #131c2e; border-radius: 10px; padding: 32px; }}
  h1 {{ color: #38bdf8; margin-top: 0; }}
  h2 {{ color: #93c5fd; border-bottom: 1px solid #2a3a55; padding-bottom: 6px; margin-top: 32px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a3a55; font-size: 14px; }}
  th {{ background: #1c2942; color: #93c5fd; }}
  .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: #0b1220; }}
  .High {{ background: #f87171; }}
  .Medium {{ background: #fb923c; }}
  .Low {{ background: #fbbf24; }}
  .Informational {{ background: #60a5fa; }}
  .finding {{ background: #0f1b30; border: 1px solid #2a3a55; border-radius: 8px; padding: 16px; margin-top: 14px; }}
  .finding h3 {{ margin: 0 0 8px 0; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-top: 4px; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-top: 14px;}}
  .stat {{ background: #0f1b30; border-radius: 8px; padding: 14px 20px; flex: 1; min-width: 120px; text-align: center; border: 1px solid #2a3a55;}}
  .stat .num {{ font-size: 26px; font-weight: bold; }}
  .stat .label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;}}
  footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>Web Application Security Scan Report</h1>
  <p class="meta">Target: <b>{target}</b> &nbsp;|&nbsp; Scan Date: {date} &nbsp;|&nbsp; Status: {status}</p>

  <h2>Executive Summary</h2>
  <p>This report presents the results of an automated, non-destructive security assessment of
  <b>{target}</b>. A total of <b>{total}</b> findings were identified.</p>
  <div class="stats">
    <div class="stat"><div class="num" style="color:#f87171">{high}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#fb923c">{medium}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#fbbf24">{low}</div><div class="label">Low</div></div>
    <div class="stat"><div class="num" style="color:#60a5fa">{info}</div><div class="label">Info</div></div>
  </div>

  <h2>Target Information</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Target URL</td><td>{target}</td></tr>
    <tr><td>Pages Discovered</td><td>{pages_discovered}</td></tr>
    <tr><td>Forms Discovered</td><td>{forms_discovered}</td></tr>
  </table>

  <h2>Vulnerability Findings</h2>
  {findings_html}

  <h2>Recommendations</h2>
  <p>Prioritize remediation of High severity findings first. Re-run this scan after remediation
  to confirm issues are resolved. This automated scan is a baseline assessment only and does not
  replace a manual penetration test performed under proper authorization.</p>

  <footer>Generated by Web Application Security Scanner &mdash; for educational / portfolio use.</footer>
</div>
</body>
</html>
"""

FINDING_TEMPLATE = """
<div class="finding">
  <h3><span class="badge {severity}">{severity}</span> &nbsp; {vulnerability}</h3>
  <p><b>Affected URL:</b> {url}</p>
  <p><b>Description:</b> {description}</p>
  <p><b>Evidence:</b> {evidence}</p>
  <p><b>Recommendation:</b> {recommendation}</p>
</div>
"""


def generate_html(scan, findings, info=None):
    """Generate an HTML report for the given scan + findings. Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"scan_{scan['id']}_report.html"
    filepath = os.path.join(REPORTS_DIR, filename)

    counts = _severity_counts(findings)
    findings_html = "".join(
        FINDING_TEMPLATE.format(
            severity=f["severity"],
            vulnerability=f["vulnerability"],
            url=f.get("url") or "N/A",
            description=f.get("description") or "N/A",
            evidence=f.get("evidence") or "N/A",
            recommendation=f.get("recommendation") or "N/A",
        )
        for f in findings
    ) or "<p>No findings were recorded for this scan.</p>"

    html = HTML_TEMPLATE.format(
        target=scan["target"],
        date=scan["date"],
        status=scan["status"],
        total=len(findings),
        high=counts["High"], medium=counts["Medium"], low=counts["Low"], info=counts["Informational"],
        pages_discovered=scan.get("pages_discovered", 0),
        forms_discovered=scan.get("forms_discovered", 0),
        findings_html=findings_html,
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath
