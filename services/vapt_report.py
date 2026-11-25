import html
from dataclasses import dataclass
from datetime import date, datetime, timezone
from io import BytesIO

from docx import Document
from fpdf import FPDF

from models.domain import FindingRecord
from models.engagement import Engagement, ManualFinding
from services.risk_score import calculate_risk_score, count_by_severity, risk_grade_label

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(slots=True)
class _ReportItem:
    ref: str
    kind: str
    title: str
    host: str
    severity: str
    cve_id: str | None
    owasp_category: str | None
    cvss_score: float | None
    description: str
    evidence: str
    remediation: str
    status: str
    retest_notes: str | None
    retested_at: datetime | None
    source: str


def _safe_pdf_text(text: str) -> str:
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _fmt_date(value: date | datetime | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return value.isoformat()


def _fmt_cvss(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "-"


def _merge_findings(
    scanner_findings: list[FindingRecord],
    manual_findings: list[ManualFinding],
) -> list[_ReportItem]:
    items: list[_ReportItem] = []

    for finding in scanner_findings:
        items.append(
            _ReportItem(
                ref="",
                kind="A",
                title=finding.title,
                host=finding.host,
                severity=finding.severity,
                cve_id=finding.cve_id,
                owasp_category=finding.owasp_category,
                cvss_score=finding.cvss_score,
                description=finding.explanation,
                evidence=finding.evidence,
                remediation=finding.remediation,
                status="open",
                retest_notes=None,
                retested_at=None,
                source=finding.source or finding.scanner,
            )
        )

    for finding in manual_findings:
        evidence = finding.evidence
        screenshots = finding.screenshots
        if screenshots:
            evidence = f"{evidence} [screenshots: {', '.join(screenshots)}]"
        items.append(
            _ReportItem(
                ref="",
                kind="M",
                title=finding.title,
                host=finding.affected_host,
                severity=finding.severity,
                cve_id=None,
                owasp_category=finding.owasp_category,
                cvss_score=finding.cvss_score,
                description=finding.description,
                evidence=evidence,
                remediation=finding.remediation,
                status=finding.status,
                retest_notes=finding.retest_notes,
                retested_at=finding.retested_at,
                source=f"manual ({finding.discovered_by})",
            )
        )

    items.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item.severity.lower(), 9),
            item.host.lower(),
            item.title.lower(),
        )
    )

    counters = {"A": 0, "M": 0}
    for item in items:
        counters[item.kind] += 1
        item.ref = f"{item.kind}-{counters[item.kind]:02d}"

    return items


def _risk_summary(items: list[_ReportItem]) -> tuple[int, str, dict[str, int]]:
    severities = [item.severity for item in items]
    score = calculate_risk_score(severities)
    return score, risk_grade_label(score), count_by_severity(severities)


def generate_vapt_html_report(
    engagement: Engagement,
    scanner_findings: list[FindingRecord],
    manual_findings: list[ManualFinding],
) -> str:
    items = _merge_findings(scanner_findings, manual_findings)
    score, grade, counts = _risk_summary(items)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scope_items = "\n".join(
        f"<li><code>{html.escape(entry)}</code></li>" for entry in engagement.scope
    ) or "<li>No scope entries.</li>"

    summary_rows = "\n".join(
        f"""
        <tr>
          <td><code>{html.escape(item.ref)}</code></td>
          <td><strong>{html.escape(item.title)}</strong><br/><small>{html.escape(item.host)}</small></td>
          <td><span class="sev sev-{html.escape(item.severity.lower())}">{html.escape(item.severity.upper())}</span></td>
          <td>{html.escape(item.cve_id or "-")}</td>
          <td>{html.escape(item.owasp_category or "-")}</td>
          <td>{html.escape(_fmt_cvss(item.cvss_score))}</td>
          <td>{html.escape(item.source)}</td>
        </tr>
        """
        for item in items
    ) or "<tr><td colspan='7'>No findings recorded for this engagement.</td></tr>"

    detail_html = "\n".join(
        f"""
        <section class="finding">
          <h3>{html.escape(item.ref)} &middot; {html.escape(item.title)}</h3>
          <div class="meta">
            Host: <code>{html.escape(item.host)}</code> &middot;
            Severity: {html.escape(item.severity.upper())} &middot;
            CVSS: {html.escape(_fmt_cvss(item.cvss_score))} &middot;
            CVE: {html.escape(item.cve_id or "-")} &middot;
            OWASP: {html.escape(item.owasp_category or "-")} &middot;
            Source: {html.escape(item.source)}
          </div>
          <h4>Observation</h4>
          <p>{html.escape(item.description or "-")}</p>
          <h4>Evidence</h4>
          <pre>{html.escape(item.evidence or "-")}</pre>
          <h4>Remediation</h4>
          <p>{html.escape(item.remediation or "-")}</p>
          <h4>Status</h4>
          <p>{html.escape(item.status)}</p>
          <h4>Retest Notes</h4>
          <p>{html.escape(item.retest_notes or "-")}</p>
        </section>
        """
        for item in items
    ) or "<p>No findings recorded.</p>"

    retest_rows = "\n".join(
        f"""
        <tr>
          <td><code>{html.escape(item.ref)}</code></td>
          <td>{html.escape(item.title)}</td>
          <td>{html.escape(item.status)}</td>
          <td>{html.escape(_fmt_date(item.retested_at))}</td>
          <td>{html.escape(item.retest_notes or "-")}</td>
        </tr>
        """
        for item in items
    ) or "<tr><td colspan='5'>No retest data recorded.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SurfaceWatch VAPT Report - {html.escape(engagement.client_name)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #0f172a; margin: 32px; line-height: 1.5; }}
    h1, h2, h3, h4 {{ margin: 0 0 8px 0; }}
    .confidential {{ color: #991b1b; font-weight: 700; letter-spacing: 0.08em; }}
    .meta {{ color: #475569; font-size: 13px; margin-bottom: 16px; }}
    .summary {{ display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }}
    .card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 16px; min-width: 130px; }}
    .card .label {{ font-size: 12px; color: #64748b; }}
    .card .value {{ font-size: 22px; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 10px; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: #f8fafc; }}
    .sev {{ font-weight: 700; font-size: 11px; padding: 2px 6px; border-radius: 4px; }}
    .sev-critical {{ background: #fee2e2; color: #991b1b; }}
    .sev-high {{ background: #ffedd5; color: #9a3412; }}
    .sev-medium {{ background: #fef3c7; color: #92400e; }}
    .sev-low {{ background: #e0f2fe; color: #075985; }}
    .sev-info {{ background: #f1f5f9; color: #334155; }}
    .finding {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 16px 0; }}
    pre {{ background: #f8fafc; padding: 8px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; }}
    .footer {{ margin-top: 32px; padding: 12px; border-top: 1px solid #cbd5e1; text-align: center; }}
  </style>
</head>
<body>
  <p class="confidential">CONFIDENTIAL</p>
  <h1>SurfaceWatch Pentest Report</h1>
  <div class="meta">
    Client: <strong>{html.escape(engagement.client_name)}</strong> &middot;
    Tester: {html.escape(engagement.tester)} &middot;
    Authorization: {html.escape(engagement.authorization_reference)}<br/>
    Engagement window: {html.escape(_fmt_date(engagement.start_date))} to {html.escape(_fmt_date(engagement.end_date))} &middot;
    Status: {html.escape(engagement.status)} &middot;
    Generated: {generated_at}
  </div>

  <h2>1. Executive Summary</h2>
  <p>
    This report summarizes an authorized penetration-testing engagement against the scope
    listed below. SurfaceWatch combined safe-mode automated checks with manual analyst findings.
    The overall risk is <strong>{score}/100 ({html.escape(grade)})</strong>.
  </p>
  <div class="summary">
    <div class="card"><div class="label">Overall Risk</div><div class="value">{score}/100 ({html.escape(grade)})</div></div>
    <div class="card"><div class="label">Total Findings</div><div class="value">{len(items)}</div></div>
    <div class="card"><div class="label">Critical</div><div class="value">{counts["critical"]}</div></div>
    <div class="card"><div class="label">High</div><div class="value">{counts["high"]}</div></div>
    <div class="card"><div class="label">Medium</div><div class="value">{counts["medium"]}</div></div>
    <div class="card"><div class="label">Low</div><div class="value">{counts["low"]}</div></div>
    <div class="card"><div class="label">Info</div><div class="value">{counts["info"]}</div></div>
  </div>

  <h2>2. Scope &amp; Methodology</h2>
  <p>The following exact scope entries were authorized for this engagement:</p>
  <ul>{scope_items}</ul>
  <p>
    Methodology: passive reconnaissance plus safe-mode Nmap service detection and nuclei
    templates. Intrusive, denial-of-service, fuzzing, and brute-force template tags are
    excluded. Every active check passed the engagement scope gate before touching the network.
  </p>
  {f"<p><strong>Engagement notes:</strong> {html.escape(engagement.notes)}</p>" if engagement.notes else ""}

  <h2>3. Findings Summary</h2>
  <table>
    <thead>
      <tr><th>Ref</th><th>Finding</th><th>Severity</th><th>CVE</th><th>OWASP</th><th>CVSS</th><th>Source</th></tr>
    </thead>
    <tbody>{summary_rows}</tbody>
  </table>

  <h2>4. Detailed Findings</h2>
  {detail_html}

  <h2>5. Retest Summary</h2>
  <table>
    <thead>
      <tr><th>Ref</th><th>Finding</th><th>Status</th><th>Retested At</th><th>Retest Notes</th></tr>
    </thead>
    <tbody>{retest_rows}</tbody>
  </table>

  <div class="footer confidential">CONFIDENTIAL &middot; Authorized engagement {html.escape(engagement.authorization_reference)} &middot; SurfaceWatch</div>
</body>
</html>
"""


def _pdf_heading(pdf: FPDF, text: str, size: int = 12) -> None:
    pdf.set_font("Helvetica", "B", size)
    pdf.multi_cell(0, 6, _safe_pdf_text(text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _pdf_body(pdf: FPDF, text: str, size: int = 9) -> None:
    pdf.set_font("Helvetica", "", size)
    pdf.multi_cell(0, 5, _safe_pdf_text(text or "-"), new_x="LMARGIN", new_y="NEXT")


def generate_vapt_pdf_report(
    engagement: Engagement,
    scanner_findings: list[FindingRecord],
    manual_findings: list[ManualFinding],
) -> bytes:
    items = _merge_findings(scanner_findings, manual_findings)
    score, grade, counts = _risk_summary(items)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(153, 27, 27)
    pdf.cell(0, 6, "CONFIDENTIAL", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(15, 23, 42)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(
        0,
        10,
        _safe_pdf_text(f"SurfaceWatch Pentest Report: {engagement.client_name}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    _pdf_body(
        pdf,
        f"Tester: {engagement.tester} | Authorization: {engagement.authorization_reference} | "
        f"Status: {engagement.status} | Window: {_fmt_date(engagement.start_date)} to "
        f"{_fmt_date(engagement.end_date)} | Generated: {generated_at}",
    )
    pdf.ln(3)

    _pdf_heading(pdf, "1. Executive Summary", 13)
    _pdf_body(
        pdf,
        "This report summarizes an authorized penetration-testing engagement against the scope "
        "listed below. SurfaceWatch combined safe-mode automated checks with manual analyst "
        f"findings. Overall risk: {score}/100 ({grade}). Total findings: {len(items)} "
        f"(critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, "
        f"low={counts['low']}, info={counts['info']}).",
    )
    pdf.ln(2)

    _pdf_heading(pdf, "2. Scope & Methodology", 13)
    _pdf_body(pdf, "Authorized scope entries:")
    for entry in engagement.scope:
        _pdf_body(pdf, f"  - {entry}")
    _pdf_body(
        pdf,
        "Methodology: passive reconnaissance plus safe-mode Nmap service detection and nuclei "
        "templates. Intrusive, denial-of-service, fuzzing, and brute-force template tags are "
        "excluded. Every active check passed the engagement scope gate before touching the "
        "network.",
    )
    if engagement.notes:
        _pdf_body(pdf, f"Engagement notes: {engagement.notes}")
    pdf.ln(2)

    _pdf_heading(pdf, "3. Findings Summary", 13)
    for item in items:
        _pdf_body(
            pdf,
            f"{item.ref} | {item.severity.upper()} | {item.title} | host={item.host} | "
            f"CVE={item.cve_id or '-'} | OWASP={item.owasp_category or '-'} | "
            f"CVSS={_fmt_cvss(item.cvss_score)} | source={item.source}",
            8,
        )
    if not items:
        _pdf_body(pdf, "No findings recorded for this engagement.")
    pdf.ln(2)

    _pdf_heading(pdf, "4. Detailed Findings", 13)
    for item in items:
        _pdf_heading(pdf, f"{item.ref} - {item.title}", 10)
        _pdf_body(
            pdf,
            f"Host: {item.host} | Severity: {item.severity.upper()} | "
            f"CVSS: {_fmt_cvss(item.cvss_score)} | CVE: {item.cve_id or '-'} | "
            f"OWASP: {item.owasp_category or '-'} | Source: {item.source}",
            8,
        )
        _pdf_body(pdf, f"Observation: {item.description}", 8)
        _pdf_body(pdf, f"Evidence: {item.evidence}", 8)
        _pdf_body(pdf, f"Remediation: {item.remediation}", 8)
        _pdf_body(
            pdf,
            f"Status: {item.status} | Retest notes: {item.retest_notes or '-'}",
            8,
        )
        pdf.ln(2)
    if not items:
        _pdf_body(pdf, "No findings recorded for this engagement.")
    pdf.ln(2)

    _pdf_heading(pdf, "5. Retest Summary", 13)
    for item in items:
        _pdf_body(
            pdf,
            f"{item.ref} | {item.title} | status={item.status} | "
            f"retested_at={_fmt_date(item.retested_at)} | notes={item.retest_notes or '-'}",
            8,
        )
    if not items:
        _pdf_body(pdf, "No retest data recorded.")
    pdf.ln(3)

    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0,
        5,
        _safe_pdf_text(
            f"CONFIDENTIAL - Authorized engagement {engagement.authorization_reference} - "
            "SurfaceWatch. Do not distribute without written consent."
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    return bytes(pdf.output())


def generate_vapt_docx_report(
    engagement: Engagement,
    scanner_findings: list[FindingRecord],
    manual_findings: list[ManualFinding],
) -> bytes:
    items = _merge_findings(scanner_findings, manual_findings)
    score, grade, counts = _risk_summary(items)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    document = Document()
    document.add_heading("CONFIDENTIAL", level=0)
    document.add_heading(f"SurfaceWatch Pentest Report: {engagement.client_name}", level=1)
    document.add_paragraph(
        f"Tester: {engagement.tester} | "
        f"Authorization: {engagement.authorization_reference} | "
        f"Status: {engagement.status} | "
        f"Window: {_fmt_date(engagement.start_date)} to {_fmt_date(engagement.end_date)} | "
        f"Generated: {generated_at}"
    )

    document.add_heading("1. Executive Summary", level=2)
    document.add_paragraph(
        "This report summarizes an authorized penetration-testing engagement against the scope "
        "listed below. SurfaceWatch combined safe-mode automated checks with manual analyst "
        f"findings. Overall risk: {score}/100 ({grade}). Total findings: {len(items)} "
        f"(critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, "
        f"low={counts['low']}, info={counts['info']})."
    )

    document.add_heading("2. Scope & Methodology", level=2)
    document.add_paragraph("Authorized scope entries:")
    for entry in engagement.scope:
        document.add_paragraph(entry, style="List Bullet")
    document.add_paragraph(
        "Methodology: passive reconnaissance plus safe-mode Nmap service detection and nuclei "
        "templates. Intrusive, denial-of-service, fuzzing, and brute-force template tags are "
        "excluded. Every active check passed the engagement scope gate before touching the "
        "network."
    )
    if engagement.notes:
        document.add_paragraph(f"Engagement notes: {engagement.notes}")

    document.add_heading("3. Findings Summary", level=2)
    summary_table = document.add_table(rows=1, cols=7)
    summary_table.style = "Table Grid"
    summary_headers = ["Ref", "Finding", "Severity", "CVE", "OWASP", "CVSS", "Source"]
    for index, header in enumerate(summary_headers):
        summary_table.rows[0].cells[index].text = header
    for item in items:
        cells = summary_table.add_row().cells
        cells[0].text = item.ref
        cells[1].text = f"{item.title} ({item.host})"
        cells[2].text = item.severity.upper()
        cells[3].text = item.cve_id or "-"
        cells[4].text = item.owasp_category or "-"
        cells[5].text = _fmt_cvss(item.cvss_score)
        cells[6].text = item.source
    if not items:
        summary_table.add_row().cells[0].text = "No findings recorded."

    document.add_heading("4. Detailed Findings", level=2)
    if not items:
        document.add_paragraph("No findings recorded for this engagement.")
    for item in items:
        document.add_heading(f"{item.ref} - {item.title}", level=3)
        document.add_paragraph(
            f"Host: {item.host} | Severity: {item.severity.upper()} | "
            f"CVSS: {_fmt_cvss(item.cvss_score)} | CVE: {item.cve_id or '-'} | "
            f"OWASP: {item.owasp_category or '-'} | Source: {item.source}"
        )
        document.add_paragraph(f"Observation: {item.description or '-'}")
        document.add_paragraph(f"Evidence: {item.evidence or '-'}")
        document.add_paragraph(f"Remediation: {item.remediation or '-'}")
        document.add_paragraph(f"Status: {item.status}")
        document.add_paragraph(f"Retest notes: {item.retest_notes or '-'}")

    document.add_heading("5. Retest Summary", level=2)
    retest_table = document.add_table(rows=1, cols=5)
    retest_table.style = "Table Grid"
    retest_headers = ["Ref", "Finding", "Status", "Retested At", "Retest Notes"]
    for index, header in enumerate(retest_headers):
        retest_table.rows[0].cells[index].text = header
    for item in items:
        cells = retest_table.add_row().cells
        cells[0].text = item.ref
        cells[1].text = item.title
        cells[2].text = item.status
        cells[3].text = _fmt_date(item.retested_at)
        cells[4].text = item.retest_notes or "-"
    if not items:
        retest_table.add_row().cells[0].text = "No retest data recorded."

    document.add_paragraph(
        f"CONFIDENTIAL - Authorized engagement {engagement.authorization_reference} - "
        "SurfaceWatch. Do not distribute without written consent."
    )

    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()
