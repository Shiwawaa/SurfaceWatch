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

_GRADE_FR = {
    "Critical": "Critique",
    "High": "Élevé",
    "Medium": "Moyen",
    "Low": "Faible",
    "Info": "Info",
}

_SEV_FR = {
    "critical": "CRITIQUE",
    "high": "ÉLEVÉE",
    "medium": "MOYENNE",
    "low": "FAIBLE",
    "info": "INFO",
}

_STATUS_FR = {
    "active": "actif",
    "on_hold": "en pause",
    "paused": "en pause",
    "completed": "terminé",
    "archived": "archivé",
    "open": "ouvert",
    "remediated": "corrigé",
    "accepted_risk": "risque accepté",
    "false_positive": "faux positif",
    "retested": "retesté",
}

_VAPT_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "html_lang": "en",
        "title_prefix": "SurfaceWatch VAPT Report",
        "confidential": "CONFIDENTIAL",
        "heading": "SurfaceWatch Pentest Report",
        "client": "Client",
        "tester": "Tester",
        "authorization": "Authorization",
        "window": "Engagement window",
        "window_short": "Window",
        "to": "to",
        "status": "Status",
        "generated": "Generated",
        "sec1": "1. Executive Summary",
        "exec_intro": "This report summarizes an authorized penetration-testing engagement against the scope listed below. SurfaceWatch combined safe-mode automated checks with manual analyst findings.",
        "overall_risk_is": "The overall risk is",
        "overall_risk": "Overall Risk",
        "total_findings": "Total Findings",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "sec2": "2. Scope & Methodology",
        "scope_intro": "The following exact scope entries were authorized for this engagement:",
        "scope_list_label": "Authorized scope entries:",
        "no_scope": "No scope entries.",
        "methodology": "Methodology: passive reconnaissance plus safe-mode Nmap service detection and nuclei templates. Intrusive, denial-of-service, fuzzing, and brute-force template tags are excluded. Every active check passed the engagement scope gate before touching the network.",
        "eng_notes": "Engagement notes",
        "sec3": "3. Findings Summary",
        "th_ref": "Ref",
        "th_finding": "Finding",
        "th_severity": "Severity",
        "th_cve": "CVE",
        "th_owasp": "OWASP",
        "th_cvss": "CVSS",
        "th_source": "Source",
        "th_status": "Status",
        "th_retested_at": "Retested At",
        "th_retest_notes": "Retest Notes",
        "sec4": "4. Detailed Findings",
        "host": "Host",
        "severity": "Severity",
        "cvss": "CVSS",
        "cve": "CVE",
        "owasp": "OWASP",
        "source": "Source",
        "observation": "Observation",
        "evidence": "Evidence",
        "remediation": "Remediation",
        "retest_notes": "Retest Notes",
        "sec5": "5. Retest Summary",
        "no_findings_eng": "No findings recorded for this engagement.",
        "no_findings": "No findings recorded.",
        "no_retest": "No retest data recorded.",
        "footer_html": "Authorized engagement",
        "footer_doc": "Do not distribute without written consent.",
    },
    "fr": {
        "html_lang": "fr",
        "title_prefix": "Rapport VAPT SurfaceWatch",
        "confidential": "CONFIDENTIEL",
        "heading": "Rapport de test d'intrusion SurfaceWatch",
        "client": "Client",
        "tester": "Testeur",
        "authorization": "Autorisation",
        "window": "Période de mission",
        "window_short": "Période",
        "to": "au",
        "status": "Statut",
        "generated": "Généré le",
        "sec1": "1. Synthèse exécutive",
        "exec_intro": "Ce rapport résume une mission de test d'intrusion autorisée sur le périmètre indiqué ci-dessous. SurfaceWatch a combiné des contrôles automatisés en mode sûr avec les constats manuels de l'analyste.",
        "overall_risk_is": "Le risque global est",
        "overall_risk": "Risque global",
        "total_findings": "Total des constats",
        "critical": "Critique",
        "high": "Élevée",
        "medium": "Moyenne",
        "low": "Faible",
        "info": "Info",
        "sec2": "2. Périmètre & Méthodologie",
        "scope_intro": "Les entrées de périmètre suivantes ont été autorisées pour cette mission :",
        "scope_list_label": "Entrées de périmètre autorisées :",
        "no_scope": "Aucune entrée de périmètre.",
        "methodology": "Méthodologie : reconnaissance passive ainsi que détection de services Nmap en mode sûr et modèles nuclei. Les modèles intrusifs, de déni de service, de fuzzing et de force brute sont exclus. Chaque contrôle actif a passé le filtre de périmètre avant de toucher le réseau.",
        "eng_notes": "Notes de mission",
        "sec3": "3. Résumé des constats",
        "th_ref": "Réf",
        "th_finding": "Constat",
        "th_severity": "Sévérité",
        "th_cve": "CVE",
        "th_owasp": "OWASP",
        "th_cvss": "CVSS",
        "th_source": "Source",
        "th_status": "Statut",
        "th_retested_at": "Retesté le",
        "th_retest_notes": "Notes de retest",
        "sec4": "4. Constats détaillés",
        "host": "Hôte",
        "severity": "Sévérité",
        "cvss": "CVSS",
        "cve": "CVE",
        "owasp": "OWASP",
        "source": "Source",
        "observation": "Observation",
        "evidence": "Preuve",
        "remediation": "Remédiation",
        "retest_notes": "Notes de retest",
        "sec5": "5. Résumé des retests",
        "no_findings_eng": "Aucun constat enregistré pour cette mission.",
        "no_findings": "Aucun constat enregistré.",
        "no_retest": "Aucune donnée de retest enregistrée.",
        "footer_html": "Mission autorisée",
        "footer_doc": "Ne pas diffuser sans consentement écrit.",
    },
}


def _tr(lang: str) -> dict[str, str]:
    return _VAPT_STRINGS["fr"] if lang == "fr" else _VAPT_STRINGS["en"]


def _grade_label(grade: str, lang: str) -> str:
    return _GRADE_FR.get(grade, grade) if lang == "fr" else grade


def _sev_label(severity: str, lang: str) -> str:
    if lang == "fr":
        return _SEV_FR.get(severity.lower(), severity.upper())
    return severity.upper()


def _status_label(status: str, lang: str) -> str:
    if lang == "fr":
        return _STATUS_FR.get(status.lower(), status)
    return status


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
    normalized = (
        str(text)
        .replace("\u2019", "'")
        .replace("\u2018", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("\u0153", "oe")
        .replace("\u0152", "OE")
    )
    return normalized.encode("latin-1", errors="replace").decode("latin-1")


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
    lang: str = "en",
) -> str:
    s = _tr(lang)
    items = _merge_findings(scanner_findings, manual_findings)
    score, raw_grade, counts = _risk_summary(items)
    grade = _grade_label(raw_grade, lang)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scope_items = "\n".join(
        f"<li><code>{html.escape(entry)}</code></li>" for entry in engagement.scope
    ) or f"<li>{html.escape(s['no_scope'])}</li>"

    summary_rows = "\n".join(
        f"""
        <tr>
          <td><code>{html.escape(item.ref)}</code></td>
          <td><strong>{html.escape(item.title)}</strong><br/><small>{html.escape(item.host)}</small></td>
          <td><span class="sev sev-{html.escape(item.severity.lower())}">{html.escape(_sev_label(item.severity, lang))}</span></td>
          <td>{html.escape(item.cve_id or "-")}</td>
          <td>{html.escape(item.owasp_category or "-")}</td>
          <td>{html.escape(_fmt_cvss(item.cvss_score))}</td>
          <td>{html.escape(item.source)}</td>
        </tr>
        """
        for item in items
    ) or f"<tr><td colspan='7'>{html.escape(s['no_findings_eng'])}</td></tr>"

    detail_html = "\n".join(
        f"""
        <section class="finding">
          <h3>{html.escape(item.ref)} &middot; {html.escape(item.title)}</h3>
          <div class="meta">
            {html.escape(s['host'])}: <code>{html.escape(item.host)}</code> &middot;
            {html.escape(s['severity'])}: {html.escape(_sev_label(item.severity, lang))} &middot;
            {html.escape(s['cvss'])}: {html.escape(_fmt_cvss(item.cvss_score))} &middot;
            {html.escape(s['cve'])}: {html.escape(item.cve_id or "-")} &middot;
            {html.escape(s['owasp'])}: {html.escape(item.owasp_category or "-")} &middot;
            {html.escape(s['source'])}: {html.escape(item.source)}
          </div>
          <h4>{html.escape(s['observation'])}</h4>
          <p>{html.escape(item.description or "-")}</p>
          <h4>{html.escape(s['evidence'])}</h4>
          <pre>{html.escape(item.evidence or "-")}</pre>
          <h4>{html.escape(s['remediation'])}</h4>
          <p>{html.escape(item.remediation or "-")}</p>
          <h4>{html.escape(s['status'])}</h4>
          <p>{html.escape(_status_label(item.status, lang))}</p>
          <h4>{html.escape(s['retest_notes'])}</h4>
          <p>{html.escape(item.retest_notes or "-")}</p>
        </section>
        """
        for item in items
    ) or f"<p>{html.escape(s['no_findings'])}</p>"

    retest_rows = "\n".join(
        f"""
        <tr>
          <td><code>{html.escape(item.ref)}</code></td>
          <td>{html.escape(item.title)}</td>
          <td>{html.escape(_status_label(item.status, lang))}</td>
          <td>{html.escape(_fmt_date(item.retested_at))}</td>
          <td>{html.escape(item.retest_notes or "-")}</td>
        </tr>
        """
        for item in items
    ) or f"<tr><td colspan='5'>{html.escape(s['no_retest'])}</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="{s['html_lang']}">
<head>
  <meta charset="UTF-8" />
  <title>{html.escape(s['title_prefix'])} - {html.escape(engagement.client_name)}</title>
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
  <p class="confidential">{html.escape(s['confidential'])}</p>
  <h1>{html.escape(s['heading'])}</h1>
  <div class="meta">
    {html.escape(s['client'])}: <strong>{html.escape(engagement.client_name)}</strong> &middot;
    {html.escape(s['tester'])}: {html.escape(engagement.tester)} &middot;
    {html.escape(s['authorization'])}: {html.escape(engagement.authorization_reference)}<br/>
    {html.escape(s['window'])}: {html.escape(_fmt_date(engagement.start_date))} {html.escape(s['to'])} {html.escape(_fmt_date(engagement.end_date))} &middot;
    {html.escape(s['status'])}: {html.escape(_status_label(engagement.status, lang))} &middot;
    {html.escape(s['generated'])}: {generated_at}
  </div>

  <h2>{html.escape(s['sec1'])}</h2>
  <p>
    {html.escape(s['exec_intro'])}
    {html.escape(s['overall_risk_is'])} <strong>{score}/100 ({html.escape(grade)})</strong>.
  </p>
  <div class="summary">
    <div class="card"><div class="label">{html.escape(s['overall_risk'])}</div><div class="value">{score}/100 ({html.escape(grade)})</div></div>
    <div class="card"><div class="label">{html.escape(s['total_findings'])}</div><div class="value">{len(items)}</div></div>
    <div class="card"><div class="label">{html.escape(s['critical'])}</div><div class="value">{counts["critical"]}</div></div>
    <div class="card"><div class="label">{html.escape(s['high'])}</div><div class="value">{counts["high"]}</div></div>
    <div class="card"><div class="label">{html.escape(s['medium'])}</div><div class="value">{counts["medium"]}</div></div>
    <div class="card"><div class="label">{html.escape(s['low'])}</div><div class="value">{counts["low"]}</div></div>
    <div class="card"><div class="label">{html.escape(s['info'])}</div><div class="value">{counts["info"]}</div></div>
  </div>

  <h2>{html.escape(s['sec2'])}</h2>
  <p>{html.escape(s['scope_intro'])}</p>
  <ul>{scope_items}</ul>
  <p>{html.escape(s['methodology'])}</p>
  {f"<p><strong>{html.escape(s['eng_notes'])}:</strong> {html.escape(engagement.notes)}</p>" if engagement.notes else ""}

  <h2>{html.escape(s['sec3'])}</h2>
  <table>
    <thead>
      <tr><th>{html.escape(s['th_ref'])}</th><th>{html.escape(s['th_finding'])}</th><th>{html.escape(s['th_severity'])}</th><th>{html.escape(s['th_cve'])}</th><th>{html.escape(s['th_owasp'])}</th><th>{html.escape(s['th_cvss'])}</th><th>{html.escape(s['th_source'])}</th></tr>
    </thead>
    <tbody>{summary_rows}</tbody>
  </table>

  <h2>{html.escape(s['sec4'])}</h2>
  {detail_html}

  <h2>{html.escape(s['sec5'])}</h2>
  <table>
    <thead>
      <tr><th>{html.escape(s['th_ref'])}</th><th>{html.escape(s['th_finding'])}</th><th>{html.escape(s['th_status'])}</th><th>{html.escape(s['th_retested_at'])}</th><th>{html.escape(s['th_retest_notes'])}</th></tr>
    </thead>
    <tbody>{retest_rows}</tbody>
  </table>

  <div class="footer confidential">{html.escape(s['confidential'])} &middot; {html.escape(s['footer_html'])} {html.escape(engagement.authorization_reference)} &middot; SurfaceWatch</div>
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
    lang: str = "en",
) -> bytes:
    s = _tr(lang)
    items = _merge_findings(scanner_findings, manual_findings)
    score, raw_grade, counts = _risk_summary(items)
    grade = _grade_label(raw_grade, lang)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(153, 27, 27)
    pdf.cell(0, 6, _safe_pdf_text(s["confidential"]), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(15, 23, 42)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(
        0,
        10,
        _safe_pdf_text(f"{s['heading']}: {engagement.client_name}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    _pdf_body(
        pdf,
        f"{s['tester']}: {engagement.tester} | {s['authorization']}: {engagement.authorization_reference} | "
        f"{s['status']}: {_status_label(engagement.status, lang)} | {s['window_short']}: {_fmt_date(engagement.start_date)} {s['to']} "
        f"{_fmt_date(engagement.end_date)} | {s['generated']}: {generated_at}",
    )
    pdf.ln(3)

    _pdf_heading(pdf, s["sec1"], 13)
    _pdf_body(
        pdf,
        f"{s['exec_intro']} {s['overall_risk']}: {score}/100 ({grade}). {s['total_findings']}: {len(items)} "
        f"({s['critical'].lower()}={counts['critical']}, {s['high'].lower()}={counts['high']}, {s['medium'].lower()}={counts['medium']}, "
        f"{s['low'].lower()}={counts['low']}, {s['info'].lower()}={counts['info']}).",
    )
    pdf.ln(2)

    _pdf_heading(pdf, s["sec2"], 13)
    _pdf_body(pdf, s["scope_list_label"])
    for entry in engagement.scope:
        _pdf_body(pdf, f"  - {entry}")
    _pdf_body(pdf, s["methodology"])
    if engagement.notes:
        _pdf_body(pdf, f"{s['eng_notes']}: {engagement.notes}")
    pdf.ln(2)

    _pdf_heading(pdf, s["sec3"], 13)
    for item in items:
        _pdf_body(
            pdf,
            f"{item.ref} | {_sev_label(item.severity, lang)} | {item.title} | {s['host'].lower()}={item.host} | "
            f"CVE={item.cve_id or '-'} | OWASP={item.owasp_category or '-'} | "
            f"CVSS={_fmt_cvss(item.cvss_score)} | {s['source'].lower()}={item.source}",
            8,
        )
    if not items:
        _pdf_body(pdf, s["no_findings_eng"])
    pdf.ln(2)

    _pdf_heading(pdf, s["sec4"], 13)
    for item in items:
        _pdf_heading(pdf, f"{item.ref} - {item.title}", 10)
        _pdf_body(
            pdf,
            f"{s['host']}: {item.host} | {s['severity']}: {_sev_label(item.severity, lang)} | "
            f"{s['cvss']}: {_fmt_cvss(item.cvss_score)} | {s['cve']}: {item.cve_id or '-'} | "
            f"{s['owasp']}: {item.owasp_category or '-'} | {s['source']}: {item.source}",
            8,
        )
        _pdf_body(pdf, f"{s['observation']}: {item.description}", 8)
        _pdf_body(pdf, f"{s['evidence']}: {item.evidence}", 8)
        _pdf_body(pdf, f"{s['remediation']}: {item.remediation}", 8)
        _pdf_body(
            pdf,
            f"{s['status']}: {_status_label(item.status, lang)} | {s['retest_notes']}: {item.retest_notes or '-'}",
            8,
        )
        pdf.ln(2)
    if not items:
        _pdf_body(pdf, s["no_findings_eng"])
    pdf.ln(2)

    _pdf_heading(pdf, s["sec5"], 13)
    for item in items:
        _pdf_body(
            pdf,
            f"{item.ref} | {item.title} | {s['status'].lower()}={_status_label(item.status, lang)} | "
            f"{s['th_retested_at'].lower()}={_fmt_date(item.retested_at)} | {s['retest_notes'].lower()}={item.retest_notes or '-'}",
            8,
        )
    if not items:
        _pdf_body(pdf, s["no_retest"])
    pdf.ln(3)

    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0,
        5,
        _safe_pdf_text(
            f"{s['confidential']} - {s['footer_html']} {engagement.authorization_reference} - "
            f"SurfaceWatch. {s['footer_doc']}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    return bytes(pdf.output())


def generate_vapt_docx_report(
    engagement: Engagement,
    scanner_findings: list[FindingRecord],
    manual_findings: list[ManualFinding],
    lang: str = "en",
) -> bytes:
    s = _tr(lang)
    items = _merge_findings(scanner_findings, manual_findings)
    score, raw_grade, counts = _risk_summary(items)
    grade = _grade_label(raw_grade, lang)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    document = Document()
    document.add_heading(s["confidential"], level=0)
    document.add_heading(f"{s['heading']}: {engagement.client_name}", level=1)
    document.add_paragraph(
        f"{s['tester']}: {engagement.tester} | "
        f"{s['authorization']}: {engagement.authorization_reference} | "
        f"{s['status']}: {_status_label(engagement.status, lang)} | "
        f"{s['window_short']}: {_fmt_date(engagement.start_date)} {s['to']} {_fmt_date(engagement.end_date)} | "
        f"{s['generated']}: {generated_at}"
    )

    document.add_heading(s["sec1"], level=2)
    document.add_paragraph(
        f"{s['exec_intro']} {s['overall_risk']}: {score}/100 ({grade}). {s['total_findings']}: {len(items)} "
        f"({s['critical'].lower()}={counts['critical']}, {s['high'].lower()}={counts['high']}, {s['medium'].lower()}={counts['medium']}, "
        f"{s['low'].lower()}={counts['low']}, {s['info'].lower()}={counts['info']})."
    )

    document.add_heading(s["sec2"], level=2)
    document.add_paragraph(s["scope_list_label"])
    for entry in engagement.scope:
        document.add_paragraph(entry, style="List Bullet")
    document.add_paragraph(s["methodology"])
    if engagement.notes:
        document.add_paragraph(f"{s['eng_notes']}: {engagement.notes}")

    document.add_heading(s["sec3"], level=2)
    summary_table = document.add_table(rows=1, cols=7)
    summary_table.style = "Table Grid"
    summary_headers = [s["th_ref"], s["th_finding"], s["th_severity"], s["th_cve"], s["th_owasp"], s["th_cvss"], s["th_source"]]
    for index, header in enumerate(summary_headers):
        summary_table.rows[0].cells[index].text = header
    for item in items:
        cells = summary_table.add_row().cells
        cells[0].text = item.ref
        cells[1].text = f"{item.title} ({item.host})"
        cells[2].text = _sev_label(item.severity, lang)
        cells[3].text = item.cve_id or "-"
        cells[4].text = item.owasp_category or "-"
        cells[5].text = _fmt_cvss(item.cvss_score)
        cells[6].text = item.source
    if not items:
        summary_table.add_row().cells[0].text = s["no_findings"]

    document.add_heading(s["sec4"], level=2)
    if not items:
        document.add_paragraph(s["no_findings_eng"])
    for item in items:
        document.add_heading(f"{item.ref} - {item.title}", level=3)
        document.add_paragraph(
            f"{s['host']}: {item.host} | {s['severity']}: {_sev_label(item.severity, lang)} | "
            f"{s['cvss']}: {_fmt_cvss(item.cvss_score)} | {s['cve']}: {item.cve_id or '-'} | "
            f"{s['owasp']}: {item.owasp_category or '-'} | {s['source']}: {item.source}"
        )
        document.add_paragraph(f"{s['observation']}: {item.description or '-'}")
        document.add_paragraph(f"{s['evidence']}: {item.evidence or '-'}")
        document.add_paragraph(f"{s['remediation']}: {item.remediation or '-'}")
        document.add_paragraph(f"{s['status']}: {_status_label(item.status, lang)}")
        document.add_paragraph(f"{s['retest_notes']}: {item.retest_notes or '-'}")

    document.add_heading(s["sec5"], level=2)
    retest_table = document.add_table(rows=1, cols=5)
    retest_table.style = "Table Grid"
    retest_headers = [s["th_ref"], s["th_finding"], s["th_status"], s["th_retested_at"], s["th_retest_notes"]]
    for index, header in enumerate(retest_headers):
        retest_table.rows[0].cells[index].text = header
    for item in items:
        cells = retest_table.add_row().cells
        cells[0].text = item.ref
        cells[1].text = item.title
        cells[2].text = _status_label(item.status, lang)
        cells[3].text = _fmt_date(item.retested_at)
        cells[4].text = item.retest_notes or "-"
    if not items:
        retest_table.add_row().cells[0].text = s["no_retest"]

    document.add_paragraph(
        f"{s['confidential']} - {s['footer_html']} {engagement.authorization_reference} - "
        f"SurfaceWatch. {s['footer_doc']}"
    )

    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()
