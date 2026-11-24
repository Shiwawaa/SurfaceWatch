import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from config import get_settings
from database import get_db
from models.domain import AuditLog, Domain, FindingRecord, Scan
from models.schemas import (
    AttestationRequest,
    AuditLogOut,
    DiffOut,
    DomainCreate,
    DomainOut,
    FindingOut,
    NotifyResultOut,
    ScanOut,
    ScanTriggerRequest,
    ScheduleUpdateRequest,
    VerifyResultOut,
)
from notifications import format_summary_text, send_email_summary, send_telegram_summary
from services import (
    ATTESTATION_STATEMENT,
    DomainNotVerifiedError,
    DomainValidationError,
    execute_domain_scan,
    expected_txt_record,
    generate_html_report,
    generate_pdf_report,
    generate_verification_token,
    get_domain_diff,
    log_audit_event,
    normalize_domain,
    risk_grade_label,
    verify_dns_txt,
)

router = APIRouter(prefix="/api", tags=["surfacewatch"])


def _domain_to_out(db: Session, domain: Domain) -> DomainOut:
    scan_count = db.scalar(select(func.count(Scan.id)).where(Scan.domain_id == domain.id)) or 0
    txt_host, txt_val = expected_txt_record(domain.name, domain.verification_token)
    return DomainOut(
        id=domain.id,
        name=domain.name,
        owner_label=domain.owner_label,
        verification_token=domain.verification_token,
        verified=domain.verified,
        verified_method=domain.verified_method,
        verified_at=domain.verified_at,
        attestation_text=domain.attestation_text,
        attestation_confirmed_at=domain.attestation_confirmed_at,
        schedule_enabled=domain.schedule_enabled,
        scan_interval_days=domain.scan_interval_days,
        last_scan_at=domain.last_scan_at,
        latest_risk_score=domain.latest_risk_score,
        created_at=domain.created_at,
        scan_count=scan_count,
        risk_grade=risk_grade_label(domain.latest_risk_score),
        txt_record_host=txt_host,
        txt_record_value=txt_val,
    )


def _scan_to_out(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        domain_id=scan.domain_id,
        status=scan.status,
        triggered_by=scan.triggered_by,
        actor=scan.actor,
        risk_score=scan.risk_score,
        risk_grade=risk_grade_label(scan.risk_score),
        discovered_hosts=json.loads(scan.discovered_hosts_json or "[]"),
        summary=json.loads(scan.summary_json or "{}"),
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


def _get_domain_or_404(db: Session, domain_id: int) -> Domain:
    domain = db.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found.")
    return domain


@router.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "SurfaceWatch"}


@router.get("/domains", response_model=list[DomainOut])
def list_domains(db: Session = Depends(get_db)) -> list[DomainOut]:
    domains = db.scalars(select(Domain).order_by(desc(Domain.created_at))).all()
    return [_domain_to_out(db, d) for d in domains]


@router.post("/domains", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
def add_domain(payload: DomainCreate, db: Session = Depends(get_db)) -> DomainOut:
    try:
        clean_name = normalize_domain(payload.name)
    except DomainValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    existing = db.scalar(select(Domain).where(Domain.name == clean_name))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{clean_name}' is already registered.",
        )

    domain = Domain(
        name=clean_name,
        owner_label=payload.owner_label.strip(),
        verification_token=generate_verification_token(),
        verified=False,
        scan_interval_days=payload.scan_interval_days,
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)

    log_audit_event(
        db,
        domain_id=domain.id,
        domain_name=domain.name,
        actor=payload.owner_label.strip(),
        action="domain_added",
        details="Domain registered awaiting ownership verification.",
    )
    return _domain_to_out(db, domain)


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(domain_id: int, db: Session = Depends(get_db)) -> Response:
    domain = _get_domain_or_404(db, domain_id)
    domain_name = domain.name
    db.delete(domain)
    db.commit()
    log_audit_event(
        db,
        domain_id=None,
        domain_name=domain_name,
        actor=get_settings().operator_id,
        action="domain_deleted",
        details="Domain and associated scan history removed.",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/domains/{domain_id}/verify/dns", response_model=VerifyResultOut)
def verify_domain_dns(domain_id: int, db: Session = Depends(get_db)) -> VerifyResultOut:
    domain = _get_domain_or_404(db, domain_id)
    settings = get_settings()
    matched, observed = verify_dns_txt(
        domain.name, domain.verification_token, timeout=settings.request_timeout_seconds
    )

    if matched:
        domain.verified = True
        domain.verified_method = "dns_txt"
        domain.verified_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(domain)
        log_audit_event(
            db,
            domain_id=domain.id,
            domain_name=domain.name,
            actor=domain.owner_label,
            action="dns_verified",
            details="Ownership verified via DNS TXT record.",
        )
        return VerifyResultOut(
            verified=True,
            method="dns_txt",
            message=f"DNS TXT ownership verified for {domain.name}.",
            observed_records=observed,
            domain=_domain_to_out(db, domain),
        )

    return VerifyResultOut(
        verified=False,
        method="dns_txt",
        message="Expected TXT token was not found yet. DNS propagation can take a few minutes.",
        observed_records=observed,
        domain=_domain_to_out(db, domain),
    )


@router.post("/domains/{domain_id}/verify/attest", response_model=VerifyResultOut)
def verify_domain_attestation(
    domain_id: int, payload: AttestationRequest, db: Session = Depends(get_db)
) -> VerifyResultOut:
    settings = get_settings()
    if not settings.allow_self_attestation:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-attestation is disabled by configuration. Use DNS TXT verification.",
        )

    if not payload.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"You must confirm: '{ATTESTATION_STATEMENT}'.",
        )

    domain = _get_domain_or_404(db, domain_id)
    now = datetime.now(timezone.utc)
    domain.verified = True
    domain.verified_method = "attestation"
    domain.verified_at = now
    domain.attestation_text = ATTESTATION_STATEMENT
    domain.attestation_confirmed_at = now
    db.commit()
    db.refresh(domain)

    log_audit_event(
        db,
        domain_id=domain.id,
        domain_name=domain.name,
        actor=payload.actor.strip(),
        action="attestation_verified",
        details=f"Confirmed: '{ATTESTATION_STATEMENT}' at {now.isoformat()}",
    )

    return VerifyResultOut(
        verified=True,
        method="attestation",
        message=f"Authorization recorded for {domain.name} at {now.isoformat()}.",
        observed_records=[],
        domain=_domain_to_out(db, domain),
    )


@router.patch("/domains/{domain_id}/schedule", response_model=DomainOut)
def update_schedule(
    domain_id: int, payload: ScheduleUpdateRequest, db: Session = Depends(get_db)
) -> DomainOut:
    domain = _get_domain_or_404(db, domain_id)
    domain.schedule_enabled = payload.schedule_enabled
    domain.scan_interval_days = payload.scan_interval_days
    db.commit()
    db.refresh(domain)

    log_audit_event(
        db,
        domain_id=domain.id,
        domain_name=domain.name,
        actor=get_settings().operator_id,
        action="schedule_updated",
        details=f"schedule_enabled={domain.schedule_enabled}, interval_days={domain.scan_interval_days}",
    )
    return _domain_to_out(db, domain)


@router.post("/domains/{domain_id}/scan", response_model=ScanOut)
def trigger_scan(
    domain_id: int,
    payload: ScanTriggerRequest | None = None,
    db: Session = Depends(get_db),
) -> ScanOut:
    domain = _get_domain_or_404(db, domain_id)
    actor = payload.actor.strip() if payload else get_settings().operator_id
    try:
        scan, _ = execute_domain_scan(db, domain, actor=actor, triggered_by="manual")
    except DomainNotVerifiedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    return _scan_to_out(scan)


@router.get("/domains/{domain_id}/scans", response_model=list[ScanOut])
def list_scans(domain_id: int, db: Session = Depends(get_db)) -> list[ScanOut]:
    _get_domain_or_404(db, domain_id)
    scans = db.scalars(
        select(Scan)
        .where(Scan.domain_id == domain_id)
        .order_by(desc(Scan.started_at), desc(Scan.id))
    ).all()
    return [_scan_to_out(s) for s in scans]


@router.get("/domains/{domain_id}/findings", response_model=list[FindingOut])
def list_findings(
    domain_id: int,
    scan_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    scanner: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    _get_domain_or_404(db, domain_id)

    target_scan_id = scan_id
    if target_scan_id is None:
        latest_scan = db.scalar(
            select(Scan)
            .where(Scan.domain_id == domain_id, Scan.status == "completed")
            .order_by(desc(Scan.started_at), desc(Scan.id))
            .limit(1)
        )
        if latest_scan is None:
            return []
        target_scan_id = latest_scan.id

    stmt = select(FindingRecord).where(
        FindingRecord.domain_id == domain_id,
        FindingRecord.scan_id == target_scan_id,
    )
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity.lower())
    if scanner:
        stmt = stmt.where(FindingRecord.scanner == scanner.lower())

    rows = db.scalars(stmt).all()
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows_sorted = sorted(rows, key=lambda r: (severity_rank.get(r.severity, 9), r.host, r.title))

    return [
        FindingOut(
            id=r.finding_uid,
            db_id=r.id,
            scanner=r.scanner,
            host=r.host,
            severity=r.severity,
            title=r.title,
            explanation=r.explanation,
            evidence=r.evidence,
            remediation=r.remediation,
        )
        for r in rows_sorted
    ]


@router.get("/domains/{domain_id}/diff", response_model=DiffOut)
def domain_diff(domain_id: int, db: Session = Depends(get_db)) -> DiffOut:
    _get_domain_or_404(db, domain_id)
    return get_domain_diff(db, domain_id)


@router.get("/domains/{domain_id}/report")
def export_report(
    domain_id: int,
    format: str = Query(default="html", pattern="^(html|pdf)$"),
    db: Session = Depends(get_db),
) -> Response:
    domain = _get_domain_or_404(db, domain_id)
    latest_scan = db.scalar(
        select(Scan)
        .where(Scan.domain_id == domain_id, Scan.status == "completed")
        .order_by(desc(Scan.started_at), desc(Scan.id))
        .limit(1)
    )
    findings: list[FindingRecord] = []
    if latest_scan is not None:
        findings = list(
            db.scalars(
                select(FindingRecord).where(FindingRecord.scan_id == latest_scan.id)
            ).all()
        )
    diff = get_domain_diff(db, domain_id)

    log_audit_event(
        db,
        domain_id=domain.id,
        domain_name=domain.name,
        actor=get_settings().operator_id,
        action="report_exported",
        details=f"Exported {format.upper()} report.",
    )

    if format == "pdf":
        pdf_bytes = generate_pdf_report(domain, latest_scan, findings, diff)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="surfacewatch-{domain.name}.pdf"'
            },
        )

    html_doc = generate_html_report(domain, latest_scan, findings, diff)
    return HTMLResponse(
        content=html_doc,
        headers={
            "Content-Disposition": f'inline; filename="surfacewatch-{domain.name}.html"'
        },
    )


@router.post("/domains/{domain_id}/notify", response_model=NotifyResultOut)
def send_domain_notification(domain_id: int, db: Session = Depends(get_db)) -> NotifyResultOut:
    domain = _get_domain_or_404(db, domain_id)
    diff = get_domain_diff(db, domain_id)
    total_findings = len(diff.new) + len(diff.unchanged)
    summary = format_summary_text(
        domain_name=domain.name,
        risk_score=domain.latest_risk_score,
        risk_grade=risk_grade_label(domain.latest_risk_score),
        total_findings=total_findings,
        new_count=diff.counts["new"],
        resolved_count=diff.counts["resolved"],
    )

    tg_ok, tg_msg = send_telegram_summary(summary)
    em_ok, em_msg = send_email_summary(f"SurfaceWatch Report: {domain.name}", summary)

    log_audit_event(
        db,
        domain_id=domain.id,
        domain_name=domain.name,
        actor=get_settings().operator_id,
        action="notification_sent",
        details=f"telegram={tg_ok} ({tg_msg}); email={em_ok} ({em_msg})",
    )

    return NotifyResultOut(
        telegram_sent=tg_ok,
        email_sent=em_ok,
        details=[tg_msg, em_msg],
    )


@router.get("/audit-logs", response_model=list[AuditLogOut])
def get_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[AuditLogOut]:
    rows = db.scalars(
        select(AuditLog).order_by(desc(AuditLog.created_at), desc(AuditLog.id)).limit(limit)
    ).all()
    return [AuditLogOut.model_validate(r) for r in rows]
