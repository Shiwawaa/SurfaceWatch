import json
from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from config import get_settings
from models.domain import Domain, FindingRecord, Scan
from models.schemas import DiffOut, FindingOut
from scanners import (
    DnsEmailScanner,
    Finding,
    HttpExposureScanner,
    PortScanner,
    RateLimiter,
    Scanner,
    ScanTarget,
    SubdomainScanner,
    TlsScanner,
)
from services.audit import log_audit_event
from services.diff_engine import compute_scan_diff
from services.risk_score import calculate_risk_score, count_by_severity


class DomainNotVerifiedError(PermissionError):
    pass


def build_default_scanners(rate_limiter: RateLimiter) -> tuple[SubdomainScanner, list[Scanner]]:
    settings = get_settings()
    discovery = SubdomainScanner(
        rate_limiter=rate_limiter,
        timeout=settings.request_timeout_seconds,
        user_agent=settings.user_agent,
        max_subdomains=settings.max_subdomains,
    )
    plugins: list[Scanner] = [
        DnsEmailScanner(
            rate_limiter=rate_limiter,
            timeout=settings.request_timeout_seconds,
            user_agent=settings.user_agent,
        ),
        TlsScanner(
            rate_limiter=rate_limiter,
            timeout=settings.request_timeout_seconds,
            user_agent=settings.user_agent,
        ),
        PortScanner(
            rate_limiter=rate_limiter,
            timeout=settings.port_timeout_seconds,
            user_agent=settings.user_agent,
        ),
        HttpExposureScanner(
            rate_limiter=rate_limiter,
            timeout=settings.request_timeout_seconds,
            user_agent=settings.user_agent,
        ),
    ]
    return discovery, plugins


def _finding_record_to_schema(rec: FindingRecord) -> FindingOut:
    return FindingOut(
        id=rec.finding_uid,
        db_id=rec.id,
        scanner=rec.scanner,
        host=rec.host,
        severity=rec.severity,
        title=rec.title,
        explanation=rec.explanation,
        evidence=rec.evidence,
        remediation=rec.remediation,
    )


def get_domain_diff(db: Session, domain_id: int) -> DiffOut:
    scans = db.scalars(
        select(Scan)
        .where(Scan.domain_id == domain_id, Scan.status == "completed")
        .order_by(desc(Scan.started_at), desc(Scan.id))
        .limit(2)
    ).all()

    if not scans:
        return DiffOut(
            current_scan_id=None,
            previous_scan_id=None,
            new=[],
            resolved=[],
            unchanged=[],
            counts={"new": 0, "resolved": 0, "unchanged": 0},
        )

    current_scan = scans[0]
    current_findings = [
        _finding_record_to_schema(f)
        for f in db.scalars(select(FindingRecord).where(FindingRecord.scan_id == current_scan.id)).all()
    ]

    if len(scans) < 2:
        return compute_scan_diff(
            current_scan_id=current_scan.id,
            previous_scan_id=None,
            current_findings=current_findings,
            previous_findings=[],
        )

    prev_scan = scans[1]
    prev_findings = [
        _finding_record_to_schema(f)
        for f in db.scalars(select(FindingRecord).where(FindingRecord.scan_id == prev_scan.id)).all()
    ]
    return compute_scan_diff(
        current_scan_id=current_scan.id,
        previous_scan_id=prev_scan.id,
        current_findings=current_findings,
        previous_findings=prev_findings,
    )


def execute_domain_scan(
    db: Session,
    domain: Domain,
    *,
    actor: str = "local-owner",
    triggered_by: str = "manual",
    discovery_scanner: SubdomainScanner | None = None,
    plugin_scanners: list[Scanner] | None = None,
) -> tuple[Scan, DiffOut]:
    if not domain.verified:
        log_audit_event(
            db,
            domain_id=domain.id,
            domain_name=domain.name,
            actor=actor,
            action="scan_blocked_unverified",
            details="Refused scan because domain ownership has not been verified.",
        )
        raise DomainNotVerifiedError(
            f"Domain '{domain.name}' is not verified. Verify ownership via DNS TXT or attestation first."
        )

    settings = get_settings()
    rate_limiter = RateLimiter(settings.rate_limit_requests_per_second)
    if discovery_scanner is None or plugin_scanners is None:
        default_discovery, default_plugins = build_default_scanners(rate_limiter)
        discovery_scanner = discovery_scanner or default_discovery
        plugin_scanners = plugin_scanners if plugin_scanners is not None else default_plugins

    scan = Scan(
        domain_id=domain.id,
        status="running",
        triggered_by=triggered_by,
        actor=actor,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_audit_event(
        db,
        domain_id=domain.id,
        domain_name=domain.name,
        actor=actor,
        action="scan_started",
        details=f"Scan #{scan.id} initiated via {triggered_by}.",
    )

    try:
        target = ScanTarget(root_domain=domain.name)
        all_findings: list[Finding] = []
        all_findings.extend(discovery_scanner.run(target))

        for scanner in plugin_scanners:
            all_findings.extend(scanner.run(target))

        # Deduplicate findings by deterministic ID within a single scan
        unique_findings: dict[str, Finding] = {}
        for item in all_findings:
            unique_findings[item.id] = item
        deduped = list(unique_findings.values())

        for item in deduped:
            db.add(
                FindingRecord(
                    scan_id=scan.id,
                    domain_id=domain.id,
                    finding_uid=item.id,
                    scanner=item.scanner,
                    host=item.host,
                    severity=item.severity.value if hasattr(item.severity, "value") else str(item.severity),
                    title=item.title,
                    explanation=item.explanation,
                    evidence=item.evidence,
                    remediation=item.remediation,
                )
            )

        severities = [
            f.severity.value if hasattr(f.severity, "value") else str(f.severity) for f in deduped
        ]
        risk_score = calculate_risk_score(severities)
        severity_counts = count_by_severity(severities)

        scan.status = "completed"
        scan.risk_score = risk_score
        scan.discovered_hosts_json = json.dumps([asdict(h) for h in target.hosts])
        scan.completed_at = datetime.now(timezone.utc)

        db.flush()
        diff = get_domain_diff(db, domain.id)
        scan.summary_json = json.dumps(
            {
                "severity_counts": severity_counts,
                "diff_counts": diff.counts,
                "total_findings": len(deduped),
                "host_count": len(target.hosts),
            }
        )

        domain.last_scan_at = scan.completed_at
        domain.latest_risk_score = risk_score
        db.commit()
        db.refresh(scan)

        log_audit_event(
            db,
            domain_id=domain.id,
            domain_name=domain.name,
            actor=actor,
            action="scan_completed",
            details=(
                f"Scan #{scan.id} completed: risk_score={risk_score}, "
                f"findings={len(deduped)}, new={diff.counts['new']}, resolved={diff.counts['resolved']}."
            ),
        )
        return scan, diff

    except Exception as exc:
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        log_audit_event(
            db,
            domain_id=domain.id,
            domain_name=domain.name,
            actor=actor,
            action="scan_failed",
            details=f"Scan #{scan.id} failed: {exc}",
        )
        raise
