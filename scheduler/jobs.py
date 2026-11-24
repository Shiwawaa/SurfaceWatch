from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from database import SessionLocal
from models.domain import Domain
from notifications.email_notifier import send_email_summary
from notifications.telegram_notifier import format_summary_text, send_telegram_summary
from services.audit import log_audit_event
from services.risk_score import risk_grade_label
from services.scan_orchestrator import execute_domain_scan

_scheduler: BackgroundScheduler | None = None


def run_due_scheduled_scans() -> int:
    """Checks verified domains with scheduling enabled and runs any due rescans."""
    now = datetime.now(timezone.utc)
    ran_count = 0

    with SessionLocal() as db:
        domains = db.scalars(
            select(Domain).where(Domain.verified.is_(True), Domain.schedule_enabled.is_(True))
        ).all()

        for domain in domains:
            interval = timedelta(days=max(domain.scan_interval_days, 1))
            last_scan = domain.last_scan_at
            if last_scan is not None and last_scan.tzinfo is None:
                last_scan = last_scan.replace(tzinfo=timezone.utc)

            if last_scan is None or (now - last_scan) >= interval:
                try:
                    scan, diff = execute_domain_scan(
                        db,
                        domain,
                        actor="apscheduler",
                        triggered_by="scheduler",
                    )
                    ran_count += 1
                    summary = format_summary_text(
                        domain_name=domain.name,
                        risk_score=scan.risk_score,
                        risk_grade=risk_grade_label(scan.risk_score),
                        total_findings=len(diff.new) + len(diff.unchanged),
                        new_count=diff.counts["new"],
                        resolved_count=diff.counts["resolved"],
                    )
                    tg_ok, _ = send_telegram_summary(summary)
                    em_ok, _ = send_email_summary(
                        f"SurfaceWatch Weekly Summary: {domain.name}", summary
                    )
                    if tg_ok or em_ok:
                        log_audit_event(
                            db,
                            domain_id=domain.id,
                            domain_name=domain.name,
                            actor="apscheduler",
                            action="notification_sent",
                            details=f"telegram={tg_ok}, email={em_ok}",
                        )
                except Exception:
                    continue
    return ran_count


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(timezone="UTC")
        _scheduler.add_job(
            run_due_scheduled_scans,
            trigger="interval",
            hours=1,
            id="surfacewatch_due_scans",
            replace_existing=True,
        )
        _scheduler.start()
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
