from sqlalchemy.orm import Session

from models.domain import AuditLog


def log_audit_event(
    db: Session,
    *,
    domain_name: str,
    actor: str,
    action: str,
    details: str = "",
    domain_id: int | None = None,
) -> AuditLog:
    entry = AuditLog(
        domain_id=domain_id,
        domain_name=domain_name,
        actor=actor,
        action=action,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
