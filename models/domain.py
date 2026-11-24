from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    owner_label: Mapped[str] = mapped_column(String(120), default="local-owner", nullable=False)
    verification_token: Mapped[str] = mapped_column(String(64), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verified_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attestation_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    attestation_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    schedule_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scan_interval_days: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    latest_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="desc(Scan.started_at)",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="desc(AuditLog.created_at)",
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="running", nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    actor: Mapped[str] = mapped_column(String(120), default="local-owner", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    discovered_hosts_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    summary_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    domain: Mapped["Domain"] = relationship(back_populates="scans")
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True, nullable=False)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), index=True, nullable=False)
    finding_uid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    scanner: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    host: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("domains.id"), index=True, nullable=True
    )
    domain_name: Mapped[str] = mapped_column(String(255), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    details: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    domain: Mapped["Domain | None"] = relationship(back_populates="audit_logs")
