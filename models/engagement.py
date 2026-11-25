import json
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base
from models.domain import utcnow

if TYPE_CHECKING:
    from models.domain import FindingRecord


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    tester: Mapped[str] = mapped_column(String(120), default="local-owner", nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
    )
    manual_findings: Mapped[list["ManualFinding"]] = relationship(
        back_populates="engagement",
        cascade="all, delete-orphan",
        order_by="desc(ManualFinding.created_at)",
    )

    @property
    def scope(self) -> list[str]:
        return json.loads(self.scope_json or "[]")

    @scope.setter
    def scope(self, value: list[str]) -> None:
        self.scope_json = json.dumps(list(value))


class ManualFinding(Base):
    __tablename__ = "manual_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_host: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    screenshots_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    discovered_by: Mapped[str] = mapped_column(String(120), default="local-owner", nullable=False)
    retest_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    retested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    engagement: Mapped["Engagement"] = relationship(back_populates="manual_findings")

    @property
    def screenshots(self) -> list[str]:
        return json.loads(self.screenshots_json or "[]")

    @screenshots.setter
    def screenshots(self, value: list[str]) -> None:
        self.screenshots_json = json.dumps(list(value))
