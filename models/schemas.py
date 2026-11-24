from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DomainCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    owner_label: str = Field(default="local-owner", min_length=1, max_length=120)
    scan_interval_days: int = Field(default=7, ge=1, le=90)


class AttestationRequest(BaseModel):
    confirmed: bool
    actor: str = Field(default="local-owner", min_length=1, max_length=120)


class ScheduleUpdateRequest(BaseModel):
    schedule_enabled: bool
    scan_interval_days: int = Field(default=7, ge=1, le=90)


class ScanTriggerRequest(BaseModel):
    actor: str = Field(default="local-owner", min_length=1, max_length=120)


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    owner_label: str
    verification_token: str
    verified: bool
    verified_method: str | None
    verified_at: datetime | None
    attestation_text: str | None
    attestation_confirmed_at: datetime | None
    schedule_enabled: bool
    scan_interval_days: int
    last_scan_at: datetime | None
    latest_risk_score: int
    created_at: datetime
    scan_count: int = 0
    risk_grade: str = "Low"
    txt_record_host: str = ""
    txt_record_value: str = ""


class FindingOut(BaseModel):
    id: str
    db_id: int | None = None
    scanner: str
    host: str
    severity: str
    title: str
    explanation: str
    evidence: str
    remediation: str


class ScanOut(BaseModel):
    id: int
    domain_id: int
    status: str
    triggered_by: str
    actor: str
    risk_score: int
    risk_grade: str
    discovered_hosts: list[dict[str, Any]]
    summary: dict[str, Any]
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


class DiffOut(BaseModel):
    current_scan_id: int | None
    previous_scan_id: int | None
    new: list[FindingOut]
    resolved: list[FindingOut]
    unchanged: list[FindingOut]
    counts: dict[str, int]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain_id: int | None
    domain_name: str
    actor: str
    action: str
    details: str
    created_at: datetime


class VerifyResultOut(BaseModel):
    verified: bool
    method: str
    message: str
    observed_records: list[str] = Field(default_factory=list)
    domain: DomainOut


class NotifyResultOut(BaseModel):
    telegram_sent: bool
    email_sent: bool
    details: list[str]
