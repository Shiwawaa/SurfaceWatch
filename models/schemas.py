from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class EngagementCreate(BaseModel):
    client_name: str = Field(..., min_length=1, max_length=255)
    authorization_reference: str = Field(..., min_length=1, max_length=255)
    scope: list[str] = Field(..., min_length=1)
    start_date: date
    end_date: date
    tester: str = Field(default="local-owner", min_length=1, max_length=120)
    notes: str = ""

    @model_validator(mode="after")
    def _validate_window(self) -> "EngagementCreate":
        if self.end_date < self.start_date:
            raise ValueError("end_date must be on or after start_date")
        return self


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_name: str
    authorization_reference: str
    scope: list[str]
    start_date: date
    end_date: date
    status: str
    tester: str
    notes: str
    created_at: datetime
    finding_count: int = 0
    risk_grade: str = "Low"


class EngagementStatusUpdate(BaseModel):
    status: str = Field(..., min_length=1, max_length=32)


class ActiveScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    tool: Literal["nmap", "nuclei"]
    actor: str = Field(default="local-owner", min_length=1, max_length=120)


class ActiveScanResultOut(BaseModel):
    engagement_id: int
    target: str
    tool: str
    tool_available: bool
    findings_created: int
    raw_command: str = ""
    error: str | None = None
    message: str = ""
    findings: list[FindingOut] = Field(default_factory=list)


class ManualFindingCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    affected_host: str = Field(..., min_length=1, max_length=255)
    severity: str = Field(..., min_length=1, max_length=16)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=255)
    owasp_category: str | None = Field(default=None, max_length=64)
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    discovered_by: str = Field(default="local-owner", min_length=1, max_length=120)


class ManualFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    title: str
    affected_host: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    owasp_category: str | None
    description: str
    evidence: str
    remediation: str
    screenshots: list[str]
    status: str
    discovered_by: str
    retest_notes: str | None
    retested_at: datetime | None
    created_at: datetime


class ManualFindingRetestUpdate(BaseModel):
    status: str = Field(default="retested", min_length=1, max_length=32)
    retest_notes: str | None = None
