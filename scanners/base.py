import hashlib
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def make_finding_id(scanner: str, host: str, code: str) -> str:
    digest = hashlib.sha256(f"{scanner}|{host}|{code}".encode("utf-8")).hexdigest()[:16]
    return f"{scanner}_{digest}"


@dataclass(slots=True)
class Finding:
    id: str
    severity: Severity
    title: str
    explanation: str
    evidence: str
    remediation: str
    host: str
    scanner: str
    code: str = ""

    @classmethod
    def create(
        cls,
        *,
        scanner: str,
        host: str,
        code: str,
        severity: Severity,
        title: str,
        explanation: str,
        evidence: str,
        remediation: str,
    ) -> "Finding":
        return cls(
            id=make_finding_id(scanner, host, code),
            severity=severity,
            title=title,
            explanation=explanation,
            evidence=evidence,
            remediation=remediation,
            host=host,
            scanner=scanner,
            code=code,
        )


@dataclass(slots=True)
class HostRecord:
    hostname: str
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanTarget:
    root_domain: str
    hosts: list[HostRecord] = field(default_factory=list)

    def ensure_host(self, hostname: str) -> HostRecord:
        for host in self.hosts:
            if host.hostname == hostname:
                return host
        record = HostRecord(hostname=hostname)
        self.hosts.append(record)
        return record


class RateLimiter:
    """Thread-safe global request rate limiter."""

    def __init__(self, requests_per_second: float = 2.0) -> None:
        self._min_interval = 1.0 / max(requests_per_second, 0.1)
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()


class Scanner(ABC):
    name: str = "base"
    description: str = "Base scanner plugin"

    def __init__(
        self,
        *,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 8.0,
        user_agent: str = "SurfaceWatch/1.0",
    ) -> None:
        self.rate_limiter = rate_limiter or RateLimiter()
        self.timeout = timeout
        self.user_agent = user_agent

    @abstractmethod
    def run(self, target: ScanTarget) -> list[Finding]:
        """Execute passive or non-intrusive checks against the verified target."""
        raise NotImplementedError
