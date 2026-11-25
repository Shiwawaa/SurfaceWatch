import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from scanners.base import Finding, Severity

NUCLEI_EXCLUDED_TAGS = "dos,fuzz,intrusive,brute-force,bruteforce"

_HIGH_RISK_SERVICES = {"ftp", "telnet", "rdp", "ms-wbt-server"}
_LOW_RISK_SERVICES = {"ssh"}

_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

_NUCLEI_TAG_TO_OWASP: dict[str, str] = {
    "sqli": "A03 Injection",
    "xss": "A03 Injection",
    "rce": "A03 Injection",
    "ssti": "A03 Injection",
    "ssrf": "A10 Server-Side Request Forgery (SSRF)",
    "lfi": "A01 Broken Access Control",
    "redirect": "A01 Broken Access Control",
    "exposure": "A01 Broken Access Control",
    "misconfig": "A05 Security Misconfiguration",
    "exposed-panel": "A05 Security Misconfiguration",
    "takeover": "A05 Security Misconfiguration",
    "default-login": "A07 Identification and Authentication Failures",
    "cve": "A06 Vulnerable and Outdated Components",
}


@dataclass(slots=True)
class ExternalToolResult:
    findings: list[Finding] = field(default_factory=list)
    tool_available: bool = True
    raw_command: str = ""
    error: str | None = None


def _nmap_severity(service_name: str) -> Severity:
    name = service_name.lower()
    if name in _HIGH_RISK_SERVICES:
        return Severity.HIGH
    if name in _LOW_RISK_SERVICES:
        return Severity.LOW
    return Severity.INFO


def _nuclei_severity(value: str) -> Severity:
    return _NUCLEI_SEVERITY_MAP.get(value.lower(), Severity.INFO)


def _nuclei_tags(raw_tags: object) -> list[str]:
    if isinstance(raw_tags, str):
        return [tag.strip().lower() for tag in raw_tags.split(",") if tag.strip()]
    if isinstance(raw_tags, list):
        return [str(tag).strip().lower() for tag in raw_tags if str(tag).strip()]
    return []


def _nuclei_owasp(tags: list[str]) -> str | None:
    for tag in tags:
        category = _NUCLEI_TAG_TO_OWASP.get(tag)
        if category is not None:
            return category
    return None


def _nuclei_cve(raw_cve: object) -> str | None:
    if raw_cve is None:
        return None
    if isinstance(raw_cve, list):
        values = [str(item).strip() for item in raw_cve if str(item).strip()]
        return ", ".join(values) if values else None
    value = str(raw_cve).strip()
    return value or None


def _nuclei_cvss(raw_cvss: object) -> float | None:
    if raw_cvss in (None, ""):
        return None
    try:
        return float(raw_cvss)
    except (TypeError, ValueError):
        return None


def _tool_missing_result(
    *, scanner: str, target: str, binary: str, raw_command: str
) -> ExternalToolResult:
    finding = Finding.create(
        scanner=scanner,
        host=target,
        code="tool_not_installed",
        severity=Severity.INFO,
        title=f"{scanner.capitalize()} is not installed ({binary!r} not found on PATH)",
        explanation=(
            f"The active {scanner} check could not run because the binary is not available "
            "on this host."
        ),
        evidence=raw_command,
        remediation=(
            f"Install {scanner} and ensure {binary!r} is on PATH, then retry the scan. "
            "SurfaceWatch never bundles or reimplements external tooling."
        ),
        source=scanner,
    )
    return ExternalToolResult(
        findings=[finding],
        tool_available=False,
        raw_command=raw_command,
        error=f"{binary} binary not found on PATH",
    )


def run_nmap_scan(
    target: str,
    binary: str = "nmap",
    timeout: float = 120.0,
    top_ports: int = 100,
) -> ExternalToolResult:
    command = [
        binary,
        "-sV",
        "--top-ports",
        str(top_ports),
        "-T3",
        "--max-rate",
        "50",
        "-Pn",
        "--open",
        "-oX",
        "-",
        target,
    ]
    raw_command = " ".join(command)

    if shutil.which(binary) is None:
        return _tool_missing_result(
            scanner="nmap", target=target, binary=binary, raw_command=raw_command
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ExternalToolResult(
            tool_available=True,
            raw_command=raw_command,
            error=f"Nmap scan timed out after {timeout} seconds.",
        )
    except OSError as exc:
        return ExternalToolResult(
            tool_available=True,
            raw_command=raw_command,
            error=f"Could not execute Nmap: {exc}",
        )

    if not completed.stdout.strip():
        error = completed.stderr.strip() or f"Nmap exited with code {completed.returncode}."
        return ExternalToolResult(tool_available=True, raw_command=raw_command, error=error)

    try:
        root = ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        return ExternalToolResult(
            tool_available=True,
            raw_command=raw_command,
            error=f"Could not parse Nmap XML output: {exc}",
        )

    findings: list[Finding] = []
    for host_el in root.findall("host"):
        address_el = host_el.find("address")
        host_addr = address_el.get("addr") if address_el is not None else target
        host_addr = host_addr or target

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = port_el.get("portid", "?")
            protocol = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            service_name = (
                service_el.get("name", "unknown") if service_el is not None else "unknown"
            )
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            evidence_parts = [f"{host_addr}:{port_id}/{protocol} open", f"service={service_name}"]
            if product:
                evidence_parts.append(f"product={product}")
            if version:
                evidence_parts.append(f"version={version}")

            findings.append(
                Finding.create(
                    scanner="nmap",
                    host=host_addr,
                    code=f"open_port_{protocol}_{port_id}",
                    severity=_nmap_severity(service_name),
                    title=f"Open port {port_id}/{protocol} ({service_name}) on {host_addr}",
                    explanation=(
                        f"Safe-mode Nmap service detection found {port_id}/{protocol} open. "
                        "An exposed network service widens the attack surface and may reveal "
                        "software versions useful to an attacker."
                    ),
                    evidence="; ".join(evidence_parts),
                    remediation=(
                        "Close the port if it is not required, or restrict access to trusted "
                        "networks with firewall rules, a VPN, or an IP allowlist."
                    ),
                    source="nmap",
                )
            )

    return ExternalToolResult(findings=findings, tool_available=True, raw_command=raw_command)


def run_nuclei_scan(
    target_url: str,
    binary: str = "nuclei",
    timeout: float = 180.0,
    rate_limit: int = 10,
    concurrency: int = 5,
) -> ExternalToolResult:
    command = [
        binary,
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-rl",
        str(rate_limit),
        "-c",
        str(concurrency),
        "-timeout",
        "5",
        "-etags",
        NUCLEI_EXCLUDED_TAGS,
    ]
    raw_command = " ".join(command)

    if shutil.which(binary) is None:
        return _tool_missing_result(
            scanner="nuclei", target=target_url, binary=binary, raw_command=raw_command
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ExternalToolResult(
            tool_available=True,
            raw_command=raw_command,
            error=f"Nuclei scan timed out after {timeout} seconds.",
        )
    except OSError as exc:
        return ExternalToolResult(
            tool_available=True,
            raw_command=raw_command,
            error=f"Could not execute nuclei: {exc}",
        )

    findings: list[Finding] = []
    parse_errors = 0
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        info = payload.get("info") or {}
        template_id = str(payload.get("template-id") or payload.get("templateID") or "unknown")
        severity_raw = str(info.get("severity") or "info")
        tags = _nuclei_tags(info.get("tags"))
        classification = info.get("classification") or {}
        cve_id = _nuclei_cve(classification.get("cve-id"))
        cvss_score = _nuclei_cvss(classification.get("cvss-score"))
        owasp_category = _nuclei_owasp(tags)
        matched_at = str(payload.get("matched-at") or payload.get("host") or target_url)
        matcher_name = payload.get("matcher-name") or ""

        evidence_parts = [f"template={template_id}", f"matched-at={matched_at}"]
        if matcher_name:
            evidence_parts.append(f"matcher={matcher_name}")
        if tags:
            evidence_parts.append(f"tags={','.join(tags)}")

        findings.append(
            Finding.create(
                scanner="nuclei",
                host=matched_at,
                code=f"{template_id}@{matched_at}",
                severity=_nuclei_severity(severity_raw),
                title=f"{info.get('name') or template_id} on {matched_at}",
                explanation=str(
                    info.get("description")
                    or "Nuclei matched a non-intrusive template against the target."
                ),
                evidence="; ".join(evidence_parts),
                remediation=str(
                    info.get("remediation")
                    or "Review the matched template, validate the issue, and apply the vendor fix."
                ),
                cve_id=cve_id,
                owasp_category=owasp_category,
                cvss_score=cvss_score,
                source="nuclei",
            )
        )

    error = None
    if parse_errors:
        error = f"Skipped {parse_errors} malformed nuclei JSONL line(s)."
    if not findings and completed.returncode != 0 and completed.stderr.strip():
        error = completed.stderr.strip()

    return ExternalToolResult(
        findings=findings,
        tool_available=True,
        raw_command=raw_command,
        error=error,
    )
