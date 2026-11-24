import pytest
from fastapi.testclient import TestClient

from models.schemas import FindingOut
from scanners.base import Finding, Severity
from services.diff_engine import compute_scan_diff
from services.risk_score import calculate_risk_score, risk_grade_label


def test_risk_score_weights_and_cap() -> None:
    assert calculate_risk_score([]) == 0
    assert calculate_risk_score(["info", "info"]) == 0
    assert calculate_risk_score(["critical", "high", "medium", "low"]) == 49
    assert calculate_risk_score(["critical"] * 10) == 100
    assert risk_grade_label(80) == "Critical"
    assert risk_grade_label(50) == "Elevated"
    assert risk_grade_label(20) == "Moderate"
    assert risk_grade_label(5) == "Low"


def test_diff_engine_classifies_new_resolved_and_unchanged() -> None:
    prev = [
        FindingOut(
            id="f1",
            scanner="tls",
            host="a.com",
            severity="high",
            title="Old TLS",
            explanation="e",
            evidence="ev",
            remediation="r",
        ),
        FindingOut(
            id="f2",
            scanner="http_exposure",
            host="a.com",
            severity="medium",
            title="Missing CSP",
            explanation="e",
            evidence="ev",
            remediation="r",
        ),
    ]
    curr = [
        FindingOut(
            id="f2",
            scanner="http_exposure",
            host="a.com",
            severity="medium",
            title="Missing CSP",
            explanation="e",
            evidence="ev",
            remediation="r",
        ),
        FindingOut(
            id="f3",
            scanner="port_check",
            host="a.com",
            severity="critical",
            title="Open Redis",
            explanation="e",
            evidence="ev",
            remediation="r",
        ),
    ]

    diff = compute_scan_diff(
        current_scan_id=2,
        previous_scan_id=1,
        current_findings=curr,
        previous_findings=prev,
    )
    assert diff.counts == {"new": 1, "resolved": 1, "unchanged": 1}
    assert diff.new[0].id == "f3"
    assert diff.resolved[0].id == "f1"
    assert diff.unchanged[0].id == "f2"


def test_api_change_detection_across_two_scans(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    dom = client.post("/api/domains", json={"name": "delta-check.com"}).json()
    client.post(f"/api/domains/{dom['id']}/verify/attest", json={"confirmed": True, "actor": "me"})

    scan_round = {"n": 0}

    class FakeDiscovery:
        def run(self, target):
            target.ensure_host("delta-check.com").ips = ["93.184.216.34"]
            return []

    class FakePlugin:
        def run(self, target):
            scan_round["n"] += 1
            if scan_round["n"] == 1:
                return [
                    Finding.create(
                        scanner="port_check",
                        host="delta-check.com",
                        code="open_port_6379",
                        severity=Severity.CRITICAL,
                        title="Open Redis",
                        explanation="Redis exposed",
                        evidence="6379 open",
                        remediation="Close 6379",
                    ),
                    Finding.create(
                        scanner="http_exposure",
                        host="delta-check.com",
                        code="missing_csp",
                        severity=Severity.MEDIUM,
                        title="Missing CSP",
                        explanation="No CSP",
                        evidence="No CSP",
                        remediation="Add CSP",
                    ),
                ]
            return [
                Finding.create(
                    scanner="http_exposure",
                    host="delta-check.com",
                    code="missing_csp",
                    severity=Severity.MEDIUM,
                    title="Missing CSP",
                    explanation="No CSP",
                    evidence="No CSP",
                    remediation="Add CSP",
                ),
                Finding.create(
                    scanner="tls",
                    host="delta-check.com",
                    code="tls_expiring_30d",
                    severity=Severity.MEDIUM,
                    title="Expiring soon",
                    explanation="Expires soon",
                    evidence="20 days",
                    remediation="Renew",
                ),
            ]

    monkeypatch.setattr(
        "services.scan_orchestrator.build_default_scanners",
        lambda _rl: (FakeDiscovery(), [FakePlugin()]),
    )

    client.post(f"/api/domains/{dom['id']}/scan")
    client.post(f"/api/domains/{dom['id']}/scan")

    diff = client.get(f"/api/domains/{dom['id']}/diff").json()
    assert diff["counts"] == {"new": 1, "resolved": 1, "unchanged": 1}
    assert diff["new"][0]["title"] == "Expiring soon"
    assert diff["resolved"][0]["title"] == "Open Redis"
