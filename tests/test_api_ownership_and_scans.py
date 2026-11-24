from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from scanners.base import Finding, Severity


def test_add_domain_creates_unverified_record(client: TestClient) -> None:
    res = client.post(
        "/api/domains",
        json={"name": "https://Example-Shop.com/about", "owner_label": "alice", "scan_interval_days": 7},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "example-shop.com"
    assert data["verified"] is False
    assert data["verification_token"].startswith("sw-")
    assert data["txt_record_host"] == "_surfacewatch-verify.example-shop.com"
    assert data["txt_record_value"] == f"surfacewatch-verify={data['verification_token']}"


def test_rejects_private_or_loopback_targets(client: TestClient) -> None:
    for invalid in ("localhost", "127.0.0.1", "intranet.internal", "192.168.1.10", "*.example.com"):
        res = client.post("/api/domains", json={"name": invalid})
        assert res.status_code == 422


def test_refuses_scan_on_unverified_domain_and_logs_audit(client: TestClient) -> None:
    created = client.post("/api/domains", json={"name": "unverified-biz.com"}).json()
    scan_res = client.post(f"/api/domains/{created['id']}/scan", json={"actor": "bob"})
    assert scan_res.status_code == 403
    assert "not verified" in scan_res.json()["detail"].lower()

    logs = client.get("/api/audit-logs").json()
    actions = [entry["action"] for entry in logs]
    assert "scan_blocked_unverified" in actions


def test_attestation_verification_stores_timestamp_and_unlocks_scan(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = client.post("/api/domains", json={"name": "my-bakery.com"}).json()

    # Must fail when confirmed is False
    bad = client.post(
        f"/api/domains/{created['id']}/verify/attest",
        json={"confirmed": False, "actor": "owner"},
    )
    assert bad.status_code == 400

    # Succeeds when confirmed is True
    ok = client.post(
        f"/api/domains/{created['id']}/verify/attest",
        json={"confirmed": True, "actor": "owner"},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["verified"] is True
    assert body["domain"]["verified_method"] == "attestation"
    assert body["domain"]["attestation_confirmed_at"] is not None

    # Mock scanners for fast offline execution
    class FakeDiscovery:
        def run(self, target):
            target.ensure_host("my-bakery.com").ips = ["93.184.216.34"]
            return []

    class FakePlugin:
        def run(self, target):
            return [
                Finding.create(
                    scanner="http_exposure",
                    host="my-bakery.com",
                    code="missing_hsts",
                    severity=Severity.MEDIUM,
                    title="Missing HSTS",
                    explanation="HTTPS should be enforced.",
                    evidence="No HSTS header",
                    remediation="Add Strict-Transport-Security header.",
                )
            ]

    monkeypatch.setattr(
        "services.scan_orchestrator.build_default_scanners",
        lambda _rl: (FakeDiscovery(), [FakePlugin()]),
    )

    scan_res = client.post(f"/api/domains/{created['id']}/scan", json={"actor": "owner"})
    assert scan_res.status_code == 200
    assert scan_res.json()["risk_score"] == 7

    html_rep = client.get(f"/api/domains/{created['id']}/report?format=html")
    assert html_rep.status_code == 200
    assert "Missing HSTS" in html_rep.text

    pdf_rep = client.get(f"/api/domains/{created['id']}/report?format=pdf")
    assert pdf_rep.status_code == 200
    assert pdf_rep.content.startswith(b"%PDF")


def test_dns_txt_verification_with_mocked_resolver(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = client.post("/api/domains", json={"name": "acme-dns.org"}).json()
    token = created["verification_token"]

    mock_rdata = MagicMock()
    mock_rdata.strings = [f"surfacewatch-verify={token}".encode("utf-8")]

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = [mock_rdata]
    monkeypatch.setattr("services.ownership.dns.resolver.Resolver", lambda: mock_resolver)

    res = client.post(f"/api/domains/{created['id']}/verify/dns")
    assert res.status_code == 200
    assert res.json()["verified"] is True
    assert res.json()["domain"]["verified_method"] == "dns_txt"


def test_schedule_update_persists(client: TestClient) -> None:
    created = client.post("/api/domains", json={"name": "sched-biz.net"}).json()
    res = client.patch(
        f"/api/domains/{created['id']}/schedule",
        json={"schedule_enabled": False, "scan_interval_days": 14},
    )
    assert res.status_code == 200
    assert res.json()["schedule_enabled"] is False
    assert res.json()["scan_interval_days"] == 14
