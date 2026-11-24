from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import dns.resolver
import httpx
import pytest

from scanners.base import HostRecord, RateLimiter, ScanTarget, Severity
from scanners.dns_email import DnsEmailScanner
from scanners.http_exposure import HttpExposureScanner
from scanners.port_check import PortScanner
from scanners.subdomain import SubdomainScanner
from scanners.tls_check import TlsScanner


def test_subdomain_scanner_filters_private_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = SubdomainScanner(rate_limiter=RateLimiter(1000))

    monkeypatch.setattr(
        scanner,
        "_query_crt_sh",
        lambda _d: ({"api.acme.com", "internal.acme.com", "unrelated.org"}, None),
    )

    def fake_resolve(hostname: str):
        if hostname == "acme.com":
            return ["93.184.216.34"], []
        if hostname == "api.acme.com":
            return ["93.184.216.35"], []
        if hostname == "internal.acme.com":
            return [], []  # Private IPs stripped by is_public_ip
        return [], []

    monkeypatch.setattr(scanner, "_resolve_host", fake_resolve)
    target = ScanTarget(root_domain="acme.com")
    findings = scanner.run(target)

    hostnames = [h.hostname for h in target.hosts]
    assert "acme.com" in hostnames
    assert "api.acme.com" in hostnames
    assert "unrelated.org" not in hostnames
    assert any("Discovered 2 public host(s)" in f.title for f in findings)


def test_dns_email_scanner_detects_weak_spf_missing_dmarc_and_dangling_cname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = DnsEmailScanner(rate_limiter=RateLimiter(1000))

    class FakeRdata:
        def __init__(self, text: str) -> None:
            self.strings = [text.encode("utf-8")]

    class FakeResolver:
        def resolve(self, name: str, rtype: str):
            if name == "acme.com" and rtype == "TXT":
                return [FakeRdata("v=spf1 +all")]
            raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("scanners.dns_email.dns.resolver.Resolver", lambda: FakeResolver())

    target = ScanTarget(
        root_domain="acme.com",
        hosts=[
            HostRecord(hostname="acme.com", ips=["93.184.216.34"]),
            HostRecord(hostname="blog.acme.com", ips=[], cnames=["acme-blog.herokuapp.com"]),
        ],
    )
    findings = scanner.run(target)
    codes = {f.code for f in findings}
    assert "spf_plus_all" in codes
    assert "dmarc_missing" in codes
    assert "dkim_not_found_common" in codes
    assert any(c.startswith("dangling_cname_") for c in codes)


def test_tls_scanner_flags_expiring_and_mismatched_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = TlsScanner(rate_limiter=RateLimiter(1000))

    fake_cert = MagicMock()
    fake_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=5)
    fake_cert.issuer = MagicMock()
    fake_cert.subject = MagicMock()
    fake_cert.issuer.__eq__ = lambda self, other: False

    monkeypatch.setattr(
        scanner,
        "_fetch_verified_and_raw_cert",
        lambda _h, port=443: (fake_cert, None, True, False),
    )
    monkeypatch.setattr(scanner, "_matches_san_or_cn", lambda _c, _h: False)
    monkeypatch.setattr(scanner, "_check_weak_protocols", lambda _h, port=443: ["TLSv1.0"])

    target = ScanTarget(
        root_domain="acme.com",
        hosts=[HostRecord(hostname="acme.com", ips=["93.184.216.34"])],
    )
    findings = scanner.run(target)
    codes = {f.code for f in findings}
    assert "tls_expiring_7d" in codes
    assert "tls_hostname_mismatch" in codes
    assert "tls_weak_protocols" in codes


def test_port_scanner_flags_risky_open_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = PortScanner(rate_limiter=RateLimiter(1000))
    monkeypatch.setattr(scanner, "_is_port_open", lambda _ip, port: port in {443, 6379})

    target = ScanTarget(
        root_domain="acme.com",
        hosts=[HostRecord(hostname="acme.com", ips=["93.184.216.34"])],
    )
    findings = scanner.run(target)
    by_code = {f.code: f for f in findings}
    assert "open_port_6379" in by_code
    assert by_code["open_port_6379"].severity == Severity.CRITICAL
    assert "open_port_443" in by_code
    assert by_code["open_port_443"].severity == Severity.INFO


def test_http_exposure_scanner_detects_missing_headers_and_exposed_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text="<html>Home</html>", headers={"Server": "nginx"})
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        if request.url.path == "/.env":
            return httpx.Response(200, text="<html>Not found</html>")  # soft-404 HTML ignored
        return httpx.Response(404, text="Not found")

    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    def mocked_client(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr("scanners.http_exposure.httpx.Client", mocked_client)

    scanner = HttpExposureScanner(rate_limiter=RateLimiter(1000))
    target = ScanTarget(
        root_domain="acme.com",
        hosts=[HostRecord(hostname="acme.com", ips=["93.184.216.34"])],
    )
    findings = scanner.run(target)
    codes = {f.code for f in findings}
    assert "missing_header_strict-transport-security" in codes
    assert "missing_header_content-security-policy" in codes
    assert "exposed_git_head" in codes
    assert "exposed_env_file" not in codes
