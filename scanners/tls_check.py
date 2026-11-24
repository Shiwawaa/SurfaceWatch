import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from scanners.base import Finding, Scanner, ScanTarget, Severity


class TlsScanner(Scanner):
    name = "tls"
    description = "Inspects TLS certificates for expiry, hostname mismatch, self-signed chains, and weak protocols"

    def _fetch_verified_and_raw_cert(
        self, hostname: str, port: int = 443
    ) -> tuple[x509.Certificate | None, str | None, bool, bool]:
        """Returns (cert, connection_error, hostname_mismatch, untrusted_or_self_signed)."""
        hostname_mismatch = False
        untrusted = False

        verified_ctx = ssl.create_default_context()
        try:
            self.rate_limiter.wait()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with verified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        return x509.load_der_x509_certificate(der), None, False, False
        except ssl.CertificateError as exc:
            msg = str(exc).lower()
            if "hostname" in msg or "ip address" in msg:
                hostname_mismatch = True
            else:
                untrusted = True
        except ssl.SSLCertVerificationError as exc:
            msg = str(exc).lower()
            if "hostname" in msg or "ip address" in msg:
                hostname_mismatch = True
            else:
                untrusted = True
        except (OSError, ssl.SSLError) as exc:
            return None, str(exc), False, False

        # Fallback read-only inspection without verification to extract certificate metadata
        raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        raw_ctx.check_hostname = False
        raw_ctx.verify_mode = ssl.CERT_NONE
        try:
            self.rate_limiter.wait()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with raw_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        return (
                            x509.load_der_x509_certificate(der),
                            None,
                            hostname_mismatch,
                            untrusted,
                        )
        except (OSError, ssl.SSLError) as exc:
            return None, str(exc), hostname_mismatch, untrusted

        return None, "No certificate returned", hostname_mismatch, untrusted

    def _check_weak_protocols(self, hostname: str, port: int = 443) -> list[str]:
        accepted: list[str] = []
        candidates = []
        if hasattr(ssl, "TLSVersion"):
            candidates = [
                ("TLSv1.0", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ]

        for label, tls_version in candidates:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
                self.rate_limiter.wait()
                with socket.create_connection((hostname, port), timeout=min(self.timeout, 4.0)) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        accepted.append(label)
            except (OSError, ssl.SSLError, ValueError):
                continue
        return accepted

    @staticmethod
    def _matches_san_or_cn(cert: x509.Certificate, hostname: str) -> bool:
        names: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names.extend(san.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass

        if not names:
            for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                names.append(str(attr.value))

        host_lower = hostname.lower()
        for pattern in names:
            pat = pattern.lower()
            if pat == host_lower:
                return True
            if pat.startswith("*."):
                suffix = pat[1:]  # ".example.com"
                if host_lower.endswith(suffix) and host_lower.count(".") == pat.count("."):
                    return True
        return False

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        hosts = [h for h in target.hosts if h.ips] or target.hosts[:1]

        for host_rec in hosts:
            hostname = host_rec.hostname
            cert, conn_err, mismatch, untrusted = self._fetch_verified_and_raw_cert(hostname)
            if cert is None:
                continue

            now = datetime.now(timezone.utc)
            not_after = cert.not_valid_after_utc
            days_left = (not_after - now).days

            if days_left < 0:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_expired",
                        severity=Severity.CRITICAL,
                        title=f"SSL/TLS certificate expired on {hostname}",
                        explanation=(
                            "Visitors to this site will see a full-screen browser security warning "
                            "and may be blocked from accessing your business website."
                        ),
                        evidence=f"Expired on {not_after.date().isoformat()} ({abs(days_left)} day(s) ago)",
                        remediation="Renew and install a valid TLS certificate immediately (e.g. via Let's Encrypt).",
                    )
                )
            elif days_left <= 7:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_expiring_7d",
                        severity=Severity.HIGH,
                        title=f"SSL/TLS certificate expires in {days_left} day(s)",
                        explanation="Your SSL certificate is days away from expiring, which will cause outages.",
                        evidence=f"Valid until {not_after.date().isoformat()} ({days_left} days left)",
                        remediation="Renew the TLS certificate immediately and enable automated renewal.",
                    )
                )
            elif days_left <= 14:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_expiring_14d",
                        severity=Severity.HIGH,
                        title=f"SSL/TLS certificate expires within 14 days ({days_left} days)",
                        explanation="Your SSL certificate expires in under two weeks.",
                        evidence=f"Valid until {not_after.date().isoformat()}",
                        remediation="Renew the TLS certificate and check your auto-renewal cron or ACME client.",
                    )
                )
            elif days_left <= 30:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_expiring_30d",
                        severity=Severity.MEDIUM,
                        title=f"SSL/TLS certificate expires within 30 days ({days_left} days)",
                        explanation="Your SSL certificate is approaching expiration within the next month.",
                        evidence=f"Valid until {not_after.date().isoformat()}",
                        remediation="Verify automatic certificate renewal is active before expiration.",
                    )
                )

            if not self._matches_san_or_cn(cert, hostname) or mismatch:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_hostname_mismatch",
                        severity=Severity.HIGH,
                        title=f"TLS certificate hostname mismatch on {hostname}",
                        explanation=(
                            "The SSL certificate served by this host is issued for a different domain name, "
                            "triggering browser trust warnings for visitors."
                        ),
                        evidence=f"Host {hostname} does not match certificate SAN/CN ({cert.subject.rfc4514_string()})",
                        remediation=f"Issue a TLS certificate whose Subject Alternative Name includes {hostname}.",
                    )
                )

            is_self_signed = cert.issuer == cert.subject
            if is_self_signed or untrusted:
                sha256_fp = cert.fingerprint(hashes.SHA256()).hex()[:16]
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_self_signed_or_untrusted",
                        severity=Severity.HIGH,
                        title=f"{'Self-signed' if is_self_signed else 'Untrusted'} TLS certificate on {hostname}",
                        explanation=(
                            "Browsers do not trust self-signed or incomplete certificate chains, "
                            "making visitors vulnerable to interception warnings."
                        ),
                        evidence=f"Issuer={cert.issuer.rfc4514_string()} | Fingerprint={sha256_fp}",
                        remediation="Replace with a publicly trusted certificate (such as Let's Encrypt) with full intermediate chain.",
                    )
                )

            weak_versions = self._check_weak_protocols(hostname)
            if weak_versions:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="tls_weak_protocols",
                        severity=Severity.HIGH,
                        title=f"Deprecated TLS protocol(s) enabled: {', '.join(weak_versions)}",
                        explanation=(
                            "Older TLS 1.0 and 1.1 protocols have known cryptographic weaknesses and "
                            "fail modern compliance requirements."
                        ),
                        evidence=f"Accepted legacy handshake on {hostname}: {', '.join(weak_versions)}",
                        remediation="Disable TLS 1.0 and TLS 1.1 in your web server/load balancer and require TLS 1.2+.",
                    )
                )

        return findings
