import dns.exception
import dns.resolver

from scanners.base import Finding, Scanner, ScanTarget, Severity

COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "dkim",
    "s1",
    "s2",
)

TAKEOVER_PROVIDER_SUFFIXES = (
    ".github.io",
    ".herokuapp.com",
    ".s3.amazonaws.com",
    ".s3-website",
    ".azurewebsites.net",
    ".cloudapp.net",
    ".pantheonsite.io",
    ".zendesk.com",
    ".netlify.app",
    ".vercel.app",
    ".cloudfront.net",
    ".wpengine.com",
)


class DnsEmailScanner(Scanner):
    name = "dns_email"
    description = "Checks SPF, DKIM selectors, DMARC policy strength, and dangling CNAME records"

    def _get_txt_records(self, resolver: dns.resolver.Resolver, name: str) -> list[str]:
        records: list[str] = []
        try:
            self.rate_limiter.wait()
            answers = resolver.resolve(name, "TXT")
            for rdata in answers:
                text = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in getattr(rdata, "strings", [str(rdata)])
                ).strip('"')
                if text:
                    records.append(text)
        except (dns.exception.DNSException, OSError):
            pass
        return records

    def _check_spf(self, resolver: dns.resolver.Resolver, root: str) -> list[Finding]:
        findings: list[Finding] = []
        txt_records = self._get_txt_records(resolver, root)
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

        if not spf_records:
            findings.append(
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="spf_missing",
                    severity=Severity.MEDIUM,
                    title="Missing SPF email authentication record",
                    explanation=(
                        "Your domain does not publish an SPF record telling mail providers which "
                        "servers are authorized to send email on your behalf. Attackers can more "
                        "easily spoof your domain in phishing emails."
                    ),
                    evidence=f"No TXT record starting with 'v=spf1' found on {root}.",
                    remediation=(
                        "Add a TXT record on your root domain listing your authorized email senders "
                        "(for example: 'v=spf1 include:_spf.google.com ~all')."
                    ),
                )
            )
            return findings

        if len(spf_records) > 1:
            findings.append(
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="spf_multiple",
                    severity=Severity.MEDIUM,
                    title="Multiple SPF records detected",
                    explanation=(
                        "Publishing more than one SPF record violates email standards and causes "
                        "many receiving mail servers to fail authentication unpredictably."
                    ),
                    evidence=" | ".join(spf_records),
                    remediation="Merge all authorized mail senders into a single v=spf1 TXT record.",
                )
            )

        primary = spf_records[0].lower()
        if "+all" in primary:
            findings.append(
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="spf_plus_all",
                    severity=Severity.HIGH,
                    title="SPF record uses permissive '+all' policy",
                    explanation=(
                        "Using '+all' tells the world that any server on the internet is allowed "
                        "to send email claiming to be from your business."
                    ),
                    evidence=spf_records[0],
                    remediation="Replace '+all' with '-all' (reject) or '~all' (softfail).",
                )
            )
        elif "?all" in primary:
            findings.append(
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="spf_neutral_all",
                    severity=Severity.MEDIUM,
                    title="SPF record uses neutral '?all' policy",
                    explanation=(
                        "A neutral '?all' policy offers virtually no protection against unauthorized "
                        "senders spoofing your domain."
                    ),
                    evidence=spf_records[0],
                    remediation="Tighten the SPF policy ending from '?all' to '~all' or '-all'.",
                )
            )
        elif "~all" in primary:
            findings.append(
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="spf_softfail",
                    severity=Severity.LOW,
                    title="SPF record uses softfail (~all) instead of strict fail (-all)",
                    explanation=(
                        "Your SPF policy flags unauthorized senders as suspicious (~all), rather than "
                        "explicitly instructing receivers to reject them (-all)."
                    ),
                    evidence=spf_records[0],
                    remediation=(
                        "Once you verify all legitimate senders are listed, consider updating '~all' to '-all'."
                    ),
                )
            )
        return findings

    def _check_dkim(self, resolver: dns.resolver.Resolver, root: str) -> list[Finding]:
        found_selectors: list[str] = []
        for selector in COMMON_DKIM_SELECTORS:
            fqdn = f"{selector}._domainkey.{root}"
            records = self._get_txt_records(resolver, fqdn)
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
                found_selectors.append(selector)

        if not found_selectors:
            return [
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="dkim_not_found_common",
                    severity=Severity.LOW,
                    title="No DKIM record found on common selectors",
                    explanation=(
                        "DKIM cryptographically signs outgoing emails so customers and partners know "
                        "messages truly came from your business. None of the standard selector names "
                        "were found (though a custom selector could still be active)."
                    ),
                    evidence=f"Checked selectors: {', '.join(COMMON_DKIM_SELECTORS)}",
                    remediation=(
                        "Verify in your email provider settings (Google Workspace, Microsoft 365, etc.) "
                        "that DKIM signing is enabled and its DNS record is published."
                    ),
                )
            ]

        return [
            Finding.create(
                scanner=self.name,
                host=root,
                code="dkim_present",
                severity=Severity.INFO,
                title=f"DKIM selector(s) published ({', '.join(found_selectors)})",
                explanation="Your domain publishes cryptographic DKIM keys for outgoing email signing.",
                evidence=f"Active selectors: {', '.join(found_selectors)}",
                remediation="Rotate DKIM keys periodically according to your mail provider's guidance.",
            )
        ]

    def _check_dmarc(self, resolver: dns.resolver.Resolver, root: str) -> list[Finding]:
        dmarc_host = f"_dmarc.{root}"
        records = [r for r in self._get_txt_records(resolver, dmarc_host) if "v=dmarc1" in r.lower()]

        if not records:
            return [
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="dmarc_missing",
                    severity=Severity.MEDIUM,
                    title="Missing DMARC email protection record",
                    explanation=(
                        "Without DMARC, receiving mail providers do not know how to handle emails "
                        "that fail SPF or DKIM checks, leaving your brand vulnerable to impersonation."
                    ),
                    evidence=f"No TXT record with 'v=DMARC1' found at {dmarc_host}.",
                    remediation=(
                        f"Publish a TXT record at {dmarc_host} starting with "
                        "'v=DMARC1; p=quarantine; rua=mailto:security@" + root + "'."
                    ),
                )
            ]

        policy_record = records[0]
        lower = policy_record.lower()
        if "p=none" in lower:
            return [
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="dmarc_p_none",
                    severity=Severity.MEDIUM,
                    title="DMARC policy is set to monitor-only (p=none)",
                    explanation=(
                        "Your DMARC record collects reports but does not instruct mail providers to "
                        "quarantine or reject spoofed emails pretending to be from your company."
                    ),
                    evidence=policy_record,
                    remediation=(
                        "Review DMARC reports to ensure legitimate mail passes, then upgrade the "
                        "policy from 'p=none' to 'p=quarantine' or 'p=reject'."
                    ),
                )
            ]

        return [
            Finding.create(
                scanner=self.name,
                host=root,
                code="dmarc_enforced",
                severity=Severity.INFO,
                title="Enforced DMARC policy detected",
                explanation="Your domain publishes an active DMARC policy instructing receivers to filter spoofed mail.",
                evidence=policy_record,
                remediation="Continue monitoring DMARC aggregate reports for delivery anomalies.",
            )
        ]

    def _check_dangling_cnames(
        self, resolver: dns.resolver.Resolver, target: ScanTarget
    ) -> list[Finding]:
        findings: list[Finding] = []
        for host in target.hosts:
            if not host.cnames:
                continue
            for cname_target in host.cnames:
                resolves = False
                for rtype in ("A", "AAAA"):
                    try:
                        self.rate_limiter.wait()
                        ans = resolver.resolve(cname_target, rtype)
                        if len(ans) > 0:
                            resolves = True
                            break
                    except (dns.exception.DNSException, OSError):
                        continue

                matches_cloud_provider = any(
                    cname_target.endswith(suffix) or suffix in cname_target
                    for suffix in TAKEOVER_PROVIDER_SUFFIXES
                )
                if not resolves:
                    severity = Severity.HIGH if matches_cloud_provider else Severity.MEDIUM
                    findings.append(
                        Finding.create(
                            scanner=self.name,
                            host=host.hostname,
                            code=f"dangling_cname_{cname_target}",
                            severity=severity,
                            title=f"Dangling CNAME detected on {host.hostname}",
                            explanation=(
                                "This subdomain points to an external target that no longer resolves. "
                                "If it points to an unclaimed cloud service, an attacker could register "
                                "that resource and host malicious content under your company's domain."
                            ),
                            evidence=f"{host.hostname} CNAME -> {cname_target} (target fails DNS resolution)",
                            remediation=(
                                f"Remove the stale CNAME record for {host.hostname} in your DNS panel "
                                "or reclaim the target service immediately."
                            ),
                        )
                    )
        return findings

    def run(self, target: ScanTarget) -> list[Finding]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = min(self.timeout, 5.0)
        resolver.timeout = min(self.timeout, 5.0)

        findings: list[Finding] = []
        findings.extend(self._check_spf(resolver, target.root_domain))
        findings.extend(self._check_dkim(resolver, target.root_domain))
        findings.extend(self._check_dmarc(resolver, target.root_domain))
        findings.extend(self._check_dangling_cnames(resolver, target))
        return findings
