import dns.exception
import dns.resolver
import httpx

from scanners.base import Finding, HostRecord, RateLimiter, Scanner, ScanTarget, Severity
from services.ownership import is_public_ip


class SubdomainScanner(Scanner):
    name = "subdomain"
    description = "Passive subdomain discovery via Certificate Transparency (crt.sh) and DNS"

    def __init__(
        self,
        *,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 8.0,
        user_agent: str = "SurfaceWatch/1.0",
        max_subdomains: int = 50,
    ) -> None:
        super().__init__(rate_limiter=rate_limiter, timeout=timeout, user_agent=user_agent)
        self.max_subdomains = max_subdomains

    def _query_crt_sh(self, domain: str) -> tuple[set[str], str | None]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        discovered: set[str] = set()
        self.rate_limiter.wait()
        try:
            with httpx.Client(
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
                follow_redirects=True,
            ) as client:
                resp = client.get(url)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:
            return discovered, f"Certificate Transparency lookup unavailable: {exc}"

        if not isinstance(payload, list):
            return discovered, None

        for entry in payload:
            raw_names = str(entry.get("name_value", ""))
            for line in raw_names.splitlines():
                candidate = line.strip().lower().rstrip(".")
                if not candidate or candidate.startswith("*."):
                    candidate = candidate.removeprefix("*.")
                if candidate == domain or candidate.endswith(f".{domain}"):
                    if " " not in candidate and "@" not in candidate:
                        discovered.add(candidate)
        return discovered, None

    def _resolve_host(self, hostname: str) -> tuple[list[str], list[str]]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = min(self.timeout, 5.0)
        resolver.timeout = min(self.timeout, 5.0)

        ips: list[str] = []
        cnames: list[str] = []

        try:
            cname_ans = resolver.resolve(hostname, "CNAME")
            for rdata in cname_ans:
                cname_target = str(rdata.target).rstrip(".").lower()
                if cname_target and cname_target not in cnames:
                    cnames.append(cname_target)
        except (dns.exception.DNSException, OSError):
            pass

        for rtype in ("A", "AAAA"):
            try:
                ans = resolver.resolve(hostname, rtype)
                for rdata in ans:
                    ip_str = str(rdata).strip()
                    if is_public_ip(ip_str) and ip_str not in ips:
                        ips.append(ip_str)
            except (dns.exception.DNSException, OSError):
                continue

        return ips, cnames

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        root = target.root_domain

        names, ct_warning = self._query_crt_sh(root)
        candidates = [root] + sorted(n for n in names if n != root)
        candidates = candidates[: self.max_subdomains]

        resolved_hosts: list[HostRecord] = []
        for hostname in candidates:
            self.rate_limiter.wait()
            ips, cnames = self._resolve_host(hostname)
            if ips or cnames or hostname == root:
                resolved_hosts.append(HostRecord(hostname=hostname, ips=ips, cnames=cnames))

        target.hosts = resolved_hosts

        public_hosts = [h for h in resolved_hosts if h.ips]
        summary_lines = [
            f"{h.hostname} -> {', '.join(h.ips) if h.ips else 'CNAME ' + ', '.join(h.cnames)}"
            for h in resolved_hosts
            if h.ips or h.cnames
        ]

        if ct_warning:
            findings.append(
                Finding.create(
                    scanner=self.name,
                    host=root,
                    code="crt_sh_unavailable",
                    severity=Severity.INFO,
                    title="Certificate Transparency feed temporarily unreachable",
                    explanation=(
                        "SurfaceWatch could not retrieve historical certificate records from crt.sh "
                        "during this scan, so discovery fell back to checking the main domain."
                    ),
                    evidence=ct_warning,
                    remediation="Re-run the scan later if you want full passive subdomain enumeration.",
                )
            )

        findings.append(
            Finding.create(
                scanner=self.name,
                host=root,
                code="discovered_footprint",
                severity=Severity.INFO,
                title=f"Discovered {len(public_hosts)} public host(s) via passive CT & DNS",
                explanation=(
                    "These internet-facing domain names were found in public SSL certificate logs "
                    "and currently resolve to public IP addresses."
                ),
                evidence="; ".join(summary_lines[:15]) if summary_lines else "No public A/AAAA records found.",
                remediation=(
                    "Review this list and retire any old test, staging, or forgotten subdomains "
                    "that your business no longer uses."
                ),
            )
        )
        return findings
