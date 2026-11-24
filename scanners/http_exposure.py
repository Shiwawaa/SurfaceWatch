import httpx

from scanners.base import Finding, Scanner, ScanTarget, Severity

SECURITY_HEADERS: tuple[tuple[str, str, Severity, str, str], ...] = (
    (
        "strict-transport-security",
        "Strict-Transport-Security (HSTS)",
        Severity.MEDIUM,
        "Without HSTS, browsers do not remember to enforce HTTPS on future visits, allowing downgrade attacks on public Wi-Fi.",
        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "content-security-policy",
        "Content-Security-Policy (CSP)",
        Severity.MEDIUM,
        "A missing Content-Security-Policy leaves your site with fewer defenses against cross-site scripting (XSS) code injection.",
        "Configure a Content-Security-Policy header restricting script and frame sources to trusted origins.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        Severity.LOW,
        "Missing X-Frame-Options allows external sites to embed your pages in hidden iframes (clickjacking risk).",
        "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing within your own site is required).",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        Severity.LOW,
        "Without 'nosniff', older browsers may misinterpret uploaded files as executable scripts.",
        "Add header: X-Content-Type-Options: nosniff",
    ),
)

SENSITIVE_PATHS: tuple[str, ...] = (
    "/admin",
    "/.git/HEAD",
    "/.env",
    "/phpinfo.php",
)


class HttpExposureScanner(Scanner):
    name = "http_exposure"
    description = "Checks missing HTTP security headers and single-GET exposed sensitive paths"

    def _check_headers(
        self, client: httpx.Client, base_url: str, hostname: str
    ) -> tuple[bool, list[Finding]]:
        findings: list[Finding] = []
        self.rate_limiter.wait()
        try:
            resp = client.get(f"{base_url}/")
        except httpx.HTTPError:
            return False, findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        is_https = base_url.startswith("https://")

        for header_key, display_name, severity, explanation, remediation in SECURITY_HEADERS:
            if header_key == "strict-transport-security" and not is_https:
                continue
            if header_key not in headers_lower:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code=f"missing_header_{header_key}",
                        severity=severity,
                        title=f"Missing {display_name} header on {hostname}",
                        explanation=explanation,
                        evidence=f"HTTP {resp.status_code} from {base_url}/ lacked '{header_key}'",
                        remediation=remediation,
                    )
                )
        return True, findings

    def _check_sensitive_paths(
        self, client: httpx.Client, base_url: str, hostname: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for path in SENSITIVE_PATHS:
            self.rate_limiter.wait()
            try:
                resp = client.get(f"{base_url}{path}")
            except httpx.HTTPError:
                continue

            if resp.status_code != 200:
                continue

            body = resp.text[:4096]
            body_lower = body.lower()

            if path == "/.git/HEAD" and "ref:" in body:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="exposed_git_head",
                        severity=Severity.CRITICAL,
                        title=f"Exposed Git repository metadata (/.git/HEAD) on {hostname}",
                        explanation=(
                            "Your web server is exposing internal Git source-control files, which can allow "
                            "attackers to download your website's source code and secrets."
                        ),
                        evidence=f"GET {base_url}{path} returned HTTP 200 with content: {body[:120].strip()}",
                        remediation="Block public web access to all '.git' directories in Nginx/Apache/CDN rules immediately.",
                    )
                )
            elif path == "/.env" and "=" in body and "<html" not in body_lower:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="exposed_env_file",
                        severity=Severity.CRITICAL,
                        title=f"Exposed environment configuration file (/.env) on {hostname}",
                        explanation=(
                            "An '.env' file is publicly downloadable. These files commonly contain database "
                            "passwords, API keys, and payment secrets."
                        ),
                        evidence=f"GET {base_url}{path} returned HTTP 200 with key=value configuration pairs.",
                        remediation="Remove '.env' from webroot, block dotfile access in your server config, and rotate all exposed secrets.",
                    )
                )
            elif path == "/phpinfo.php" and ("php version" in body_lower or "phpinfo()" in body_lower):
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="exposed_phpinfo",
                        severity=Severity.HIGH,
                        title=f"Exposed diagnostic page (/phpinfo.php) on {hostname}",
                        explanation=(
                            "A PHP diagnostic page is publicly visible, revealing server software versions, "
                            "file paths, and environment variables that help attackers plan targeted exploits."
                        ),
                        evidence=f"GET {base_url}{path} returned HTTP 200 containing PHP configuration details.",
                        remediation="Delete phpinfo.php from your production web server immediately.",
                    )
                )
            elif path == "/admin" and "not found" not in body_lower and "404" not in body_lower:
                findings.append(
                    Finding.create(
                        scanner=self.name,
                        host=hostname,
                        code="exposed_admin_path",
                        severity=Severity.MEDIUM,
                        title=f"Publicly accessible /admin endpoint on {hostname}",
                        explanation=(
                            "An administrative interface responded at /admin without an access block. "
                            "Exposed admin portals are frequent targets for password-guessing attacks."
                        ),
                        evidence=f"GET {base_url}{path} returned HTTP 200 ({len(resp.content)} bytes).",
                        remediation=(
                            "Restrict /admin access by IP allowlist or VPN, and require Multi-Factor Authentication."
                        ),
                    )
                )
        return findings

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        hosts = [h for h in target.hosts if h.ips] or target.hosts[:1]

        with httpx.Client(
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=False,
        ) as client:
            for host_rec in hosts:
                hostname = host_rec.hostname
                reachable = False
                for scheme in ("https", "http"):
                    base_url = f"{scheme}://{hostname}"
                    ok, header_findings = self._check_headers(client, base_url, hostname)
                    if ok:
                        reachable = True
                        findings.extend(header_findings)
                        findings.extend(self._check_sensitive_paths(client, base_url, hostname))
                        break
                if not reachable:
                    continue

        return findings
