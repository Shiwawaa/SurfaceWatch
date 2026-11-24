import socket

from scanners.base import Finding, RateLimiter, Scanner, ScanTarget, Severity

ALLOWED_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    80,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
    27017,
)

PORT_RISK_PROFILES: dict[int, tuple[str, Severity, str, str]] = {
    23: (
        "Telnet",
        Severity.CRITICAL,
        "Telnet transmits usernames, passwords, and commands in unencrypted plaintext over the internet.",
        "Disable Telnet immediately and use SSH or a private VPN instead.",
    ),
    445: (
        "SMB File Sharing",
        Severity.CRITICAL,
        "Exposed Windows/SMB file sharing ports are a primary target for ransomware and worm attacks.",
        "Block port 445 at your perimeter firewall and restrict file sharing to a private VPN.",
    ),
    6379: (
        "Redis",
        Severity.CRITICAL,
        "Exposed Redis cache databases frequently lack authentication and allow rapid data theft or server takeover.",
        "Bind Redis to 127.0.0.1 or a private VPC subnet and block port 6379 publicly.",
    ),
    27017: (
        "MongoDB",
        Severity.CRITICAL,
        "Publicly reachable MongoDB ports expose sensitive customer or operational data to automated ransom bots.",
        "Restrict MongoDB to internal application servers via firewall rules and enable authentication.",
    ),
    3389: (
        "Remote Desktop (RDP)",
        Severity.HIGH,
        "Internet-exposed RDP is heavily targeted by brute-force credential attacks and ransomware operators.",
        "Place RDP behind a VPN with Multi-Factor Authentication (MFA) and close port 3389 publicly.",
    ),
    3306: (
        "MySQL / MariaDB",
        Severity.HIGH,
        "Your database service is reachable from the public internet, increasing risk of brute-force or data leaks.",
        "Bind the database to localhost/private network and block port 3306 on public firewall rules.",
    ),
    5432: (
        "PostgreSQL",
        Severity.HIGH,
        "Your PostgreSQL database port is open to the public internet rather than restricted to your app server.",
        "Restrict port 5432 to trusted private IPs or localhost in firewall and pg_hba.conf settings.",
    ),
    21: (
        "FTP",
        Severity.HIGH,
        "Standard FTP sends credentials and files unencrypted over the network.",
        "Disable FTP on port 21 and migrate file transfers to SFTP (over SSH) or FTPS.",
    ),
    22: (
        "SSH",
        Severity.LOW,
        "SSH administrative access is reachable from the internet. This is common on servers, but requires strict hardening.",
        "Disable password logins in favor of SSH keys, and restrict port 22 by IP allowlist or VPN where possible.",
    ),
    25: (
        "SMTP Mail",
        Severity.INFO,
        "SMTP mail port 25 is open. Expected for mail servers, otherwise unnecessary exposure.",
        "Confirm this host is an intentional mail exchanger; otherwise close port 25.",
    ),
    8080: (
        "Alternate HTTP (8080)",
        Severity.LOW,
        "An alternate web port (8080) is open publicly, often indicating a dev server, admin panel, or unencrypted proxy.",
        "Verify whether port 8080 is intentional; route production web traffic over HTTPS (443) only.",
    ),
    80: (
        "HTTP (80)",
        Severity.INFO,
        "Standard web port 80 is open (typically used to redirect visitors to HTTPS on port 443).",
        "Ensure all traffic on port 80 immediately redirects to HTTPS (port 443).",
    ),
    443: (
        "HTTPS (443)",
        Severity.INFO,
        "Standard encrypted web port 443 is open.",
        "Keep TLS certificates valid and web server software patched.",
    ),
}


class PortScanner(Scanner):
    name = "port_check"
    description = "Connect-only TCP reachability check on a small list of common ports"

    def __init__(
        self,
        *,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 2.0,
        user_agent: str = "SurfaceWatch/1.0",
    ) -> None:
        super().__init__(rate_limiter=rate_limiter, timeout=timeout, user_agent=user_agent)

    def _is_port_open(self, ip: str, port: int) -> bool:
        self.rate_limiter.wait()
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        scanned_ips: set[str] = set()

        for host_rec in target.hosts:
            if not host_rec.ips:
                continue
            target_ip = host_rec.ips[0]
            if target_ip in scanned_ips:
                continue
            scanned_ips.add(target_ip)

            for port in ALLOWED_PORTS:
                if self._is_port_open(target_ip, port):
                    service_name, severity, explanation, remediation = PORT_RISK_PROFILES[port]
                    findings.append(
                        Finding.create(
                            scanner=self.name,
                            host=host_rec.hostname,
                            code=f"open_port_{port}",
                            severity=severity,
                            title=f"Port {port} ({service_name}) is open on {host_rec.hostname}",
                            explanation=explanation,
                            evidence=f"TCP connect succeeded on {target_ip}:{port}",
                            remediation=remediation,
                        )
                    )
        return findings
