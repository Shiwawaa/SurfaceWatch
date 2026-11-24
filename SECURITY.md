# Security Policy

## Defensive-Use Mandate

**SurfaceWatch is strictly a defensive external attack-surface monitoring tool.**

By running this software, you agree to scan **only** domains and infrastructure that:
1. You directly own, or
2. You have explicit, documented written authorization from the asset owner to assess.

Unauthorized scanning of third-party infrastructure may violate local, national, or international laws (such as the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or EU directives).

## Built-In Technical Safeguards

- **Mandatory Ownership Gate**: Scans are refused (HTTP `403`) unless the domain has passed DNS TXT token verification or explicit timestamped ownership attestation.
- **Passive-First Discovery**: Subdomain enumeration relies strictly on public Certificate Transparency logs (`crt.sh`) and standard DNS resolution. No dictionary brute-forcing is performed.
- **Non-Intrusive Checks**: Port checks perform TCP connect/close handshakes only on a small fixed port list (`21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017`). HTTP checks send single `GET` requests for known misconfiguration paths (`/.git/HEAD`, `/.env`, `/phpinfo.php`, `/admin`). No exploits or payloads are sent.
- **SSRF & Private Network Protection**: Loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and reserved IPv6 ranges are blocked before any network probe occurs.
- **Rate Limiting & Transparency**: Global request pacing and an explicit `SurfaceWatch/1.0` `User-Agent` identify all HTTP traffic.
- **Immutable Audit Trail**: Every verification event, scan trigger, blocked scan, and report export is logged with actor, domain, and UTC timestamp.

## Reporting a Security Vulnerability

If you discover a security vulnerability in SurfaceWatch itself:

1. **Do not** open a public GitHub issue with exploit details.
2. Email the maintainers privately or use GitHub Private Vulnerability Reporting on the repository.
3. Include steps to reproduce, affected files, and suggested remediation.
4. We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.
