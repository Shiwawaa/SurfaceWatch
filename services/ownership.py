import ipaddress
import re
import secrets

import dns.exception
import dns.resolver

ATTESTATION_STATEMENT = "I own or am authorized to test this domain"

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".arpa", ".lan", ".home", ".corp")


class DomainValidationError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    if not value:
        raise DomainValidationError("Domain name cannot be empty.")

    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]
    if ":" in value:
        value = value.split(":", 1)[0]
    value = value.rstrip(".")

    if value.startswith("*."):
        raise DomainValidationError("Wildcard domains are not allowed. Enter a specific domain.")

    try:
        ipaddress.ip_address(value)
        raise DomainValidationError("IP addresses are not allowed. Enter a registered domain name.")
    except ValueError:
        pass

    if value in {"localhost", "127.0.0.1", "::1"} or any(
        value.endswith(suffix) for suffix in _BLOCKED_SUFFIXES
    ):
        raise DomainValidationError("Internal, loopback, or reserved hostnames cannot be scanned.")

    if not _HOSTNAME_RE.match(value):
        raise DomainValidationError("Invalid domain format. Example: acme-bakery.com")

    tld = value.rsplit(".", 1)[-1]
    if len(tld) < 2 or tld.isdigit():
        raise DomainValidationError("Domain must end with a valid top-level domain.")

    return value


def is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def generate_verification_token() -> str:
    return f"sw-{secrets.token_hex(16)}"


def expected_txt_record(domain: str, token: str) -> tuple[str, str]:
    return f"_surfacewatch-verify.{domain}", f"surfacewatch-verify={token}"


def verify_dns_txt(
    domain: str, expected_token: str, timeout: float = 5.0
) -> tuple[bool, list[str]]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    expected_prefixed = f"surfacewatch-verify={expected_token}"
    observed: list[str] = []
    hosts_to_check = [f"_surfacewatch-verify.{domain}", domain]

    for host in hosts_to_check:
        try:
            answers = resolver.resolve(host, "TXT")
            for rdata in answers:
                txt_value = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in getattr(rdata, "strings", [str(rdata)])
                ).strip('"')
                observed.append(f"{host}: {txt_value}")
                if txt_value == expected_prefixed or txt_value == expected_token:
                    return True, observed
        except (dns.exception.DNSException, OSError):
            continue

    return False, observed
