import ipaddress
import re
from datetime import datetime, timezone

from models.engagement import Engagement

_SCOPE_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:\*\.)?(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class ScopeError(ValueError):
    pass


class EngagementExpiredError(PermissionError):
    pass


def _parse_network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _is_domain(entry: str) -> bool:
    return bool(_SCOPE_DOMAIN_RE.match(entry))


def normalize_scope(entries: list[str]) -> list[str]:
    if not entries:
        raise ScopeError("Scope must contain at least one IP network or domain.")

    normalized: set[str] = set()
    for raw in entries:
        entry = raw.strip().lower().rstrip(".")
        if not entry:
            raise ScopeError(f"Invalid scope entry: {raw!r}")

        network = _parse_network(entry)
        if network is not None:
            normalized.add(str(network))
            continue

        if not _is_domain(entry):
            raise ScopeError(
                f"Invalid scope entry {raw!r}: expected an IP network or a domain "
                "(optionally prefixed with '*.')."
            )
        normalized.add(entry)

    if not normalized:
        raise ScopeError("Scope must contain at least one IP network or domain.")
    return sorted(normalized)


def is_in_scope(engagement: Engagement, target: str) -> bool:
    normalized_target = target.strip().lower().rstrip(".")
    if not normalized_target:
        return False

    try:
        target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(
            normalized_target
        )
    except ValueError:
        target_ip = None

    for entry in engagement.scope:
        network = _parse_network(entry)
        if network is not None:
            if target_ip is not None and target_ip in network:
                return True
            continue

        domain = entry[2:] if entry.startswith("*.") else entry
        if normalized_target == domain or normalized_target.endswith("." + domain):
            return True

    return False


def assert_scan_allowed(engagement: Engagement, target: str) -> None:
    today = datetime.now(timezone.utc).date()
    if (
        engagement.status != "active"
        or today < engagement.start_date
        or today > engagement.end_date
    ):
        raise EngagementExpiredError(
            f"Engagement {engagement.id} is not active for scanning "
            f"(status={engagement.status}, window={engagement.start_date}..{engagement.end_date})."
        )

    if not is_in_scope(engagement, target):
        raise ScopeError(
            f"Target {target!r} is outside the authorized scope of engagement {engagement.id}."
        )
