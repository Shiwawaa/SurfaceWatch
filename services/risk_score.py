from collections.abc import Iterable

from scanners.base import Severity

SEVERITY_WEIGHTS: dict[str, int] = {
    Severity.CRITICAL.value: 25,
    Severity.HIGH.value: 15,
    Severity.MEDIUM.value: 7,
    Severity.LOW.value: 2,
    Severity.INFO.value: 0,
}


def calculate_risk_score(severities: Iterable[str]) -> int:
    total = 0
    for sev in severities:
        key = sev.lower() if isinstance(sev, str) else str(sev).lower()
        total += SEVERITY_WEIGHTS.get(key, 0)
    return min(100, total)


def risk_grade_label(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 45:
        return "Elevated"
    if score >= 15:
        return "Moderate"
    return "Low"


def count_by_severity(severities: Iterable[str]) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for sev in severities:
        key = sev.lower()
        if key in counts:
            counts[key] += 1
    return counts
