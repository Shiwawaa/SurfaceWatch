import httpx

from config import get_settings


def format_summary_text(
    *,
    domain_name: str,
    risk_score: int,
    risk_grade: str,
    total_findings: int,
    new_count: int,
    resolved_count: int,
) -> str:
    return (
        f"SurfaceWatch Weekly Summary for {domain_name}\n"
        f"- Risk Score: {risk_score}/100 ({risk_grade})\n"
        f"- Total Findings: {total_findings}\n"
        f"- New Issues: {new_count}\n"
        f"- Resolved Issues: {resolved_count}\n"
        "Review full details and remediation steps in your SurfaceWatch dashboard."
    )


def send_telegram_summary(message: str) -> tuple[bool, str]:
    settings = get_settings()
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        return False, "Telegram not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID unset)."

    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    try:
        with httpx.Client(timeout=settings.request_timeout_seconds) as client:
            resp = client.post(
                url,
                json={"chat_id": settings.telegram_chat_id, "text": message},
            )
            resp.raise_for_status()
        return True, "Telegram summary delivered."
    except httpx.HTTPError as exc:
        return False, f"Telegram delivery failed: {exc}"
