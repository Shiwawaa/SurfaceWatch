from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SurfaceWatch"
    app_env: str = "production"
    database_url: str = "sqlite:///./data/surfacewatch.db"

    user_agent: str = (
        "SurfaceWatch/1.0 (+https://github.com/surfacewatch/surfacewatch; "
        "defensive-authorized-scan)"
    )
    request_timeout_seconds: float = 8.0
    port_timeout_seconds: float = 2.0
    rate_limit_requests_per_second: float = 2.0
    max_subdomains: int = 50
    default_scan_interval_days: int = 7
    operator_id: str = "local-owner"
    allow_self_attestation: bool = True

    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_use_tls: bool = True


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.database_url.startswith("sqlite:///"):
        db_path = settings.database_url.removeprefix("sqlite:///")
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return settings
