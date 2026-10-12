from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    cors_origins: str = "http://localhost"
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None

    # Outgoing mail for the "click this link to confirm your email" flow. If smtp_host is left
    # blank, no email is sent - the confirmation link is just printed to the backend's logs
    # (docker compose logs backend), which is fine for trying this out before wiring up real SMTP.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_use_tls: bool = True
    app_base_url: str = "http://localhost"

    # Where field-staff site-visit photos land on disk once pushed via /sync/push. Needs its
    # own Docker volume mount (like backups/) so they survive a container rebuild.
    field_uploads_dir: str = "/app/uploads/field"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
