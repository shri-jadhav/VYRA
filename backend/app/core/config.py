import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "VYRA Cloud Security Engineering Platform"
    APP_VERSION: str = "1.0.0"
    TAGLINE: str = "Find the change. Prevent the regression. Verify the fix."
    DEBUG: bool = False

    # Server Configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite:///./vyra.db"

    # AWS Profile and Region
    # Default explicitly targets the verified read-only profile
    AWS_PROFILE: str = "vyra-readonly"
    AWS_DEFAULT_REGION: str = "ap-south-1"

    # Expected AWS Account Identity Guard
    # In LIVE mode, this account ID must be explicitly configured and match sts:GetCallerIdentity
    VYRA_EXPECTED_AWS_ACCOUNT_ID: str = ""

    # Safety Guardrails
    ALLOW_LIVE_COLLECTION: bool = True
    REMEDIATION_DRY_RUN_ONLY: bool = True

    # Storage Paths
    EVIDENCE_DIR: str = "./data/evidence"
    REPORTS_DIR: str = "./reports/exports"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

# Ensure directories exist
os.makedirs(settings.EVIDENCE_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
os.makedirs("./data", exist_ok=True)
