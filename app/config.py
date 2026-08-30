"""Environment-backed runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    database_url: str
    oidc_issuer: str
    oidc_audience: str
    oidc_jwks_url: str
    oidc_algorithms: tuple[str, ...]
    oidc_clock_skew_seconds: int
    allowed_origins: tuple[str, ...]

    @classmethod
    def from_env(cls, *, require_runtime: bool = True) -> "Settings":
        if require_runtime:
            database_url = _required("NEXUS_DATABASE_URL")
            issuer = _required("NEXUS_OIDC_ISSUER").rstrip("/")
            audience = _required("NEXUS_OIDC_AUDIENCE")
            jwks_url = _required("NEXUS_OIDC_JWKS_URL")
        else:
            database_url = os.getenv("NEXUS_DATABASE_URL", "")
            issuer = os.getenv("NEXUS_OIDC_ISSUER", "").rstrip("/")
            audience = os.getenv("NEXUS_OIDC_AUDIENCE", "")
            jwks_url = os.getenv("NEXUS_OIDC_JWKS_URL", "")
        origins = tuple(value.strip() for value in os.getenv("NEXUS_ALLOWED_ORIGINS", "").split(",") if value.strip())
        return cls(
            environment=os.getenv("NEXUS_ENVIRONMENT", "development"),
            database_url=database_url,
            oidc_issuer=issuer,
            oidc_audience=audience,
            oidc_jwks_url=jwks_url,
            oidc_algorithms=tuple(value.strip() for value in os.getenv("NEXUS_OIDC_ALGORITHMS", "RS256").split(",") if value.strip()),
            oidc_clock_skew_seconds=int(os.getenv("NEXUS_OIDC_CLOCK_SKEW_SECONDS", "30")),
            allowed_origins=origins,
        )

    def validate_runtime(self) -> None:
        required = {
            "NEXUS_DATABASE_URL": self.database_url,
            "NEXUS_OIDC_ISSUER": self.oidc_issuer,
            "NEXUS_OIDC_AUDIENCE": self.oidc_audience,
            "NEXUS_OIDC_JWKS_URL": self.oidc_jwks_url,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"missing production configuration: {', '.join(missing)}")
        if self.environment == "production" and not self.allowed_origins:
            raise RuntimeError("NEXUS_ALLOWED_ORIGINS is required in production")
