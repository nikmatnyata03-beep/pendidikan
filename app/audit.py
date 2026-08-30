"""Audit event contract with sensitive field redaction."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


SENSITIVE_KEYS = frozenset({"authorization", "access_token", "refresh_token", "password", "secret", "cvv", "pin"})


def redact_metadata(value: dict[str, Any]) -> dict[str, Any]:
    return {key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else item for key, item in value.items()}


@dataclass(frozen=True, slots=True)
class AuditEvent:
    action: str
    resource_type: str
    resource_id: str | None
    decision: str
    request_id: str
    tenant_id: str | None = None
    actor_subject: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def safe_metadata(self) -> dict[str, Any]:
        return redact_metadata(self.metadata)


class AuditSink(Protocol):
    async def write(self, event: AuditEvent) -> None: ...
