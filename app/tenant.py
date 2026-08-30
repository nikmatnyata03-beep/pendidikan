"""Tenant selection that never trusts a raw tenant header by itself."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .identity import Identity


class TenantAccessError(ValueError):
    """Raised when the requested tenant is ambiguous or not assigned."""


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: str
    subject_id: str
    is_global_admin: bool = False


def resolve_tenant(
    identity: Identity,
    requested_tenant_id: str | None,
    allowed_tenant_ids: Iterable[str],
    *,
    is_global_admin: bool = False,
) -> TenantContext:
    allowed = tuple(dict.fromkeys(value for value in allowed_tenant_ids if value))
    if requested_tenant_id:
        if not is_global_admin and requested_tenant_id not in allowed:
            raise TenantAccessError("subject is not a member of the requested tenant")
        return TenantContext(requested_tenant_id, identity.subject, is_global_admin)
    if len(allowed) == 1:
        return TenantContext(allowed[0], identity.subject, is_global_admin)
    if not allowed:
        raise TenantAccessError("subject has no active tenant membership")
    raise TenantAccessError("X-Tenant-ID is required when subject has multiple tenants")
