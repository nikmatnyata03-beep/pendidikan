import base64
import json

import pytest

from app.audit import redact_metadata
from app.config import Settings
from app.identity import Identity, IdentityError, parse_unverified_claims
from app.tenant import TenantAccessError, resolve_tenant


def _segment(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def test_unverified_jwt_parser_only_reads_header_and_payload():
    token = ".".join([_segment({"alg": "RS256", "kid": "key-1"}), _segment({"sub": "user-1"}), "signature"])

    header, claims = parse_unverified_claims(token)

    assert header["kid"] == "key-1"
    assert claims["sub"] == "user-1"


def test_malformed_token_is_rejected():
    with pytest.raises(IdentityError):
        parse_unverified_claims("not-a-jwt")


def test_multiple_tenants_require_explicit_context():
    identity = Identity(subject="user-1", issuer="https://sso.example", audience=("api",))

    with pytest.raises(TenantAccessError, match="X-Tenant-ID"):
        resolve_tenant(identity, None, ["tenant-a", "tenant-b"])

    context = resolve_tenant(identity, "tenant-b", ["tenant-a", "tenant-b"])
    assert context.tenant_id == "tenant-b"


def test_unknown_tenant_header_is_rejected_for_non_global_identity():
    identity = Identity(subject="user-1", issuer="https://sso.example", audience=("api",))

    with pytest.raises(TenantAccessError, match="not a member"):
        resolve_tenant(identity, "tenant-x", ["tenant-a"])


def test_global_identity_can_select_known_or_new_tenant():
    identity = Identity(subject="admin-1", issuer="https://sso.example", audience=("api",))

    context = resolve_tenant(identity, "tenant-x", ["tenant-a"], is_global_admin=True)
    assert context.tenant_id == "tenant-x"
    assert context.is_global_admin is True


def test_audit_metadata_redacts_secrets():
    safe = redact_metadata({"permission": "grade.write", "Authorization": "Bearer secret", "cvv": "123"})

    assert safe == {"permission": "grade.write", "Authorization": "[REDACTED]", "cvv": "[REDACTED]"}


def test_production_settings_fail_without_identity_and_database_config(monkeypatch):
    monkeypatch.setenv("NEXUS_ENVIRONMENT", "production")
    settings = Settings.from_env(require_runtime=False)

    with pytest.raises(RuntimeError, match="missing production configuration"):
        settings.validate_runtime()
