from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.authorization import Grant, ResourceContext
from app.config import Settings
from app.identity import Identity
from app.main import create_app


TENANT = "11111111-1111-1111-1111-111111111111"
INSTITUTION = "22222222-2222-2222-2222-222222222222"
PROGRAM = "33333333-3333-3333-3333-333333333333"
COURSE = "44444444-4444-4444-4444-444444444444"
USER = "55555555-5555-5555-5555-555555555555"


class FakeVerifier:
    async def verify(self, token):
        return Identity(subject="admin-1", issuer="https://sso.example", audience=("nexus",))


class FakeStore:
    def __init__(self):
        self.audit = []

    async def fetch_allowed_tenants(self, subject):
        return (TENANT,), False

    async def fetch_user(self, subject, tenant_id, **kwargs):
        return {"id": USER, "external_subject": subject, "tenant_id": tenant_id, "status": "active"}

    async def fetch_grants(self, subject, tenant_id, **kwargs):
        return (Grant("grant-1", subject, "institution_admin", "institution", INSTITUTION, TENANT),)

    async def fetch_resource_context(self, resource_type, resource_id, tenant_id, **kwargs):
        return ResourceContext(tenant_id, INSTITUTION, "66666666-6666-6666-6666-666666666666", PROGRAM, COURSE, None)

    async def create_role_assignment(self, **kwargs):
        return "77777777-7777-7777-7777-777777777777"

    async def write_audit(self, event, **kwargs):
        self.audit.append(event)

    async def ready(self):
        return True


def test_api_requires_identity_and_tenant_context():
    client = TestClient(create_app(store=FakeStore(), verifier=FakeVerifier()))

    assert client.get("/health/live").status_code == 200
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/me", headers={"Authorization": "Bearer demo"}).status_code == 200
    assert client.get("/v1/me", headers={"Authorization": "Bearer demo", "X-Tenant-ID": "not-a-uuid"}).status_code == 400
    assert client.get("/v1/me", headers={"Authorization": "Bearer demo", "X-Tenant-ID": "99999999-9999-9999-9999-999999999999"}).status_code == 403


def test_api_access_check_and_scoped_admin_grant():
    store = FakeStore()
    client = TestClient(create_app(store=store, verifier=FakeVerifier()))
    headers = {"Authorization": "Bearer demo", "X-Tenant-ID": TENANT}

    access = client.post(
        "/v1/access/check",
        headers=headers,
        json={"permission": "course.manage", "resource_type": "course", "resource_id": COURSE},
    )
    assert access.status_code == 200
    assert access.json()["allowed"] is True

    grant = client.post(
        "/v1/admin/grants",
        headers=headers,
        json={"user_id": USER, "role_key": "course_admin", "scope_kind": "course", "scope_resource_id": COURSE, "permissions": ["course.manage"]},
    )
    assert grant.status_code == 201
    assert UUID(grant.json()["assignment_id"])
    assert any(event.action == "admin.grant.create" and event.decision == "allowed" for event in store.audit)


def test_production_app_rejects_missing_runtime_configuration_on_startup():
    settings = Settings("production", "", "", "", "", ("RS256",), 30, ("https://campus.example",))
    app = create_app(settings=settings)

    with pytest.raises(RuntimeError, match="missing production configuration"):
        with TestClient(app):
            pass
