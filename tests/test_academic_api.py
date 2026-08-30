from fastapi.testclient import TestClient

from app.authorization import Grant, ResourceContext
from app.identity import Identity
from app.main import create_app


TENANT = "11111111-1111-1111-1111-111111111111"
INSTITUTION = "22222222-2222-2222-2222-222222222222"
FACULTY = "33333333-3333-3333-3333-333333333333"
PROGRAM = "44444444-4444-4444-4444-444444444444"
COURSE = "55555555-5555-5555-5555-555555555555"


class FakeVerifier:
    async def verify(self, token):
        return Identity(subject="admin-1", issuer="https://sso.example", audience=("nexus",))


class FakeAcademicStore:
    def __init__(self):
        self.audit = []
        self.created = []

    async def fetch_allowed_tenants(self, subject):
        return (TENANT,), False

    async def fetch_user(self, subject, tenant_id, **kwargs):
        return {"id": "66666666-6666-6666-6666-666666666666", "external_subject": subject, "tenant_id": tenant_id, "status": "active"}

    async def fetch_grants(self, subject, tenant_id, **kwargs):
        return (Grant("grant-1", subject, "institution_admin", "institution", INSTITUTION, TENANT),)

    async def fetch_resource_context(self, resource_type, resource_id, tenant_id, **kwargs):
        if resource_type == "section":
            return ResourceContext(tenant_id=TENANT, institution_id=INSTITUTION, section_id=resource_id)
        if resource_type == "student":
            return ResourceContext(tenant_id=TENANT, institution_id=INSTITUTION, program_id=PROGRAM, student_id=resource_id)
        return ResourceContext(
            tenant_id=TENANT,
            institution_id=INSTITUTION,
            faculty_id=FACULTY,
            program_id=PROGRAM,
            course_id=COURSE,
        )

    async def create_academic_resource(self, resource_type, tenant_id, data, **kwargs):
        self.created.append((resource_type, data))
        return {"id": COURSE, "tenant_id": tenant_id, **data}

    async def list_academic(self, resource_type, tenant_id, **kwargs):
        return [{
            "id": FACULTY,
            "faculty_id": FACULTY,
            "institution_id": INSTITUTION,
            "tenant_id": tenant_id,
            "code": "FIK",
            "name": "Fakultas Ilmu Komputer",
        }]

    async def assign_section_instructor(self, section_id, user_id, tenant_id, **kwargs):
        return {"id": "77777777-7777-7777-7777-777777777777", "section_id": section_id, "user_id": user_id}

    async def list_section_instructors(self, section_id, tenant_id, **kwargs):
        return [{"section_id": section_id, "user_id": "88888888-8888-8888-8888-888888888888", "display_name": "Dosen"}]

    async def enroll_student(self, section_id, student_id, tenant_id, **kwargs):
        return {"id": "99999999-9999-9999-9999-999999999999", "section_id": section_id, "student_id": student_id, "status": "enrolled"}

    async def list_section_enrollments(self, section_id, tenant_id, **kwargs):
        return [{"section_id": section_id, "student_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "status": "enrolled"}]

    async def write_audit(self, event, **kwargs):
        self.audit.append(event)

    async def ready(self):
        return True


def test_academic_create_and_list_use_parent_scope_authorization():
    store = FakeAcademicStore()
    client = TestClient(create_app(store=store, verifier=FakeVerifier()))
    headers = {"Authorization": "Bearer demo", "X-Tenant-ID": TENANT}

    created = client.post(
        "/v1/academic/faculties",
        headers=headers,
        json={"institution_id": INSTITUTION, "code": "FIK", "name": "Fakultas Ilmu Komputer"},
    )
    assert created.status_code == 201
    assert store.created[0][0] == "faculty"

    listed = client.get("/v1/academic/faculty?limit=10", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["items"][0]["code"] == "FIK"
    assert any(event.action == "academic.faculty.create" for event in store.audit)


def test_academic_route_rejects_unknown_resource_and_invalid_payload():
    client = TestClient(create_app(store=FakeAcademicStore(), verifier=FakeVerifier()))
    headers = {"Authorization": "Bearer demo", "X-Tenant-ID": TENANT}

    assert client.get("/v1/academic/unknown", headers=headers).status_code == 404
    response = client.post(
        "/v1/academic/courses",
        headers=headers,
        json={"program_id": PROGRAM, "code": "IF-1", "name": "Pengantar", "credits": 99},
    )
    assert response.status_code == 422


def test_section_assignment_and_enrollment_use_section_scope():
    store = FakeAcademicStore()
    client = TestClient(create_app(store=store, verifier=FakeVerifier()))
    headers = {"Authorization": "Bearer demo", "X-Tenant-ID": TENANT}

    instructor = client.post(
        f"/v1/academic/sections/{COURSE}/instructors",
        headers=headers,
        json={"user_id": "88888888-8888-8888-8888-888888888888", "assignment_role": "instructor"},
    )
    assert instructor.status_code == 201

    enrollment = client.post(
        "/v1/academic/enrollments",
        headers=headers,
        json={"section_id": COURSE, "student_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
    )
    assert enrollment.status_code == 201
    assert enrollment.json()["status"] == "enrolled"

    roster = client.get(f"/v1/academic/sections/{COURSE}/enrollments", headers=headers)
    assert roster.status_code == 200
    assert roster.json()["items"][0]["status"] == "enrolled"
