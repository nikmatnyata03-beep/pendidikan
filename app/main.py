"""Step 2 HTTP application: identity, tenant context, access checks, and grants."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import date
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .audit import AuditEvent
from .authorization import AuthorizationService, ResourceContext, permissions_within_role
from .config import Settings
from .db import ConflictError, DatabaseUnavailable, NotFoundError, PostgresStore
from .identity import Identity, IdentityError, OidcVerifier
from .tenant import TenantAccessError, TenantContext, resolve_tenant

ResourceType = Literal["institution", "faculty", "program", "course", "section", "student"]
ScopeType = Literal["global", "institution", "faculty", "program", "course", "section"]


class AccessCheckRequest(BaseModel):
    permission: str = Field(min_length=3, max_length=100, pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    resource_type: ResourceType
    resource_id: UUID


class GrantCreateRequest(BaseModel):
    user_id: UUID
    role_key: str = Field(min_length=2, max_length=60, pattern=r"^[a-z][a-z0-9_]*$")
    scope_kind: ScopeType
    scope_resource_id: UUID | None = None
    effect: Literal["allow", "deny"] = "allow"
    permissions: list[str] | None = Field(default=None, max_length=60)


class InstitutionCreateRequest(BaseModel):
    code: str = Field(min_length=2, max_length=30, pattern=r"^[A-Z0-9][A-Z0-9_-]*$")
    name: str = Field(min_length=2, max_length=200)
    timezone: str = Field(default="Asia/Jakarta", min_length=3, max_length=60)


class FacultyCreateRequest(BaseModel):
    institution_id: UUID
    code: str = Field(min_length=2, max_length=30, pattern=r"^[A-Z0-9][A-Z0-9_-]*$")
    name: str = Field(min_length=2, max_length=200)


class ProgramCreateRequest(BaseModel):
    faculty_id: UUID
    code: str = Field(min_length=2, max_length=30, pattern=r"^[A-Z0-9][A-Z0-9_-]*$")
    name: str = Field(min_length=2, max_length=200)
    degree_level: Literal["D1", "D2", "D3", "D4", "S1", "S2", "S3", "profesi"]
    status: Literal["draft", "active", "archived"] = "draft"


class CourseCreateRequest(BaseModel):
    program_id: UUID
    code: str = Field(min_length=2, max_length=30, pattern=r"^[A-Z0-9][A-Z0-9_-]*$")
    name: str = Field(min_length=2, max_length=200)
    credits: int = Field(ge=1, le=12)
    status: Literal["draft", "active", "archived"] = "draft"


class SectionCreateRequest(BaseModel):
    course_id: UUID
    term_id: UUID
    section_code: str = Field(min_length=1, max_length=30, pattern=r"^[A-Za-z0-9_-]+$")
    capacity: int = Field(gt=0, le=10000)
    status: Literal["draft", "open", "closed", "cancelled"] = "draft"


class TermCreateRequest(BaseModel):
    code: str = Field(min_length=2, max_length=30, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    name: str = Field(min_length=2, max_length=200)
    starts_on: date
    ends_on: date
    status: Literal["draft", "open", "closed", "archived"] = "draft"


class StudentCreateRequest(BaseModel):
    user_id: UUID
    program_id: UUID
    student_number: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9./_-]+$")
    entry_year: int = Field(ge=1900, le=2200)
    status: Literal["active", "leave", "graduated", "withdrawn"] = "active"


class InstructorAssignmentCreateRequest(BaseModel):
    user_id: UUID
    assignment_role: Literal["instructor", "assistant"] = "instructor"


class EnrollmentCreateRequest(BaseModel):
    section_id: UUID
    student_id: UUID
    requested_status: Literal["enrolled", "waitlisted"] = "enrolled"


class RegistrationCreateRequest(BaseModel):
    institution_id: UUID
    program_id: UUID | None = None
    registration_type: Literal["new", "re_registration"] = "new"
    academic_year: str = Field(min_length=4, max_length=20, pattern=r"^[0-9]{4}([/-][0-9]{4})?$")
    student_full_name: str = Field(min_length=2, max_length=200)
    birth_place: str | None = Field(default=None, max_length=100)
    birth_date: date | None = None
    gender: Literal["male", "female"] | None = None
    address: str | None = Field(default=None, max_length=500)
    father_name: str | None = Field(default=None, max_length=200)
    father_phone: str | None = Field(default=None, max_length=30)
    mother_name: str | None = Field(default=None, max_length=200)
    mother_phone: str | None = Field(default=None, max_length=30)
    guardian_name: str | None = Field(default=None, max_length=200)
    guardian_phone: str | None = Field(default=None, max_length=30)
    notes: str | None = Field(default=None, max_length=1000)


class RegistrationStatusUpdateRequest(BaseModel):
    status: Literal["verified", "accepted", "rejected", "enrolled"]


def _store(request: Request) -> PostgresStore:
    store = request.app.state.store
    if store is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database is not configured")
    return store


async def _identity(request: Request, authorization: Annotated[str | None, Header()] = None) -> Identity:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required", headers={"WWW-Authenticate": "Bearer"})
    verifier = request.app.state.verifier
    if verifier is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "identity provider is not configured")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required", headers={"WWW-Authenticate": "Bearer"})
    try:
        identity = await verifier.verify(token)
    except IdentityError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid bearer token", headers={"WWW-Authenticate": "Bearer"}) from exc
    request.state.identity = identity
    return identity


async def _tenant_context(
    request: Request,
    identity: Identity = Depends(_identity),
    x_tenant_id: Annotated[str | None, Header()] = None,
    store: PostgresStore = Depends(_store),
) -> TenantContext:
    if x_tenant_id:
        try:
            UUID(x_tenant_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid tenant id") from exc
    try:
        allowed, global_admin = await store.fetch_allowed_tenants(identity.subject)
        context = resolve_tenant(identity, x_tenant_id, allowed, is_global_admin=global_admin)
    except TenantAccessError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    request.state.tenant = context
    return context


async def _audit(request: Request, *, action: str, resource_type: str, resource_id: str | None, decision: str, metadata: dict) -> None:
    store = request.app.state.store
    if store is None:
        return
    identity = getattr(request.state, "identity", None)
    tenant = getattr(request.state, "tenant", None)
    try:
        await store.write_audit(
            AuditEvent(
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                decision=decision,
                request_id=request.state.request_id,
                tenant_id=tenant.tenant_id if tenant else None,
                actor_subject=identity.subject if identity else None,
                metadata=metadata,
            ),
            global_admin=tenant.is_global_admin if tenant else False,
        )
    except Exception:
        request.app.state.logger.exception("audit write failed")
        if request.app.state.settings.environment == "production":
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "audit service unavailable")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    if app.state.settings.environment == "production":
        app.state.settings.validate_runtime()
    created_store = False
    store = app.state.store
    if store is None and app.state.settings.database_url:
        store = PostgresStore(app.state.settings.database_url)
        await store.connect()
        app.state.store = store
        created_store = True
    yield
    if created_store and store is not None:
        await store.close()


def create_app(*, settings: Settings | None = None, store: PostgresStore | None = None, verifier: OidcVerifier | None = None) -> FastAPI:
    settings = settings or Settings.from_env(require_runtime=False)
    app = FastAPI(title="Nexus Campus API", version="0.2.0", lifespan=_lifespan)
    app.state.settings = settings
    app.state.store = store
    if verifier is None and settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url:
        verifier = OidcVerifier(settings)
    app.state.verifier = verifier
    import logging
    app.state.logger = logging.getLogger("nexus.api")
    origins = list(settings.allowed_origins) or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=bool(settings.allowed_origins),
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Tenant-ID"],
    )

    @app.middleware("http")
    async def request_audit_middleware(request: Request, call_next):
        request.state.request_id = request.headers.get("X-Request-ID") or str(uuid4())
        try:
            response = await call_next(request)
        except Exception:
            await _audit(request, action="http.request", resource_type="http", resource_id=None, decision="denied", metadata={"method": request.method, "path": request.url.path, "status": 500})
            raise
        response.headers["X-Request-ID"] = request.state.request_id
        if response.status_code in (401, 403):
            await _audit(request, action="http.request", resource_type="http", resource_id=None, decision="denied", metadata={"method": request.method, "path": request.url.path, "status": response.status_code})
        return response

    @app.get("/health/live", tags=["health"])
    async def live():
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    async def ready(request: Request):
        store = _store(request)
        try:
            await store.ready()
        except DatabaseUnavailable as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
        return {"status": "ready"}

    @app.get("/v1/me", tags=["identity"])
    async def me(identity: Identity = Depends(_identity), tenant: TenantContext = Depends(_tenant_context), store: PostgresStore = Depends(_store)):
        try:
            user = await store.fetch_user(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "active user profile not found") from exc
        return {"user": user, "tenant_id": tenant.tenant_id, "subject": identity.subject}

    @app.post("/v1/access/check", tags=["authorization"])
    async def access_check(
        payload: AccessCheckRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        try:
            resource = await store.fetch_resource_context(payload.resource_type, str(payload.resource_id), tenant.tenant_id, global_admin=tenant.is_global_admin)
            grants = await store.fetch_grants(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found") from exc
        decision = AuthorizationService(grants).explain(identity.subject, payload.permission, resource)
        await _audit(request, action="authorization.check", resource_type=payload.resource_type, resource_id=str(payload.resource_id), decision="allowed" if decision.allowed else "denied", metadata={"permission": payload.permission, "reason": decision.reason})
        return {"allowed": decision.allowed, "permission": payload.permission, "resource_type": payload.resource_type, "resource_id": str(payload.resource_id)}

    @app.post("/v1/admin/grants", status_code=status.HTTP_201_CREATED, tags=["administration"])
    async def create_grant(
        payload: GrantCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        if payload.scope_kind == "global":
            if payload.scope_resource_id is not None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "global grants cannot include scope_resource_id")
            resource = ResourceContext(tenant_id=tenant.tenant_id)
        else:
            if payload.scope_resource_id is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "scope_resource_id is required for scoped grants")
            try:
                resource = await store.fetch_resource_context(payload.scope_kind, str(payload.scope_resource_id), tenant.tenant_id, global_admin=tenant.is_global_admin)
            except (NotFoundError, ValueError) as exc:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "grant scope resource not found") from exc
        grants = await store.fetch_grants(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        auth = AuthorizationService(grants)
        if not auth.can_delegate_role(identity.subject, payload.role_key, resource):
            await _audit(request, action="admin.grant.create", resource_type=payload.scope_kind, resource_id=str(payload.scope_resource_id) if payload.scope_resource_id else None, decision="denied", metadata={"role_key": payload.role_key})
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient authority to delegate this role")
        if payload.permissions is not None:
            within_role = permissions_within_role(payload.role_key, payload.permissions)
            actor_can_grant = all(auth.can(identity.subject, permission, resource) for permission in payload.permissions)
            if not within_role or not actor_can_grant:
                await _audit(request, action="admin.grant.create", resource_type=payload.scope_kind, resource_id=str(payload.scope_resource_id) if payload.scope_resource_id else None, decision="denied", metadata={"role_key": payload.role_key, "reason": "permission_escalation"})
                raise HTTPException(status.HTTP_403_FORBIDDEN, "permission override exceeds role or actor authority")
        actor = await store.fetch_user(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        try:
            assignment_id = await store.create_role_assignment(
                user_id=str(payload.user_id), role_key=payload.role_key,
                scope_kind=payload.scope_kind, scope_resource_id=str(payload.scope_resource_id) if payload.scope_resource_id else None,
                tenant_id=None if payload.scope_kind == "global" else tenant.tenant_id,
                effect=payload.effect, permissions=payload.permissions, granted_by=actor["id"],
                global_admin=tenant.is_global_admin,
            )
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        await _audit(request, action="admin.grant.create", resource_type=payload.scope_kind, resource_id=str(payload.scope_resource_id) if payload.scope_resource_id else None, decision="allowed", metadata={"role_key": payload.role_key, "assignment_id": assignment_id})
        return {"assignment_id": assignment_id, "role_key": payload.role_key, "scope_kind": payload.scope_kind, "scope_resource_id": payload.scope_resource_id}

    async def _public_tenant(request: Request, store: PostgresStore, tenant_slug: str) -> dict:
        try:
            tenant = await store.fetch_tenant_by_slug(tenant_slug)
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "public site not found") from exc
        request.state.tenant = TenantContext(tenant["id"], "public")
        return tenant

    @app.get("/v1/public/{tenant_slug}/foundation", tags=["public"])
    async def public_foundation(tenant_slug: str, request: Request, store: PostgresStore = Depends(_store)):
        tenant = await _public_tenant(request, store, tenant_slug)
        try:
            site = await store.fetch_public_foundation(tenant["id"])
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "published foundation site not found") from exc
        return site

    @app.get("/v1/public/{tenant_slug}/institutions", tags=["public"])
    async def public_institutions(tenant_slug: str, request: Request, store: PostgresStore = Depends(_store)):
        tenant = await _public_tenant(request, store, tenant_slug)
        return {"items": await store.list_public_institutions(tenant["id"])}

    @app.get("/v1/public/{tenant_slug}/institutions/{institution_slug}", tags=["public"])
    async def public_institution(tenant_slug: str, institution_slug: str, request: Request, store: PostgresStore = Depends(_store)):
        tenant = await _public_tenant(request, store, tenant_slug)
        try:
            site = await store.fetch_public_institution(tenant["id"], institution_slug)
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "published institution site not found") from exc
        return site

    @app.get("/v1/public/{tenant_slug}/institutions/{institution_slug}/posts", tags=["public"])
    async def public_institution_posts(
        tenant_slug: str,
        institution_slug: str,
        request: Request,
        limit: int = Query(default=20, ge=1, le=100),
        store: PostgresStore = Depends(_store),
    ):
        tenant = await _public_tenant(request, store, tenant_slug)
        return {"items": await store.list_public_posts(tenant["id"], institution_slug, limit=limit)}

    @app.post("/v1/public/{tenant_slug}/registrations", status_code=status.HTTP_201_CREATED, tags=["public"])
    async def public_registration(
        tenant_slug: str,
        payload: RegistrationCreateRequest,
        request: Request,
        store: PostgresStore = Depends(_store),
    ):
        tenant = await _public_tenant(request, store, tenant_slug)
        try:
            result = await store.create_registration_application(tenant["id"], payload.model_dump())
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "institution or program not found") from exc
        await _audit(
            request,
            action="admission.application.submit",
            resource_type="institution",
            resource_id=str(payload.institution_id),
            decision="allowed",
            metadata={"application_no": result["application_no"], "registration_type": payload.registration_type},
        )
        return {"application_no": result["application_no"], "id": result["id"], "status": result["status"]}

    academic_parent_types = {
        "institution": None,
        "faculty": ("institution", "institution_id"),
        "program": ("faculty", "faculty_id"),
        "course": ("program", "program_id"),
        "section": ("course", "course_id"),
        "student": ("program", "program_id"),
        "term": None,
    }
    academic_permissions = {
        "institution": ("institution.read", "institution.manage"),
        "faculty": ("faculty.read", "faculty.manage"),
        "program": ("program.read", "program.manage"),
        "course": ("course.read", "course.manage"),
        "section": ("section.read", "section.manage"),
        "student": ("student.read", "student.manage"),
        "term": ("schedule.read", "schedule.manage"),
    }

    def _academic_context(row: dict, tenant: TenantContext) -> ResourceContext:
        return ResourceContext(
            tenant_id=tenant.tenant_id,
            institution_id=row.get("institution_id"),
            faculty_id=row.get("faculty_id"),
            program_id=row.get("program_id"),
            course_id=row.get("course_id"),
            section_id=row.get("section_id"),
            student_id=row.get("student_id"),
        )

    async def _academic_parent_context(
        resource_type: str,
        payload: BaseModel,
        tenant: TenantContext,
        store: PostgresStore,
    ) -> ResourceContext:
        parent = academic_parent_types.get(resource_type)
        if parent is None:
            return ResourceContext(tenant_id=tenant.tenant_id)
        parent_type, field_name = parent
        parent_id = getattr(payload, field_name)
        try:
            return await store.fetch_resource_context(
                parent_type,
                str(parent_id),
                tenant.tenant_id,
                global_admin=tenant.is_global_admin,
            )
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "parent resource not found in tenant") from exc

    async def _require_academic_permission(
        request: Request,
        identity: Identity,
        tenant: TenantContext,
        store: PostgresStore,
        resource_type: str,
        permission: str,
        resource: ResourceContext,
    ) -> None:
        grants = await store.fetch_grants(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        decision = AuthorizationService(grants).explain(identity.subject, permission, resource)
        if not decision.allowed:
            resource_ids = {
                "institution": resource.institution_id,
                "faculty": resource.faculty_id,
                "program": resource.program_id,
                "course": resource.course_id,
                "section": resource.section_id,
                "student": resource.student_id,
            }
            await _audit(
                request,
                action=f"academic.{resource_type}.{permission.rsplit('.', 1)[-1]}",
                resource_type=resource_type,
                resource_id=resource_ids.get(resource_type),
                decision="denied",
                metadata={"permission": permission, "reason": decision.reason},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient permission for academic resource")

    async def _create_academic(
        resource_type: str,
        payload: BaseModel,
        request: Request,
        identity: Identity,
        tenant: TenantContext,
        store: PostgresStore,
    ):
        _, manage_permission = academic_permissions[resource_type]
        parent = await _academic_parent_context(resource_type, payload, tenant, store)
        await _require_academic_permission(request, identity, tenant, store, resource_type, manage_permission, parent)
        try:
            result = await store.create_academic_resource(
                resource_type,
                tenant.tenant_id,
                payload.model_dump(),
                global_admin=tenant.is_global_admin,
            )
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "parent resource not found in tenant") from exc
        except ConflictError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        await _audit(
            request,
            action=f"academic.{resource_type}.create",
            resource_type=resource_type,
            resource_id=result.get("id"),
            decision="allowed",
            metadata={"permission": manage_permission},
        )
        return result

    @app.get("/v1/admin/registrations", tags=["admissions"])
    async def list_registrations(
        request: Request,
        application_status: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        allowed_statuses = {"draft", "submitted", "verified", "accepted", "rejected", "enrolled"}
        if application_status is not None and application_status not in allowed_statuses:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid registration status")
        rows = await store.list_registration_applications(
            tenant.tenant_id,
            application_status=application_status,
            limit=limit,
            offset=offset,
            global_admin=tenant.is_global_admin,
        )
        grants = await store.fetch_grants(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        auth = AuthorizationService(grants)
        visible = [
            row
            for row in rows
            if auth.can(
                identity.subject,
                "admission.read",
                ResourceContext(tenant_id=tenant.tenant_id, institution_id=row["institution_id"]),
            )
        ]
        await _audit(
            request,
            action="admission.application.list",
            resource_type="institution",
            resource_id=None,
            decision="allowed",
            metadata={"returned": len(visible), "requested": len(rows)},
        )
        return {"items": visible, "limit": limit, "offset": offset}

    @app.patch("/v1/admin/registrations/{application_id}/status", tags=["admissions"])
    async def update_registration_status(
        application_id: UUID,
        payload: RegistrationStatusUpdateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        try:
            application = await store.fetch_registration_context(str(application_id), tenant.tenant_id)
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "registration application not found") from exc
        context = ResourceContext(tenant_id=tenant.tenant_id, institution_id=application["institution_id"])
        await _require_academic_permission(request, identity, tenant, store, "institution", "admission.manage", context)
        try:
            result = await store.update_registration_status(
                str(application_id),
                tenant.tenant_id,
                payload.status,
                global_admin=tenant.is_global_admin,
            )
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "registration application not found") from exc
        await _audit(
            request,
            action="admission.application.status.update",
            resource_type="institution",
            resource_id=application["institution_id"],
            decision="allowed",
            metadata={"application_id": str(application_id), "status": payload.status},
        )
        return result

    @app.post("/v1/academic/institutions", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_institution(
        payload: InstitutionCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        return await _create_academic("institution", payload, request, identity, tenant, store)

    @app.post("/v1/academic/faculties", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_faculty(
        payload: FacultyCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        return await _create_academic("faculty", payload, request, identity, tenant, store)

    @app.post("/v1/academic/programs", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_program(
        payload: ProgramCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        return await _create_academic("program", payload, request, identity, tenant, store)

    @app.post("/v1/academic/courses", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_course(
        payload: CourseCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        return await _create_academic("course", payload, request, identity, tenant, store)

    @app.post("/v1/academic/sections", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_section(
        payload: SectionCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        return await _create_academic("section", payload, request, identity, tenant, store)

    @app.post("/v1/academic/terms", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_term(
        payload: TermCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        if payload.ends_on <= payload.starts_on:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "ends_on must be after starts_on")
        return await _create_academic("term", payload, request, identity, tenant, store)

    @app.post("/v1/academic/students", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def create_student(
        payload: StudentCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        return await _create_academic("student", payload, request, identity, tenant, store)

    @app.post("/v1/academic/sections/{section_id}/instructors", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def assign_instructor(
        section_id: UUID,
        payload: InstructorAssignmentCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        try:
            section = await store.fetch_resource_context(
                "section", str(section_id), tenant.tenant_id, global_admin=tenant.is_global_admin
            )
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "section not found in tenant") from exc
        await _require_academic_permission(request, identity, tenant, store, "section", "section.manage", section)
        try:
            result = await store.assign_section_instructor(
                str(section_id),
                str(payload.user_id),
                tenant.tenant_id,
                assignment_role=payload.assignment_role,
                global_admin=tenant.is_global_admin,
            )
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "section or user not found in tenant") from exc
        except ConflictError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        await _audit(
            request,
            action="academic.section.instructor.assign",
            resource_type="section",
            resource_id=str(section_id),
            decision="allowed",
            metadata={"user_id": str(payload.user_id), "assignment_role": payload.assignment_role},
        )
        return result

    @app.get("/v1/academic/sections/{section_id}/instructors", tags=["academic"])
    async def list_instructors(
        section_id: UUID,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        try:
            section = await store.fetch_resource_context(
                "section", str(section_id), tenant.tenant_id, global_admin=tenant.is_global_admin
            )
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "section not found in tenant") from exc
        await _require_academic_permission(request, identity, tenant, store, "section", "section.read", section)
        items = await store.list_section_instructors(
            str(section_id), tenant.tenant_id, global_admin=tenant.is_global_admin
        )
        return {"items": items}

    @app.post("/v1/academic/enrollments", status_code=status.HTTP_201_CREATED, tags=["academic"])
    async def enroll_student(
        payload: EnrollmentCreateRequest,
        request: Request,
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        try:
            section = await store.fetch_resource_context(
                "section", str(payload.section_id), tenant.tenant_id, global_admin=tenant.is_global_admin
            )
            student = await store.fetch_resource_context(
                "student", str(payload.student_id), tenant.tenant_id, global_admin=tenant.is_global_admin
            )
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "section or student not found in tenant") from exc
        await _require_academic_permission(request, identity, tenant, store, "section", "section.manage", section)
        await _require_academic_permission(request, identity, tenant, store, "student", "student.manage", student)
        try:
            result = await store.enroll_student(
                str(payload.section_id),
                str(payload.student_id),
                tenant.tenant_id,
                requested_status=payload.requested_status,
                global_admin=tenant.is_global_admin,
            )
        except NotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        except ConflictError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        await _audit(
            request,
            action="academic.enrollment.create",
            resource_type="section",
            resource_id=str(payload.section_id),
            decision="allowed",
            metadata={"student_id": str(payload.student_id), "status": result["status"]},
        )
        return result

    @app.get("/v1/academic/sections/{section_id}/enrollments", tags=["academic"])
    async def list_enrollments(
        section_id: UUID,
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        try:
            section = await store.fetch_resource_context(
                "section", str(section_id), tenant.tenant_id, global_admin=tenant.is_global_admin
            )
        except (NotFoundError, ValueError) as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "section not found in tenant") from exc
        await _require_academic_permission(request, identity, tenant, store, "section", "section.read", section)
        items = await store.list_section_enrollments(
            str(section_id), tenant.tenant_id, limit=limit, offset=offset, global_admin=tenant.is_global_admin
        )
        return {"items": items, "limit": limit, "offset": offset}

    @app.get("/v1/academic/{resource_type}", tags=["academic"])
    async def list_academic(
        resource_type: str,
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        identity: Identity = Depends(_identity),
        tenant: TenantContext = Depends(_tenant_context),
        store: PostgresStore = Depends(_store),
    ):
        if resource_type not in academic_permissions:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unsupported academic resource type")
        read_permission, _ = academic_permissions[resource_type]
        rows = await store.list_academic(
            resource_type,
            tenant.tenant_id,
            limit=limit,
            offset=offset,
            global_admin=tenant.is_global_admin,
        )
        grants = await store.fetch_grants(identity.subject, tenant.tenant_id, global_admin=tenant.is_global_admin)
        auth = AuthorizationService(grants)
        visible = [
            row
            for row in rows
            if auth.can(identity.subject, read_permission, _academic_context(row, tenant))
        ]
        await _audit(
            request,
            action=f"academic.{resource_type}.list",
            resource_type=resource_type,
            resource_id=None,
            decision="allowed",
            metadata={"permission": read_permission, "returned": len(visible), "requested": len(rows)},
        )
        return {"items": visible, "limit": limit, "offset": offset}

    return app


app = create_app()
