"""Explicit asyncpg repository used by the HTTP layer.

Queries are intentionally explicit and tenant-filtered. The service layer must
resolve a resource context before asking the authorization engine to decide.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from typing import Any

from .audit import AuditEvent
from .authorization import Grant, ResourceContext


class DatabaseUnavailable(RuntimeError):
    pass


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


def _uuid(value: str | uuid.UUID) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class PostgresStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.pool: Any = None

    async def connect(self) -> None:
        try:
            import asyncpg
        except ImportError as exc:
            raise DatabaseUnavailable("asyncpg is required for PostgreSQL runtime") from exc
        self.pool = await asyncpg.create_pool(
            self.database_url,
            min_size=2,
            max_size=10,
            command_timeout=10,
            max_inactive_connection_lifetime=300,
            statement_cache_size=0,
            server_settings={"search_path": "nexus,public"},
        )

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()
            self.pool = None

    def _pool(self) -> Any:
        if self.pool is None:
            raise DatabaseUnavailable("database pool is not connected")
        return self.pool

    @asynccontextmanager
    async def _tenant_connection(self, tenant_id: str, *, global_admin: bool = False):
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('app.tenant_id', $1, true), set_config('app.global_admin', $2, true)",
                    str(_uuid(tenant_id)),
                    "true" if global_admin else "false",
                )
                yield connection

    @asynccontextmanager
    async def _system_connection(self):
        """Use only for pre-auth request audit rows with no tenant context."""

        async with self._pool().acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('app.tenant_id', '', true), set_config('app.global_admin', 'true', true)"
                )
                yield connection

    async def ready(self) -> bool:
        async with self._pool().acquire() as connection:
            return (await connection.fetchval("SELECT 1")) == 1

    async def fetch_allowed_tenants(self, subject: str) -> tuple[tuple[str, ...], bool]:
        async with self._pool().acquire() as connection:
            tenant_rows = await connection.fetch(
                """
                SELECT DISTINCT tenant_id::text AS tenant_id
                FROM users
                WHERE external_subject = $1 AND status = 'active'
                UNION
                SELECT DISTINCT a.tenant_id::text
                FROM user_role_assignments a
                JOIN users u ON u.id = a.user_id
                WHERE u.external_subject = $1
                  AND a.tenant_id IS NOT NULL
                  AND a.starts_at <= now()
                  AND (a.ends_at IS NULL OR a.ends_at > now())
                ORDER BY tenant_id
                """,
                subject,
            )
            global_admin = await connection.fetchval(
                """
                SELECT EXISTS (
                  SELECT 1
                  FROM user_role_assignments a
                  JOIN users u ON u.id = a.user_id
                  JOIN roles r ON r.id = a.role_id
                  WHERE u.external_subject = $1
                    AND r.role_key = 'super_admin'
                    AND a.tenant_id IS NULL AND a.scope_id IS NULL
                    AND a.starts_at <= now()
                    AND (a.ends_at IS NULL OR a.ends_at > now())
                )
                """,
                subject,
            )
            return tuple(row["tenant_id"] for row in tenant_rows), bool(global_admin)

    async def fetch_user(self, subject: str, tenant_id: str, *, global_admin: bool = False) -> dict[str, Any]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            row = await connection.fetchrow(
                """
                SELECT id::text AS id, external_subject, display_name, email::text AS email,
                       status, tenant_id::text AS tenant_id
                FROM users
                WHERE external_subject = $1 AND status = 'active'
                  AND ($3 OR tenant_id = $2)
                ORDER BY CASE WHEN tenant_id = $2 THEN 0 ELSE 1 END, created_at
                LIMIT 1
                """,
                subject,
                _uuid(tenant_id),
                global_admin,
            )
        if row is None:
            raise NotFoundError("active user not found in tenant")
        return dict(row)

    async def fetch_grants(self, subject: str, tenant_id: str, *, global_admin: bool = False) -> tuple[Grant, ...]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            rows = await connection.fetch(
                """
                SELECT a.id::text AS grant_id, u.external_subject, r.role_key,
                       COALESCE(s.kind::text, 'global') AS scope_kind,
                       s.resource_id::text AS scope_id,
                       a.tenant_id::text AS tenant_id, a.effect::text AS effect,
                       a.starts_at, a.ends_at,
                       CASE WHEN a.use_role_defaults
                         THEN array_agg(DISTINCT role_perm.permission_key) FILTER (WHERE role_perm.permission_key IS NOT NULL)
                         ELSE COALESCE(array_agg(DISTINCT ap.permission_key) FILTER (WHERE ap.permission_key IS NOT NULL), ARRAY[]::text[])
                       END AS permissions
                FROM user_role_assignments a
                JOIN users u ON u.id = a.user_id
                JOIN roles r ON r.id = a.role_id
                LEFT JOIN authorization_scopes s ON s.id = a.scope_id
                LEFT JOIN assignment_permissions ap ON ap.assignment_id = a.id
                LEFT JOIN role_permissions rp ON rp.role_id = r.id
                LEFT JOIN permissions role_perm ON role_perm.id = rp.permission_id
                WHERE u.external_subject = $1
                  AND (a.tenant_id IS NULL OR a.tenant_id = $2)
                  AND a.starts_at <= now()
                  AND (a.ends_at IS NULL OR a.ends_at > now())
                GROUP BY a.id, u.external_subject, r.role_key, s.kind, s.resource_id,
                         a.tenant_id, a.effect, a.starts_at, a.ends_at, a.use_role_defaults
                """,
                subject,
                _uuid(tenant_id),
            )
        return tuple(
            Grant(
                grant_id=row["grant_id"],
                subject_id=row["external_subject"],
                role=row["role_key"],
                scope_kind=row["scope_kind"],
                scope_id=row["scope_id"],
                tenant_id=row["tenant_id"],
                permissions=frozenset(row["permissions"]) if row["permissions"] is not None else None,
                effect=row["effect"],
                starts_at=row["starts_at"],
                ends_at=row["ends_at"],
            )
            for row in rows
        )

    async def fetch_resource_context(self, resource_type: str, resource_id: str, tenant_id: str, *, global_admin: bool = False) -> ResourceContext:
        queries = {
            "institution": """
                SELECT i.id::text AS institution_id, i.tenant_id::text AS tenant_id
                FROM institutions i WHERE i.id = $1 AND i.tenant_id = $2
            """,
            "faculty": """
                SELECT f.id::text AS faculty_id, i.id::text AS institution_id, i.tenant_id::text AS tenant_id
                FROM faculties f JOIN institutions i ON i.id = f.institution_id
                WHERE f.id = $1 AND i.tenant_id = $2
            """,
            "program": """
                SELECT p.id::text AS program_id, f.id::text AS faculty_id,
                       i.id::text AS institution_id, i.tenant_id::text AS tenant_id
                FROM programs p JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE p.id = $1 AND i.tenant_id = $2
            """,
            "course": """
                SELECT c.id::text AS course_id, p.id::text AS program_id,
                       f.id::text AS faculty_id, i.id::text AS institution_id,
                       i.tenant_id::text AS tenant_id
                FROM courses c JOIN programs p ON p.id = c.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE c.id = $1 AND i.tenant_id = $2
            """,
             "section": """
                SELECT s.id::text AS section_id, c.id::text AS course_id,
                       p.id::text AS program_id, f.id::text AS faculty_id,
                       i.id::text AS institution_id, i.tenant_id::text AS tenant_id
                FROM course_sections s JOIN courses c ON c.id = s.course_id
                JOIN programs p ON p.id = c.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                 WHERE s.id = $1 AND i.tenant_id = $2
             """,
             "student": """
                 SELECT sp.id::text AS student_id, sp.id::text AS profile_id,
                        p.id::text AS program_id, f.id::text AS faculty_id,
                        i.id::text AS institution_id, i.tenant_id::text AS tenant_id
                 FROM student_profiles sp JOIN programs p ON p.id = sp.program_id
                 JOIN faculties f ON f.id = p.faculty_id
                 JOIN institutions i ON i.id = f.institution_id
                 WHERE sp.id = $1 AND i.tenant_id = $2
             """,
         }
        query = queries.get(resource_type)
        if query is None:
            raise ValueError("unsupported resource type")
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            row = await connection.fetchrow(query, _uuid(resource_id), _uuid(tenant_id))
        if row is None:
            raise NotFoundError("resource not found in tenant")
        return ResourceContext(**{key: value for key, value in dict(row).items() if value is not None})

    async def list_academic(
        self,
        resource_type: str,
        tenant_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        global_admin: bool = False,
    ) -> list[dict[str, Any]]:
        queries = {
            "institution": """
                SELECT i.id::text AS id, i.id::text AS institution_id,
                       i.tenant_id::text AS tenant_id, i.code, i.name, i.timezone
                FROM institutions i WHERE i.tenant_id = $1
                ORDER BY i.code LIMIT $2 OFFSET $3
            """,
            "faculty": """
                SELECT f.id::text AS id, f.id::text AS faculty_id,
                       i.id::text AS institution_id, i.tenant_id::text AS tenant_id,
                       f.code, f.name
                FROM faculties f JOIN institutions i ON i.id = f.institution_id
                WHERE i.tenant_id = $1
                ORDER BY f.code LIMIT $2 OFFSET $3
            """,
            "program": """
                SELECT p.id::text AS id, p.id::text AS program_id,
                       f.id::text AS faculty_id, i.id::text AS institution_id,
                       i.tenant_id::text AS tenant_id, p.code, p.name,
                       p.degree_level, p.status
                FROM programs p JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE i.tenant_id = $1
                ORDER BY p.code LIMIT $2 OFFSET $3
            """,
            "course": """
                SELECT c.id::text AS id, c.id::text AS course_id,
                       p.id::text AS program_id, f.id::text AS faculty_id,
                       i.id::text AS institution_id, i.tenant_id::text AS tenant_id,
                       c.code, c.name, c.credits, c.status
                FROM courses c JOIN programs p ON p.id = c.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE i.tenant_id = $1
                ORDER BY c.code LIMIT $2 OFFSET $3
            """,
            "section": """
                SELECT s.id::text AS id, s.id::text AS section_id,
                       c.id::text AS course_id, p.id::text AS program_id,
                       f.id::text AS faculty_id, i.id::text AS institution_id,
                       i.tenant_id::text AS tenant_id, s.term_id::text AS term_id,
                       s.term_code, s.section_code, s.capacity, s.status
                FROM course_sections s JOIN courses c ON c.id = s.course_id
                JOIN programs p ON p.id = c.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE i.tenant_id = $1
                ORDER BY s.term_code DESC, s.section_code LIMIT $2 OFFSET $3
            """,
            "student": """
                SELECT sp.id::text AS id, sp.id::text AS student_id,
                       sp.tenant_id::text AS tenant_id, sp.user_id::text AS user_id,
                       sp.student_number, sp.entry_year, sp.status,
                       p.id::text AS program_id, f.id::text AS faculty_id,
                       i.id::text AS institution_id
                FROM student_profiles sp JOIN programs p ON p.id = sp.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE sp.tenant_id = $1
                ORDER BY sp.student_number LIMIT $2 OFFSET $3
            """,
            "term": """
                SELECT t.id::text AS id, t.tenant_id::text AS tenant_id,
                       t.code, t.name, t.starts_on, t.ends_on, t.status
                FROM academic_terms t WHERE t.tenant_id = $1
                ORDER BY t.starts_on DESC, t.code LIMIT $2 OFFSET $3
            """,
        }
        query = queries.get(resource_type)
        if query is None:
            raise ValueError("unsupported academic resource type")
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            rows = await connection.fetch(query, _uuid(tenant_id), limit, offset)
        return [dict(row) for row in rows]

    async def create_academic_resource(
        self,
        resource_type: str,
        tenant_id: str,
        data: dict[str, Any],
        *,
        global_admin: bool = False,
    ) -> dict[str, Any]:
        queries = {
            "institution": (
                """
                INSERT INTO institutions (tenant_id, code, name, timezone)
                VALUES ($1, $2, $3, $4)
                RETURNING id::text AS id, id::text AS institution_id,
                          tenant_id::text AS tenant_id, code, name, timezone
                """,
                lambda: (_uuid(tenant_id), data["code"], data["name"], data["timezone"]),
            ),
            "faculty": (
                """
                INSERT INTO faculties (institution_id, code, name)
                SELECT i.id, $2, $3 FROM institutions i
                WHERE i.id = $1 AND i.tenant_id = $4
                RETURNING id::text AS id, id::text AS faculty_id, institution_id::text AS institution_id,
                          $4::text AS tenant_id, code, name
                """,
                lambda: (_uuid(data["institution_id"]), data["code"], data["name"], _uuid(tenant_id)),
            ),
            "program": (
                """
                INSERT INTO programs (faculty_id, code, name, degree_level, status)
                SELECT f.id, $2, $3, $4, $5 FROM faculties f
                JOIN institutions i ON i.id = f.institution_id
                WHERE f.id = $1 AND i.tenant_id = $6
                RETURNING id::text AS id, id::text AS program_id, faculty_id::text AS faculty_id,
                          $6::text AS tenant_id, code, name, degree_level, status
                """,
                lambda: (_uuid(data["faculty_id"]), data["code"], data["name"], data["degree_level"], data["status"], _uuid(tenant_id)),
            ),
            "course": (
                """
                INSERT INTO courses (program_id, code, name, credits, status)
                SELECT p.id, $2, $3, $4, $5 FROM programs p
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE p.id = $1 AND i.tenant_id = $6
                RETURNING id::text AS id, id::text AS course_id, program_id::text AS program_id,
                          $6::text AS tenant_id, code, name, credits, status
                """,
                lambda: (_uuid(data["program_id"]), data["code"], data["name"], data["credits"], data["status"], _uuid(tenant_id)),
            ),
            "section": (
                """
                INSERT INTO course_sections (course_id, term_id, term_code, section_code, capacity, status)
                SELECT c.id, t.id, t.code, $3, $4, $5
                FROM courses c
                JOIN programs p ON p.id = c.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                JOIN academic_terms t ON t.id = $2 AND t.tenant_id = $6
                WHERE c.id = $1 AND i.tenant_id = $6
                RETURNING id::text AS id, id::text AS section_id, course_id::text AS course_id,
                          term_id::text AS term_id, term_code, section_code, capacity, status
                """,
                lambda: (_uuid(data["course_id"]), _uuid(data["term_id"]), data["section_code"], data["capacity"], data["status"], _uuid(tenant_id)),
            ),
            "student": (
                """
                INSERT INTO student_profiles (tenant_id, user_id, program_id, student_number, entry_year, status)
                SELECT $4, u.id, p.id, $3, $5, $6
                FROM users u JOIN programs p ON p.id = $2
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE u.id = $1 AND u.tenant_id = $4 AND i.tenant_id = $4
                RETURNING id::text AS id, id::text AS student_id, tenant_id::text AS tenant_id,
                          user_id::text AS user_id, program_id::text AS program_id,
                          student_number, entry_year, status
                """,
                lambda: (_uuid(data["user_id"]), _uuid(data["program_id"]), data["student_number"], _uuid(tenant_id), data["entry_year"], data["status"]),
            ),
            "term": (
                """
                INSERT INTO academic_terms (tenant_id, code, name, starts_on, ends_on, status)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id::text AS id, tenant_id::text AS tenant_id,
                          code, name, starts_on, ends_on, status
                """,
                lambda: (_uuid(tenant_id), data["code"], data["name"], data["starts_on"], data["ends_on"], data["status"]),
            ),
        }
        entry = queries.get(resource_type)
        if entry is None:
            raise ValueError("unsupported academic resource type")
        query, params = entry
        try:
            async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
                row = await connection.fetchrow(query, *params())
        except Exception as exc:
            try:
                import asyncpg
            except ImportError:
                raise
            if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
                raise ConflictError("academic resource already exists") from exc
            raise
        if row is None:
            raise NotFoundError("parent resource not found in tenant")
        return dict(row)

    async def assign_section_instructor(
        self,
        section_id: str,
        user_id: str,
        tenant_id: str,
        *,
        assignment_role: str = "instructor",
        global_admin: bool = False,
    ) -> dict[str, Any]:
        query = """
            INSERT INTO section_instructors (tenant_id, section_id, user_id, assignment_role)
            SELECT $3, s.id, u.id, $4
            FROM course_sections s
            JOIN courses c ON c.id = s.course_id
            JOIN programs p ON p.id = c.program_id
            JOIN faculties f ON f.id = p.faculty_id
            JOIN institutions i ON i.id = f.institution_id
            JOIN users u ON u.id = $2 AND u.tenant_id = $3
            WHERE s.id = $1 AND i.tenant_id = $3
            RETURNING id::text AS id, tenant_id::text AS tenant_id,
                      section_id::text AS section_id, user_id::text AS user_id,
                      assignment_role, created_at
        """
        try:
            async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
                row = await connection.fetchrow(
                    query,
                    _uuid(section_id),
                    _uuid(user_id),
                    _uuid(tenant_id),
                    assignment_role,
                )
        except Exception as exc:
            try:
                import asyncpg
            except ImportError:
                raise
            if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
                raise ConflictError("user is already assigned to this section") from exc
            if isinstance(exc, asyncpg.exceptions.RaiseError) and exc.sqlstate == "P0001":
                raise ValueError(str(exc)) from exc
            raise
        if row is None:
            raise NotFoundError("section or user not found in tenant")
        return dict(row)

    async def list_section_instructors(
        self,
        section_id: str,
        tenant_id: str,
        *,
        global_admin: bool = False,
    ) -> list[dict[str, Any]]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            rows = await connection.fetch(
                """
                SELECT si.id::text AS id, si.tenant_id::text AS tenant_id,
                       si.section_id::text AS section_id, si.user_id::text AS user_id,
                       u.external_subject, u.display_name, u.email::text AS email,
                       si.assignment_role, si.created_at
                FROM section_instructors si
                JOIN users u ON u.id = si.user_id
                WHERE si.section_id = $1 AND si.tenant_id = $2
                ORDER BY u.display_name
                """,
                _uuid(section_id),
                _uuid(tenant_id),
            )
        return [dict(row) for row in rows]

    async def enroll_student(
        self,
        section_id: str,
        student_id: str,
        tenant_id: str,
        *,
        requested_status: str = "enrolled",
        global_admin: bool = False,
    ) -> dict[str, Any]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            section = await connection.fetchrow(
                """
                SELECT s.id, s.capacity, s.status, i.tenant_id
                FROM course_sections s
                JOIN courses c ON c.id = s.course_id
                JOIN programs p ON p.id = c.program_id
                JOIN faculties f ON f.id = p.faculty_id
                JOIN institutions i ON i.id = f.institution_id
                WHERE s.id = $1 AND i.tenant_id = $2
                FOR UPDATE OF s
                """,
                _uuid(section_id),
                _uuid(tenant_id),
            )
            if section is None:
                raise NotFoundError("section not found in tenant")
            if section["status"] != "open":
                raise ValueError("only open sections accept enrollment")

            student = await connection.fetchrow(
                """
                SELECT sp.id, sp.status
                FROM student_profiles sp
                WHERE sp.id = $1 AND sp.tenant_id = $2
                """,
                _uuid(student_id),
                _uuid(tenant_id),
            )
            if student is None:
                raise NotFoundError("student profile not found in tenant")
            if student["status"] != "active":
                raise ValueError("only active students can enroll")

            active_count = await connection.fetchval(
                """
                SELECT count(*) FROM section_enrollments
                WHERE section_id = $1 AND status IN ('waitlisted', 'enrolled')
                """,
                _uuid(section_id),
            )
            assigned_status = requested_status
            if requested_status == "enrolled" and active_count >= section["capacity"]:
                assigned_status = "waitlisted"

            try:
                row = await connection.fetchrow(
                    """
                    INSERT INTO section_enrollments (tenant_id, section_id, student_id, status)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id::text AS id, tenant_id::text AS tenant_id,
                              section_id::text AS section_id, student_id::text AS student_id,
                              status, enrolled_at
                    """,
                    _uuid(tenant_id),
                    _uuid(section_id),
                    _uuid(student_id),
                    assigned_status,
                )
            except Exception as exc:
                try:
                    import asyncpg
                except ImportError:
                    raise
                if isinstance(exc, asyncpg.exceptions.UniqueViolationError):
                    raise ConflictError("student is already enrolled in this section") from exc
                if isinstance(exc, asyncpg.exceptions.RaiseError) and exc.sqlstate == "P0001":
                    raise ValueError(str(exc)) from exc
                raise
        return dict(row)

    async def list_section_enrollments(
        self,
        section_id: str,
        tenant_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        global_admin: bool = False,
    ) -> list[dict[str, Any]]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            rows = await connection.fetch(
                """
                SELECT se.id::text AS id, se.tenant_id::text AS tenant_id,
                       se.section_id::text AS section_id, se.student_id::text AS student_id,
                       sp.student_number, u.display_name, u.email::text AS email,
                       se.status, se.final_grade, se.enrolled_at
                FROM section_enrollments se
                JOIN student_profiles sp ON sp.id = se.student_id
                JOIN users u ON u.id = sp.user_id
                WHERE se.section_id = $1 AND se.tenant_id = $2
                ORDER BY se.status, sp.student_number
                LIMIT $3 OFFSET $4
                """,
                _uuid(section_id),
                _uuid(tenant_id),
                limit,
                offset,
            )
        return [dict(row) for row in rows]

    async def fetch_tenant_by_slug(self, slug: str) -> dict[str, Any]:
        async with self._pool().acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT id::text AS id, slug, name, status
                FROM tenants
                WHERE slug = $1 AND status = 'active'
                """,
                slug,
            )
        if row is None:
            raise NotFoundError("tenant not found")
        return dict(row)

    async def fetch_public_foundation(self, tenant_id: str) -> dict[str, Any]:
        async with self._tenant_connection(tenant_id) as connection:
            row = await connection.fetchrow(
                """
                SELECT id::text AS id, tenant_id::text AS tenant_id, slug, name,
                       tagline, description, logo_url, phone, email::text AS email,
                       address, is_published
                FROM foundation_sites
                WHERE tenant_id = $1 AND is_published
                """,
                _uuid(tenant_id),
            )
        if row is None:
            raise NotFoundError("published foundation site not found")
        return dict(row)

    async def list_public_institutions(self, tenant_id: str) -> list[dict[str, Any]]:
        async with self._tenant_connection(tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT i.id::text AS id, i.tenant_id::text AS tenant_id,
                       i.code, i.name, i.timezone, s.slug, s.description,
                       s.logo_url, s.theme, s.is_published
                FROM institutions i
                JOIN institution_sites s ON s.institution_id = i.id
                WHERE i.tenant_id = $1 AND s.is_published
                ORDER BY i.code
                """,
                _uuid(tenant_id),
            )
        return [dict(row) for row in rows]

    async def fetch_public_institution(self, tenant_id: str, slug: str) -> dict[str, Any]:
        async with self._tenant_connection(tenant_id) as connection:
            row = await connection.fetchrow(
                """
                SELECT i.id::text AS id, i.tenant_id::text AS tenant_id,
                       i.code, i.name, i.timezone, s.slug, s.description,
                       s.logo_url, s.theme, s.is_published
                FROM institutions i
                JOIN institution_sites s ON s.institution_id = i.id
                WHERE i.tenant_id = $1 AND s.slug = $2 AND s.is_published
                """,
                _uuid(tenant_id),
                slug,
            )
        if row is None:
            raise NotFoundError("published institution site not found")
        return dict(row)

    async def list_public_posts(self, tenant_id: str, institution_slug: str, *, limit: int = 20) -> list[dict[str, Any]]:
        async with self._tenant_connection(tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT p.id::text AS id, p.institution_id::text AS institution_id,
                       p.post_type, p.slug, p.title, p.excerpt, p.body,
                       p.cover_url, p.published_at
                FROM institution_posts p
                JOIN institution_sites s ON s.institution_id = p.institution_id
                WHERE p.tenant_id = $1 AND s.slug = $2 AND p.status = 'published'
                ORDER BY p.published_at DESC NULLS LAST, p.created_at DESC
                LIMIT $3
                """,
                _uuid(tenant_id),
                institution_slug,
                limit,
            )
        return [dict(row) for row in rows]

    async def create_registration_application(self, tenant_id: str, data: dict[str, Any]) -> dict[str, Any]:
        query = """
            INSERT INTO registration_applications (
              tenant_id, institution_id, program_id, registration_type, academic_year,
              student_full_name, birth_place, birth_date, gender, address,
              father_name, father_phone, mother_name, mother_phone,
              guardian_name, guardian_phone, notes
            )
            SELECT $1, i.id, p.id, $4, $5, $6, $7, $8, $9, $10,
                   $11, $12, $13, $14, $15, $16, $17
            FROM institutions i
            LEFT JOIN institution_programs p ON p.id = $3 AND p.institution_id = i.id AND p.tenant_id = $1
            WHERE i.id = $2 AND i.tenant_id = $1
            RETURNING id::text AS id, application_no, tenant_id::text AS tenant_id,
                      institution_id::text AS institution_id, program_id::text AS program_id,
                      registration_type, academic_year, status, student_full_name,
                      submitted_at, created_at
        """
        values = (
            _uuid(tenant_id),
            _uuid(data["institution_id"]),
            _uuid(data["program_id"]) if data.get("program_id") else None,
            data["registration_type"],
            data["academic_year"],
            data["student_full_name"],
            data.get("birth_place"),
            data.get("birth_date"),
            data.get("gender"),
            data.get("address"),
            data.get("father_name"),
            data.get("father_phone"),
            data.get("mother_name"),
            data.get("mother_phone"),
            data.get("guardian_name"),
            data.get("guardian_phone"),
            data.get("notes"),
        )
        try:
            async with self._tenant_connection(tenant_id) as connection:
                row = await connection.fetchrow(query, *values)
        except Exception as exc:
            try:
                import asyncpg
            except ImportError:
                raise
            if isinstance(exc, asyncpg.exceptions.ForeignKeyViolationError):
                raise NotFoundError("institution or program not found in tenant") from exc
            raise
        if row is None:
            raise NotFoundError("institution not found in tenant")
        return dict(row)

    async def list_registration_applications(
        self,
        tenant_id: str,
        *,
        application_status: str | None = None,
        limit: int = 100,
        offset: int = 0,
        global_admin: bool = False,
    ) -> list[dict[str, Any]]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            rows = await connection.fetch(
                """
                SELECT r.id::text AS id, r.application_no,
                       r.institution_id::text AS institution_id, i.name AS institution_name,
                       r.program_id::text AS program_id, p.name AS program_name,
                       r.registration_type, r.academic_year, r.status,
                       r.student_full_name, r.submitted_at, r.created_at, r.updated_at
                FROM registration_applications r
                JOIN institutions i ON i.id = r.institution_id
                LEFT JOIN institution_programs p ON p.id = r.program_id
                WHERE r.tenant_id = $1 AND ($2::text IS NULL OR r.status = $2)
                ORDER BY r.created_at DESC
                LIMIT $3 OFFSET $4
                """,
                _uuid(tenant_id),
                application_status,
                limit,
                offset,
            )
        return [dict(row) for row in rows]

    async def update_registration_status(
        self,
        application_id: str,
        tenant_id: str,
        new_status: str,
        *,
        global_admin: bool = False,
    ) -> dict[str, Any]:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            row = await connection.fetchrow(
                """
                UPDATE registration_applications
                SET status = $3, updated_at = now()
                WHERE id = $1 AND tenant_id = $2
                RETURNING id::text AS id, application_no, status,
                          institution_id::text AS institution_id,
                          student_full_name, updated_at
                """,
                _uuid(application_id),
                _uuid(tenant_id),
                new_status,
            )
        if row is None:
            raise NotFoundError("registration application not found in tenant")
        return dict(row)

    async def fetch_registration_context(self, application_id: str, tenant_id: str) -> dict[str, Any]:
        async with self._tenant_connection(tenant_id) as connection:
            row = await connection.fetchrow(
                """
                SELECT id::text AS id, tenant_id::text AS tenant_id,
                       institution_id::text AS institution_id,
                       status, student_full_name
                FROM registration_applications
                WHERE id = $1 AND tenant_id = $2
                """,
                _uuid(application_id),
                _uuid(tenant_id),
            )
        if row is None:
            raise NotFoundError("registration application not found in tenant")
        return dict(row)

    async def fetch_scope_id(self, scope_kind: str, resource_id: str, tenant_id: str, *, global_admin: bool = False) -> str:
        async with self._tenant_connection(tenant_id, global_admin=global_admin) as connection:
            scope_id = await connection.fetchval(
                """
                SELECT id::text FROM authorization_scopes
                WHERE kind = $1::nexus_scope_kind AND resource_id = $2 AND tenant_id = $3
                """,
                scope_kind,
                _uuid(resource_id),
                _uuid(tenant_id),
            )
        if scope_id is None:
            raise NotFoundError("authorization scope is not registered")
        return scope_id

    async def create_role_assignment(
        self,
        *,
        user_id: str,
        role_key: str,
        scope_kind: str,
        scope_resource_id: str | None,
        tenant_id: str | None,
        effect: str,
        permissions: list[str] | None,
        granted_by: str,
        global_admin: bool = False,
    ) -> str:
        if scope_kind == "global":
            scope_id = None
        else:
            if not tenant_id or not scope_resource_id:
                raise ValueError("scoped assignment requires tenant and resource")
            scope_id = await self.fetch_scope_id(scope_kind, scope_resource_id, tenant_id, global_admin=global_admin)
        async with self._pool().acquire() as connection:
            async with connection.transaction():
                role_id = await connection.fetchval("SELECT id FROM roles WHERE role_key = $1", role_key)
                if role_id is None:
                    raise NotFoundError("role not found")
                assignment_id = await connection.fetchval(
                    """
                    INSERT INTO user_role_assignments
                      (tenant_id, user_id, role_id, scope_id, effect, granted_by, use_role_defaults)
                    VALUES ($1, $2, $3, $4, $5::nexus_grant_effect, $6, $7)
                    RETURNING id::text
                    """,
                    _uuid(tenant_id) if tenant_id else None,
                    _uuid(user_id),
                    role_id,
                    _uuid(scope_id) if scope_id else None,
                    effect,
                    _uuid(granted_by),
                    permissions is None,
                )
                if permissions is not None:
                    await connection.executemany(
                        "INSERT INTO assignment_permissions (assignment_id, permission_key) VALUES ($1, $2)",
                        [(assignment_id, permission) for permission in permissions],
                    )
        return assignment_id

    async def write_audit(self, event: AuditEvent, *, global_admin: bool = False) -> None:
        if event.tenant_id:
            connection_context = self._tenant_connection(event.tenant_id, global_admin=global_admin)
        else:
            connection_context = self._system_connection()
        async with connection_context as connection:
            actor_id = None
            if event.actor_subject:
                actor_id = await connection.fetchval(
                    """
                    SELECT id FROM users
                    WHERE external_subject = $1
                    ORDER BY CASE WHEN tenant_id = $2 THEN 0 ELSE 1 END, created_at
                    LIMIT 1
                    """,
                    event.actor_subject,
                    _uuid(event.tenant_id) if event.tenant_id else None,
                )
            await connection.execute(
                """
                INSERT INTO audit_logs
                  (tenant_id, actor_user_id, actor_subject, action, resource_type, resource_id, decision, request_id, metadata, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
                """,
                _uuid(event.tenant_id) if event.tenant_id else None,
                actor_id,
                event.actor_subject,
                event.action,
                event.resource_type,
                _uuid(event.resource_id) if event.resource_id else None,
                event.decision,
                event.request_id,
                json.dumps(event.safe_metadata(), separators=(",", ":")),
                event.created_at,
            )
