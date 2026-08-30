"""Scoped authorization for Nexus Campus.

The policy is deny-by-default. A grant can be global or scoped to an
institution, faculty, program, course, or section. A matching deny grant
always wins over an allow grant, which makes emergency revocation explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Literal

ScopeKind = Literal["global", "institution", "faculty", "program", "course", "section"]
Effect = Literal["allow", "deny"]

ROLE_DEFAULT_PERMISSIONS: dict[str, frozenset[str]] = {
    "super_admin": frozenset({"*"}),
    "institution_admin": frozenset({"*"}),
    "faculty_admin": frozenset({"*"}),
    "program_admin": frozenset({"*"}),
    "course_admin": frozenset({"*"}),
    "section_admin": frozenset({"*"}),
    "academic_admin": frozenset({
        "institution.read", "faculty.read", "student.*", "program.*", "course.*", "section.*", "attendance.*",
        "assessment.*", "schedule.*", "content.*", "admission.*", "report.read", "audit.read",
    }),
    "finance_admin": frozenset({"finance.*", "student.read", "report.finance"}),
    "instructor": frozenset({
        "course.read", "section.read", "attendance.manage", "material.*",
        "assessment.manage", "grade.read", "grade.write",
    }),
    "student": frozenset({
        "profile.read", "course.read", "section.read", "attendance.read",
        "material.read", "assignment.submit", "grade.read", "finance.read",
    }),
    "lembaga_admin": frozenset({"*"}),
    "operator_pendaftaran": frozenset({"admission.*", "student.read"}),
    "guru": frozenset({
        "course.read", "section.read", "attendance.manage", "material.*",
        "assessment.manage", "grade.read", "grade.write",
    }),
    "santri": frozenset({
        "profile.read", "course.read", "section.read", "attendance.read",
        "material.read", "assignment.submit", "grade.read", "finance.read",
    }),
    "wali": frozenset({"student.read"}),
}

ROLE_PRIORITY: dict[str, int] = {
    "student": 0,
    "instructor": 10,
    "section_admin": 20,
    "course_admin": 30,
    "program_admin": 40,
    "finance_admin": 45,
    "academic_admin": 45,
    "faculty_admin": 50,
    "institution_admin": 60,
    "super_admin": 100,
    "lembaga_admin": 60,
    "operator_pendaftaran": 15,
    "wali": 5,
}


@dataclass(frozen=True, slots=True)
class ResourceContext:
    """Resolved authorization ancestry for one protected resource."""

    tenant_id: str
    institution_id: str | None = None
    faculty_id: str | None = None
    program_id: str | None = None
    course_id: str | None = None
    section_id: str | None = None
    student_id: str | None = None

    def scope_id(self, kind: ScopeKind) -> str | None:
        return {
            "global": None,
            "institution": self.institution_id,
            "faculty": self.faculty_id,
            "program": self.program_id,
            "course": self.course_id,
            "section": self.section_id,
        }[kind]


@dataclass(frozen=True, slots=True)
class Grant:
    """A positive or negative permission assignment.

    `tenant_id=None` is reserved for a global grant. A global scope with a
    tenant id is still restricted to that tenant and is useful for an
    institution administrator that has every permission inside one tenant.
    """

    grant_id: str
    subject_id: str
    role: str
    scope_kind: ScopeKind
    scope_id: str | None
    tenant_id: str | None = None
    permissions: frozenset[str] | None = None
    effect: Effect = "allow"
    starts_at: datetime | None = None
    ends_at: datetime | None = None

    def active(self, now: datetime) -> bool:
        current = now.astimezone(timezone.utc)
        start = self.starts_at.astimezone(timezone.utc) if self.starts_at else None
        end = self.ends_at.astimezone(timezone.utc) if self.ends_at else None
        return (start is None or current >= start) and (end is None or current < end)


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    matched_grants: tuple[str, ...] = ()


def permission_matches(granted: str, requested: str) -> bool:
    """Match exact, global wildcard, or a domain wildcard such as `course.*`."""

    return granted == "*" or granted == requested or (
        granted.endswith(".*") and requested.startswith(granted[:-1])
    )


def permissions_within_role(role: str, requested: Iterable[str]) -> bool:
    """Keep assignment-specific permissions bounded by the target role."""

    allowed = ROLE_DEFAULT_PERMISSIONS.get(role, frozenset())
    return all(any(permission_matches(value, item) for value in allowed) for item in requested)


def scope_matches(grant: Grant, resource: ResourceContext) -> bool:
    """Return true when a grant scope is an ancestor of the resource scope."""

    if grant.tenant_id is not None and grant.tenant_id != resource.tenant_id:
        return False
    if grant.scope_kind == "global":
        return grant.scope_id is None
    return grant.scope_id is not None and grant.scope_id == resource.scope_id(grant.scope_kind)


class AuthorizationService:
    """Pure policy evaluator; persistence and identity verification stay outside."""

    def __init__(self, grants: Iterable[Grant], *, now: datetime | None = None) -> None:
        self._grants = tuple(grants)
        self._now = now or datetime.now(timezone.utc)

    def explain(self, subject_id: str, permission: str, resource: ResourceContext) -> Decision:
        matched: list[Grant] = []
        for grant in self._grants:
            if grant.subject_id != subject_id:
                continue
            if not grant.active(self._now):
                continue
            if not scope_matches(grant, resource):
                continue
            permissions = grant.permissions if grant.permissions is not None else ROLE_DEFAULT_PERMISSIONS.get(grant.role, frozenset())
            if any(permission_matches(value, permission) for value in permissions):
                matched.append(grant)

        deny_ids = tuple(grant.grant_id for grant in matched if grant.effect == "deny")
        if deny_ids:
            return Decision(False, "explicit_deny", deny_ids)
        allow_ids = tuple(grant.grant_id for grant in matched if grant.effect == "allow")
        if allow_ids:
            return Decision(True, "matched_allow", allow_ids)
        return Decision(False, "no_matching_grant")

    def can(self, subject_id: str, permission: str, resource: ResourceContext) -> bool:
        return self.explain(subject_id, permission, resource).allowed

    def can_delegate_role(self, subject_id: str, role: str, resource: ResourceContext) -> bool:
        """Prevent a scoped admin from granting authority above its own rank."""

        target_rank = ROLE_PRIORITY.get(role)
        if target_rank is None or not self.can(subject_id, "admin.grant.manage", resource):
            return False
        highest_rank = -1
        for grant in self._grants:
            if grant.subject_id != subject_id or grant.effect != "allow" or not grant.active(self._now):
                continue
            if not scope_matches(grant, resource):
                continue
            permissions = grant.permissions if grant.permissions is not None else ROLE_DEFAULT_PERMISSIONS.get(grant.role, frozenset())
            if any(permission_matches(value, "admin.grant.manage") for value in permissions):
                highest_rank = max(highest_rank, ROLE_PRIORITY.get(grant.role, -1))
        return highest_rank >= target_rank
