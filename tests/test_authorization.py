from datetime import datetime, timedelta, timezone

from app.authorization import AuthorizationService, Grant, ResourceContext, permissions_within_role


NOW = datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc)
TENANT_A = ResourceContext(
    tenant_id="tenant-a",
    institution_id="inst-a",
    faculty_id="fac-a",
    program_id="prog-a",
    course_id="course-a",
    section_id="section-a",
)
TENANT_B = ResourceContext(
    tenant_id="tenant-b",
    institution_id="inst-b",
    faculty_id="fac-b",
    program_id="prog-b",
    course_id="course-b",
    section_id="section-b",
)


def grant(**overrides):
    values = {
        "grant_id": "g-1",
        "subject_id": "admin-1",
        "role": "program_admin",
        "scope_kind": "program",
        "scope_id": "prog-a",
        "tenant_id": "tenant-a",
    }
    values.update(overrides)
    return Grant(**values)


def test_program_admin_has_full_power_inside_program():
    auth = AuthorizationService([grant()], now=NOW)

    assert auth.can("admin-1", "finance.refund", TENANT_A)
    assert not auth.can("admin-1", "course.manage", TENANT_B)


def test_institution_admin_has_full_power_across_its_faculties():
    another_program = ResourceContext(
        tenant_id="tenant-a",
        institution_id="inst-a",
        faculty_id="fac-other",
        program_id="prog-other",
        course_id="course-other",
        section_id="section-other",
    )
    auth = AuthorizationService([
        grant(role="institution_admin", scope_kind="institution", scope_id="inst-a"),
    ], now=NOW)

    assert auth.can("admin-1", "course.manage", another_program)
    assert not auth.can("admin-1", "course.manage", TENANT_B)


def test_global_super_admin_can_cross_tenant():
    auth = AuthorizationService([
        grant(
            grant_id="g-global",
            role="super_admin",
            scope_kind="global",
            scope_id=None,
            tenant_id=None,
        ),
    ], now=NOW)

    assert auth.can("admin-1", "audit.read", TENANT_B)
    assert auth.can("admin-1", "finance.write", TENANT_A)


def test_course_scope_reaches_sections_of_that_course_only():
    sibling = ResourceContext(
        tenant_id="tenant-a",
        institution_id="inst-a",
        faculty_id="fac-a",
        program_id="prog-a",
        course_id="course-sibling",
        section_id="section-sibling",
    )
    auth = AuthorizationService([grant(role="course_admin", scope_kind="course", scope_id="course-a")], now=NOW)

    assert auth.can("admin-1", "section.manage", TENANT_A)
    assert not auth.can("admin-1", "section.manage", sibling)


def test_limited_finance_role_cannot_write_grades():
    auth = AuthorizationService([grant(role="finance_admin", scope_kind="institution", scope_id="inst-a")], now=NOW)

    assert auth.can("admin-1", "finance.invoice.write", TENANT_A)
    assert not auth.can("admin-1", "grade.write", TENANT_A)


def test_explicit_deny_wins_over_allow():
    auth = AuthorizationService([
        grant(grant_id="allow", role="institution_admin", scope_kind="institution", scope_id="inst-a"),
        grant(
            grant_id="deny-course",
            role="institution_admin",
            scope_kind="course",
            scope_id="course-a",
            effect="deny",
            permissions=frozenset({"finance.*"}),
        ),
    ], now=NOW)

    decision = auth.explain("admin-1", "finance.refund", TENANT_A)
    assert not decision.allowed
    assert decision.reason == "explicit_deny"
    assert decision.matched_grants == ("deny-course",)


def test_expired_grant_is_ignored():
    auth = AuthorizationService([
        grant(ends_at=NOW - timedelta(seconds=1)),
    ], now=NOW)

    assert not auth.can("admin-1", "course.manage", TENANT_A)


def test_domain_wildcard_matches_only_its_domain():
    auth = AuthorizationService([grant(permissions=frozenset({"attendance.*"}))], now=NOW)

    assert auth.can("admin-1", "attendance.adjust", TENANT_A)
    assert not auth.can("admin-1", "finance.read", TENANT_A)


def test_explicit_empty_permission_set_is_not_default_role_power():
    auth = AuthorizationService([grant(permissions=frozenset())], now=NOW)

    assert not auth.can("admin-1", "course.manage", TENANT_A)


def test_scoped_admin_cannot_delegate_above_its_own_rank():
    auth = AuthorizationService([grant(role="program_admin")], now=NOW)

    assert auth.can_delegate_role("admin-1", "course_admin", TENANT_A)
    assert not auth.can_delegate_role("admin-1", "institution_admin", TENANT_A)


def test_permission_override_cannot_expand_target_role():
    assert permissions_within_role("finance_admin", ["finance.invoice.write"])
    assert not permissions_within_role("finance_admin", ["grade.write"])
    assert not permissions_within_role("student", ["*"])
