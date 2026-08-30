from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_step4_migration_adds_academic_tables_and_rls():
    sql = (ROOT / "migrations" / "004_academic_foundation.sql").read_text()

    for table in ("academic_terms", "student_profiles", "course_prerequisites", "section_instructors", "section_enrollments"):
        assert f"CREATE TABLE {table}" in sql
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in sql

    assert "validate_academic_tenant_links" in sql
    assert "course section and academic term must belong to the same tenant" in sql
    assert "course prerequisites must belong to the same tenant" in sql


def test_migrations_are_applied_in_dependency_order():
    migration_names = sorted(path.name for path in (ROOT / "migrations").glob("*.sql"))

    assert migration_names == [
        "001_foundation.sql",
        "002_permissions.sql",
        "003_tenant_rls.sql",
        "004_academic_foundation.sql",
        "005_enrollment_integrity.sql",
        "006_migration_baseline.sql",
        "007_yayasan_sites_admissions.sql",
        "008_function_search_path.sql",
        "009_yayasan_trigger_fix.sql",
        "010_yayasan_trigger_branch_fix.sql",
        "011_public_auth_trigger_username_fix.sql",
        "012_auth_confirmation_sync.sql",
    ]


def test_step5_migration_serializes_capacity_and_active_staff_rules():
    sql = (ROOT / "migrations" / "005_enrollment_integrity.sql").read_text()

    assert "pg_advisory_xact_lock" in sql
    assert "only open sections accept enrollment" in sql
    assert "section capacity has been reached" in sql
    assert "only active users can be assigned to a section" in sql


def test_nexus_migrations_are_schema_isolated():
    for path in sorted((ROOT / "migrations").glob("*.sql")):
        sql = path.read_text()
        assert "SET search_path = nexus, public" in sql
