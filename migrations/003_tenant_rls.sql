-- Nexus Campus Step 3: database-level tenant isolation.
-- The API sets these LOCAL transaction settings after verifying the bearer
-- token and resolving the tenant. They are never accepted from the client.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE OR REPLACE FUNCTION nexus_current_tenant()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid;
$$;

CREATE OR REPLACE FUNCTION nexus_is_global_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(NULLIF(current_setting('app.global_admin', true), '')::boolean, false);
$$;

ALTER TABLE institutions ENABLE ROW LEVEL SECURITY;
ALTER TABLE faculties ENABLE ROW LEVEL SECURITY;
ALTER TABLE programs ENABLE ROW LEVEL SECURITY;
ALTER TABLE courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE course_sections ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_scope_closure ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

ALTER TABLE institutions FORCE ROW LEVEL SECURITY;
ALTER TABLE faculties FORCE ROW LEVEL SECURITY;
ALTER TABLE programs FORCE ROW LEVEL SECURITY;
ALTER TABLE courses FORCE ROW LEVEL SECURITY;
ALTER TABLE course_sections FORCE ROW LEVEL SECURITY;
ALTER TABLE authorization_scopes FORCE ROW LEVEL SECURITY;
ALTER TABLE authorization_scope_closure FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

CREATE POLICY institutions_tenant_isolation ON institutions
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY faculties_tenant_isolation ON faculties
  USING (EXISTS (
    SELECT 1 FROM institutions i
    WHERE i.id = faculties.institution_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM institutions i
    WHERE i.id = faculties.institution_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ));

CREATE POLICY programs_tenant_isolation ON programs
  USING (EXISTS (
    SELECT 1 FROM faculties f JOIN institutions i ON i.id = f.institution_id
    WHERE f.id = programs.faculty_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM faculties f JOIN institutions i ON i.id = f.institution_id
    WHERE f.id = programs.faculty_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ));

CREATE POLICY courses_tenant_isolation ON courses
  USING (EXISTS (
    SELECT 1 FROM programs p JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE p.id = courses.program_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM programs p JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE p.id = courses.program_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ));

CREATE POLICY sections_tenant_isolation ON course_sections
  USING (EXISTS (
    SELECT 1 FROM courses c JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = course_sections.course_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM courses c JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = course_sections.course_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ));

CREATE POLICY scopes_tenant_isolation ON authorization_scopes
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY closure_tenant_isolation ON authorization_scope_closure
  USING (EXISTS (
    SELECT 1 FROM authorization_scopes s
    WHERE s.id = authorization_scope_closure.ancestor_id
      AND (s.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM authorization_scopes s
    WHERE s.id = authorization_scope_closure.ancestor_id
      AND (s.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ));

CREATE POLICY audit_tenant_isolation ON audit_logs
  USING (tenant_id = nexus_current_tenant() OR (tenant_id IS NULL AND nexus_is_global_admin()))
  WITH CHECK (tenant_id = nexus_current_tenant() OR (tenant_id IS NULL AND nexus_is_global_admin()));
