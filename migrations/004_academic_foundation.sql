-- Nexus Campus Step 4: academic master data and enrollment foundations.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE TABLE academic_terms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  starts_on DATE NOT NULL,
  ends_on DATE NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'open', 'closed', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (ends_on > starts_on),
  UNIQUE (tenant_id, code)
);

ALTER TABLE course_sections
  ADD COLUMN IF NOT EXISTS term_id UUID REFERENCES academic_terms(id);

CREATE TABLE student_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  program_id UUID NOT NULL REFERENCES programs(id),
  student_number TEXT NOT NULL,
  entry_year SMALLINT NOT NULL CHECK (entry_year BETWEEN 1900 AND 2200),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'leave', 'graduated', 'withdrawn')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id),
  UNIQUE (tenant_id, student_number)
);

CREATE TABLE course_prerequisites (
  course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  prerequisite_course_id UUID NOT NULL REFERENCES courses(id) ON DELETE RESTRICT,
  min_grade TEXT,
  PRIMARY KEY (course_id, prerequisite_course_id),
  CHECK (course_id <> prerequisite_course_id)
);

CREATE TABLE section_instructors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  section_id UUID NOT NULL REFERENCES course_sections(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  assignment_role TEXT NOT NULL DEFAULT 'instructor' CHECK (assignment_role IN ('instructor', 'assistant')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (section_id, user_id)
);

CREATE TABLE section_enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  section_id UUID NOT NULL REFERENCES course_sections(id) ON DELETE CASCADE,
  student_id UUID NOT NULL REFERENCES student_profiles(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'enrolled' CHECK (status IN ('waitlisted', 'enrolled', 'dropped', 'completed')),
  final_grade TEXT,
  enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (section_id, student_id)
);

CREATE OR REPLACE FUNCTION validate_academic_tenant_links()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  expected_tenant UUID;
  linked_tenant UUID;
BEGIN
  IF TG_TABLE_NAME = 'course_sections' AND NEW.term_id IS NOT NULL THEN
    SELECT i.tenant_id INTO expected_tenant
    FROM courses c
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = NEW.course_id;
    SELECT tenant_id INTO linked_tenant FROM academic_terms WHERE id = NEW.term_id;
    IF expected_tenant IS NULL OR linked_tenant IS NULL OR expected_tenant <> linked_tenant THEN
      RAISE EXCEPTION 'course section and academic term must belong to the same tenant';
    END IF;
  ELSIF TG_TABLE_NAME = 'student_profiles' THEN
    SELECT i.tenant_id INTO expected_tenant
    FROM programs p
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE p.id = NEW.program_id;
    SELECT tenant_id INTO linked_tenant FROM users WHERE id = NEW.user_id;
    IF expected_tenant IS NULL OR linked_tenant IS NULL OR NEW.tenant_id <> expected_tenant OR NEW.tenant_id <> linked_tenant THEN
      RAISE EXCEPTION 'student profile links must belong to the same tenant';
    END IF;
  ELSIF TG_TABLE_NAME = 'course_prerequisites' THEN
    SELECT i.tenant_id INTO expected_tenant
    FROM courses c
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = NEW.course_id;
    SELECT i.tenant_id INTO linked_tenant
    FROM courses c
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = NEW.prerequisite_course_id;
    IF expected_tenant IS NULL OR linked_tenant IS NULL OR expected_tenant <> linked_tenant THEN
      RAISE EXCEPTION 'course prerequisites must belong to the same tenant';
    END IF;
  ELSIF TG_TABLE_NAME = 'section_instructors' THEN
    SELECT i.tenant_id INTO expected_tenant
    FROM course_sections s
    JOIN courses c ON c.id = s.course_id
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE s.id = NEW.section_id;
    SELECT tenant_id INTO linked_tenant FROM users WHERE id = NEW.user_id;
    IF expected_tenant IS NULL OR linked_tenant IS NULL OR NEW.tenant_id <> expected_tenant OR NEW.tenant_id <> linked_tenant THEN
      RAISE EXCEPTION 'section instructor links must belong to the same tenant';
    END IF;
  ELSIF TG_TABLE_NAME = 'section_enrollments' THEN
    SELECT i.tenant_id INTO expected_tenant
    FROM course_sections s
    JOIN courses c ON c.id = s.course_id
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE s.id = NEW.section_id;
    SELECT tenant_id INTO linked_tenant FROM student_profiles WHERE id = NEW.student_id;
    IF expected_tenant IS NULL OR linked_tenant IS NULL OR NEW.tenant_id <> expected_tenant OR NEW.tenant_id <> linked_tenant THEN
      RAISE EXCEPTION 'section enrollment links must belong to the same tenant';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_section_term_tenant
BEFORE INSERT OR UPDATE ON course_sections
FOR EACH ROW EXECUTE FUNCTION validate_academic_tenant_links();

CREATE TRIGGER trg_validate_student_profile_tenant
BEFORE INSERT OR UPDATE ON student_profiles
FOR EACH ROW EXECUTE FUNCTION validate_academic_tenant_links();

CREATE TRIGGER trg_validate_course_prerequisite_tenant
BEFORE INSERT OR UPDATE ON course_prerequisites
FOR EACH ROW EXECUTE FUNCTION validate_academic_tenant_links();

CREATE TRIGGER trg_validate_section_instructor_tenant
BEFORE INSERT OR UPDATE ON section_instructors
FOR EACH ROW EXECUTE FUNCTION validate_academic_tenant_links();

CREATE TRIGGER trg_validate_section_enrollment_tenant
BEFORE INSERT OR UPDATE ON section_enrollments
FOR EACH ROW EXECUTE FUNCTION validate_academic_tenant_links();

CREATE INDEX idx_academic_terms_tenant_status ON academic_terms(tenant_id, status);
CREATE INDEX idx_sections_term ON course_sections(term_id);
CREATE INDEX idx_student_profiles_program ON student_profiles(program_id);
CREATE INDEX idx_section_instructors_section ON section_instructors(section_id);
CREATE INDEX idx_section_enrollments_student ON section_enrollments(student_id);

ALTER TABLE academic_terms ENABLE ROW LEVEL SECURITY;
ALTER TABLE student_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE course_prerequisites ENABLE ROW LEVEL SECURITY;
ALTER TABLE section_instructors ENABLE ROW LEVEL SECURITY;
ALTER TABLE section_enrollments ENABLE ROW LEVEL SECURITY;

ALTER TABLE academic_terms FORCE ROW LEVEL SECURITY;
ALTER TABLE student_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE course_prerequisites FORCE ROW LEVEL SECURITY;
ALTER TABLE section_instructors FORCE ROW LEVEL SECURITY;
ALTER TABLE section_enrollments FORCE ROW LEVEL SECURITY;

CREATE POLICY academic_terms_tenant_isolation ON academic_terms
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY student_profiles_tenant_isolation ON student_profiles
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY course_prerequisites_tenant_isolation ON course_prerequisites
  USING (EXISTS (
    SELECT 1 FROM courses c
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = course_prerequisites.course_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM courses c
    JOIN programs p ON p.id = c.program_id
    JOIN faculties f ON f.id = p.faculty_id
    JOIN institutions i ON i.id = f.institution_id
    WHERE c.id = course_prerequisites.course_id
      AND (i.tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  ));

CREATE POLICY section_instructors_tenant_isolation ON section_instructors
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY section_enrollments_tenant_isolation ON section_enrollments
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

INSERT INTO permissions (permission_key, label, domain) VALUES
  ('institution.read', 'Read institutions', 'institution'),
  ('institution.manage', 'Manage institutions', 'institution'),
  ('faculty.read', 'Read faculties', 'faculty'),
  ('faculty.manage', 'Manage faculties', 'faculty'),
  ('program.manage', 'Manage programs', 'program'),
  ('student.*', 'Manage student domain', 'student')
ON CONFLICT (permission_key) DO NOTHING;

WITH role_permission_map(role_key, permission_key) AS (
  VALUES
    ('academic_admin', 'institution.read'),
    ('academic_admin', 'faculty.read'),
    ('academic_admin', 'student.*')
)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role_permission_map map
JOIN roles r ON r.role_key = map.role_key
JOIN permissions p ON p.permission_key = map.permission_key
ON CONFLICT DO NOTHING;
