-- Nexus Campus Step 1: tenant, academic hierarchy, scoped admin authority.
-- PostgreSQL 15+. Run in a migration transaction.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE nexus_scope_kind AS ENUM (
  'global', 'institution', 'faculty', 'program', 'course', 'section'
);

CREATE TYPE nexus_grant_effect AS ENUM ('allow', 'deny');

CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE institutions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  timezone TEXT NOT NULL DEFAULT 'Asia/Jakarta',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, code)
);

CREATE TABLE faculties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  institution_id UUID NOT NULL REFERENCES institutions(id),
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (institution_id, code)
);

CREATE TABLE programs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_id UUID NOT NULL REFERENCES faculties(id),
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  degree_level TEXT NOT NULL CHECK (degree_level IN ('D1', 'D2', 'D3', 'D4', 'S1', 'S2', 'S3', 'profesi')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (faculty_id, code)
);

CREATE TABLE courses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  program_id UUID NOT NULL REFERENCES programs(id),
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  credits SMALLINT NOT NULL CHECK (credits BETWEEN 1 AND 12),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (program_id, code)
);

CREATE TABLE course_sections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID NOT NULL REFERENCES courses(id),
  term_code TEXT NOT NULL,
  section_code TEXT NOT NULL,
  capacity INTEGER NOT NULL CHECK (capacity > 0),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('draft', 'open', 'closed', 'cancelled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (course_id, term_code, section_code)
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  external_subject TEXT NOT NULL,
  display_name TEXT NOT NULL,
  email CITEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('invited', 'active', 'locked', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_subject),
  UNIQUE (tenant_id, email)
);

CREATE TABLE roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_key TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  is_system BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  permission_key TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  domain TEXT NOT NULL
);

CREATE TABLE role_permissions (
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

-- Generic nodes make scope assignment strongly referential and avoid a
-- polymorphic foreign key. resource_id points to the domain row represented.
CREATE TABLE authorization_scopes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  kind nexus_scope_kind NOT NULL,
  resource_id UUID,
  parent_id UUID REFERENCES authorization_scopes(id),
  label TEXT NOT NULL,
  UNIQUE (kind, resource_id),
  CHECK ((kind = 'global' AND resource_id IS NULL) OR (kind <> 'global' AND resource_id IS NOT NULL))
);

-- Closure rows are maintained in the same transaction as hierarchy changes.
-- A row (ancestor, descendant, depth=0) is required for every scope itself.
CREATE TABLE authorization_scope_closure (
  ancestor_id UUID NOT NULL REFERENCES authorization_scopes(id) ON DELETE CASCADE,
  descendant_id UUID NOT NULL REFERENCES authorization_scopes(id) ON DELETE CASCADE,
  depth INTEGER NOT NULL CHECK (depth >= 0),
  PRIMARY KEY (ancestor_id, descendant_id)
);

CREATE TABLE user_role_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id),
  scope_id UUID REFERENCES authorization_scopes(id),
  effect nexus_grant_effect NOT NULL DEFAULT 'allow',
  starts_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ends_at TIMESTAMPTZ,
  granted_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (ends_at IS NULL OR ends_at > starts_at)
);

-- Prevent accidental cross-tenant grants. Global grants are the only rows
-- allowed to omit tenant_id and scope_id.
CREATE OR REPLACE FUNCTION validate_role_assignment_tenant()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  user_tenant UUID;
  scope_tenant UUID;
  role_key_value TEXT;
BEGIN
  SELECT tenant_id INTO user_tenant FROM users WHERE id = NEW.user_id;
  IF user_tenant IS NULL THEN
    RAISE EXCEPTION 'role assignment user does not exist: %', NEW.user_id;
  END IF;
  SELECT role_key INTO role_key_value FROM roles WHERE id = NEW.role_id;
  IF role_key_value IS NULL THEN
    RAISE EXCEPTION 'role assignment role does not exist: %', NEW.role_id;
  END IF;

  IF NEW.scope_id IS NULL THEN
    IF NEW.tenant_id IS NULL AND role_key_value <> 'super_admin' THEN
      RAISE EXCEPTION 'only super_admin may receive a global assignment';
    END IF;
    IF NEW.tenant_id IS NOT NULL AND NEW.tenant_id <> user_tenant THEN
      RAISE EXCEPTION 'assignment tenant does not match user tenant';
    END IF;
    RETURN NEW;
  END IF;

  SELECT tenant_id INTO scope_tenant FROM authorization_scopes WHERE id = NEW.scope_id;
  IF scope_tenant IS NULL OR NEW.tenant_id IS NULL THEN
    RAISE EXCEPTION 'scoped assignment requires an existing tenant scope';
  END IF;
  IF user_tenant <> scope_tenant OR NEW.tenant_id <> scope_tenant THEN
    RAISE EXCEPTION 'assignment crosses tenant boundary';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_role_assignment_tenant
BEFORE INSERT OR UPDATE ON user_role_assignments
FOR EACH ROW EXECUTE FUNCTION validate_role_assignment_tenant();

CREATE TABLE assignment_permissions (
  assignment_id UUID NOT NULL REFERENCES user_role_assignments(id) ON DELETE CASCADE,
  permission_key TEXT NOT NULL,
  PRIMARY KEY (assignment_id, permission_key)
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  actor_user_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id UUID,
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'denied', 'system')),
  request_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_institutions_tenant ON institutions(tenant_id);
CREATE INDEX idx_faculties_institution ON faculties(institution_id);
CREATE INDEX idx_programs_faculty ON programs(faculty_id);
CREATE INDEX idx_courses_program ON courses(program_id);
CREATE INDEX idx_sections_course_term ON course_sections(course_id, term_code);
CREATE INDEX idx_scope_closure_descendant ON authorization_scope_closure(descendant_id);
CREATE INDEX idx_assignments_user_active ON user_role_assignments(user_id, starts_at, ends_at);
CREATE INDEX idx_assignments_scope ON user_role_assignments(scope_id);
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, created_at DESC);

-- Seed system roles. Permission rows are intentionally seeded by the next
-- migration so deployments can choose a narrower permission catalog.
INSERT INTO roles (role_key, label, is_system) VALUES
  ('super_admin', 'Super administrator', true),
  ('institution_admin', 'Institution administrator', true),
  ('faculty_admin', 'Faculty administrator', true),
  ('program_admin', 'Program administrator', true),
  ('course_admin', 'Course administrator', true),
  ('section_admin', 'Section administrator', true),
  ('academic_admin', 'Academic administrator', true),
  ('finance_admin', 'Finance administrator', true),
  ('instructor', 'Instructor', true),
  ('student', 'Student', true)
ON CONFLICT (role_key) DO NOTHING;
