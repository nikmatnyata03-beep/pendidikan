-- Yayasan Darussolah Wal Jinan: public sites and santri admissions.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE TABLE foundation_sites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id),
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  tagline TEXT,
  description TEXT,
  logo_url TEXT,
  phone TEXT,
  email CITEXT,
  address TEXT,
  is_published BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE institution_sites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  institution_id UUID NOT NULL UNIQUE REFERENCES institutions(id) ON DELETE CASCADE,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  logo_url TEXT,
  theme JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_published BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, slug)
);

CREATE TABLE institution_programs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  min_age SMALLINT CHECK (min_age IS NULL OR min_age BETWEEN 0 AND 100),
  max_age SMALLINT CHECK (max_age IS NULL OR max_age BETWEEN 0 AND 100),
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (institution_id, code),
  CHECK (max_age IS NULL OR min_age IS NULL OR max_age >= min_age)
);

CREATE TABLE registration_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  application_no TEXT NOT NULL DEFAULT ('REG-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10))),
  institution_id UUID NOT NULL REFERENCES institutions(id),
  program_id UUID REFERENCES institution_programs(id),
  registration_type TEXT NOT NULL CHECK (registration_type IN ('new', 're_registration')),
  academic_year TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('draft', 'submitted', 'verified', 'accepted', 'rejected', 'enrolled')),
  student_full_name TEXT NOT NULL,
  birth_place TEXT,
  birth_date DATE,
  gender TEXT CHECK (gender IS NULL OR gender IN ('male', 'female')),
  address TEXT,
  father_name TEXT,
  father_phone TEXT,
  mother_name TEXT,
  mother_phone TEXT,
  guardian_name TEXT,
  guardian_phone TEXT,
  notes TEXT,
  created_by UUID REFERENCES users(id),
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, application_no)
);

CREATE TABLE registration_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  application_id UUID NOT NULL REFERENCES registration_applications(id) ON DELETE CASCADE,
  document_type TEXT NOT NULL CHECK (document_type IN ('family_card', 'guardian_id', 'child_id', 'nisn', 'photo', 'previous_certificate', 'other')),
  storage_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  review_note TEXT,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (application_id, document_type)
);

CREATE TABLE institution_posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
  author_user_id UUID REFERENCES users(id),
  post_type TEXT NOT NULL DEFAULT 'announcement' CHECK (post_type IN ('announcement', 'activity', 'news')),
  slug TEXT NOT NULL,
  title TEXT NOT NULL,
  excerpt TEXT,
  body TEXT NOT NULL,
  cover_url TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
  published_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (institution_id, slug)
);

CREATE OR REPLACE FUNCTION validate_yayasan_tenant_links()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  institution_tenant UUID;
  program_institution UUID;
  application_tenant UUID;
  author_tenant UUID;
BEGIN
  IF TG_TABLE_NAME IN ('institution_sites', 'institution_programs', 'registration_applications', 'institution_posts') THEN
    SELECT tenant_id INTO institution_tenant FROM institutions WHERE id = NEW.institution_id;
    IF institution_tenant IS NULL OR institution_tenant <> NEW.tenant_id THEN
      RAISE EXCEPTION 'institution content must belong to the same tenant';
    END IF;
  END IF;

  IF TG_TABLE_NAME = 'registration_applications' AND NEW.program_id IS NOT NULL THEN
    SELECT institution_id INTO program_institution FROM institution_programs WHERE id = NEW.program_id;
    IF program_institution IS NULL OR program_institution <> NEW.institution_id THEN
      RAISE EXCEPTION 'registration program must belong to the selected institution';
    END IF;
  ELSIF TG_TABLE_NAME = 'registration_documents' THEN
    SELECT tenant_id INTO application_tenant FROM registration_applications WHERE id = NEW.application_id;
    IF application_tenant IS NULL OR application_tenant <> NEW.tenant_id THEN
      RAISE EXCEPTION 'registration document must belong to the same tenant as its application';
    END IF;
  ELSIF TG_TABLE_NAME = 'institution_posts' AND NEW.author_user_id IS NOT NULL THEN
    SELECT tenant_id INTO author_tenant FROM users WHERE id = NEW.author_user_id;
    IF author_tenant IS NULL OR author_tenant <> NEW.tenant_id THEN
      RAISE EXCEPTION 'post author must belong to the same tenant';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_institution_site_tenant
BEFORE INSERT OR UPDATE ON institution_sites
FOR EACH ROW EXECUTE FUNCTION validate_yayasan_tenant_links();

CREATE TRIGGER trg_validate_institution_program_tenant
BEFORE INSERT OR UPDATE ON institution_programs
FOR EACH ROW EXECUTE FUNCTION validate_yayasan_tenant_links();

CREATE TRIGGER trg_validate_registration_application_tenant
BEFORE INSERT OR UPDATE ON registration_applications
FOR EACH ROW EXECUTE FUNCTION validate_yayasan_tenant_links();

CREATE TRIGGER trg_validate_registration_document_tenant
BEFORE INSERT OR UPDATE ON registration_documents
FOR EACH ROW EXECUTE FUNCTION validate_yayasan_tenant_links();

CREATE TRIGGER trg_validate_institution_post_tenant
BEFORE INSERT OR UPDATE ON institution_posts
FOR EACH ROW EXECUTE FUNCTION validate_yayasan_tenant_links();

CREATE INDEX idx_institution_programs_tenant ON institution_programs(tenant_id, institution_id);
CREATE INDEX idx_registrations_tenant_status ON registration_applications(tenant_id, status, created_at DESC);
CREATE INDEX idx_registration_documents_application ON registration_documents(application_id);
CREATE INDEX idx_institution_posts_published ON institution_posts(institution_id, status, published_at DESC);

ALTER TABLE foundation_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE institution_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE institution_programs ENABLE ROW LEVEL SECURITY;
ALTER TABLE registration_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE registration_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE institution_posts ENABLE ROW LEVEL SECURITY;

ALTER TABLE foundation_sites FORCE ROW LEVEL SECURITY;
ALTER TABLE institution_sites FORCE ROW LEVEL SECURITY;
ALTER TABLE institution_programs FORCE ROW LEVEL SECURITY;
ALTER TABLE registration_applications FORCE ROW LEVEL SECURITY;
ALTER TABLE registration_documents FORCE ROW LEVEL SECURITY;
ALTER TABLE institution_posts FORCE ROW LEVEL SECURITY;

CREATE POLICY foundation_sites_tenant_isolation ON foundation_sites
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY institution_sites_tenant_isolation ON institution_sites
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY institution_programs_tenant_isolation ON institution_programs
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY registration_applications_tenant_isolation ON registration_applications
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY registration_documents_tenant_isolation ON registration_documents
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

CREATE POLICY institution_posts_tenant_isolation ON institution_posts
  USING (tenant_id = nexus_current_tenant() OR nexus_is_global_admin())
  WITH CHECK (tenant_id = nexus_current_tenant() OR nexus_is_global_admin());

INSERT INTO roles (role_key, label, is_system) VALUES
  ('lembaga_admin', 'Lembaga administrator', true),
  ('operator_pendaftaran', 'Registration operator', true),
  ('guru', 'Teacher', true),
  ('santri', 'Santri', true),
  ('wali', 'Guardian', true)
ON CONFLICT (role_key) DO NOTHING;

INSERT INTO permissions (permission_key, label, domain) VALUES
  ('content.read', 'Read public institution content', 'content'),
  ('content.manage', 'Manage institution content', 'content'),
  ('admission.read', 'Read registration applications', 'admission'),
  ('admission.manage', 'Manage registration applications', 'admission')
ON CONFLICT (permission_key) DO NOTHING;

WITH role_permission_map(role_key, permission_key) AS (
  VALUES
    ('lembaga_admin', '*'),
    ('operator_pendaftaran', 'admission.read'),
    ('operator_pendaftaran', 'admission.manage'),
    ('operator_pendaftaran', 'student.read'),
    ('guru', 'course.read'),
    ('guru', 'section.read'),
    ('guru', 'attendance.manage'),
    ('guru', 'material.*'),
    ('guru', 'assessment.manage'),
    ('guru', 'grade.read'),
    ('guru', 'grade.write'),
    ('santri', 'profile.read'),
    ('santri', 'course.read'),
    ('santri', 'section.read'),
    ('santri', 'attendance.read'),
    ('santri', 'material.read'),
    ('santri', 'assignment.submit'),
    ('santri', 'grade.read'),
    ('santri', 'finance.read'),
    ('wali', 'student.read')
)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM role_permission_map map
JOIN roles r ON r.role_key = map.role_key
JOIN permissions p ON p.permission_key = map.permission_key
ON CONFLICT DO NOTHING;
