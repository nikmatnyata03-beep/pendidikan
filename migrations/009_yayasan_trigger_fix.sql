-- Nexus Campus Step 9: fix trigger branching for heterogeneous NEW records.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE OR REPLACE FUNCTION validate_yayasan_tenant_links()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = nexus, public
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

  IF TG_TABLE_NAME = 'registration_applications' THEN
    IF NEW.program_id IS NOT NULL THEN
      SELECT institution_id INTO program_institution FROM institution_programs WHERE id = NEW.program_id;
      IF program_institution IS NULL OR program_institution <> NEW.institution_id THEN
        RAISE EXCEPTION 'registration program must belong to the selected institution';
      END IF;
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
