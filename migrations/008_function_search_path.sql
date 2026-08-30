-- Nexus Campus Step 8: make trigger functions safe for every connection role.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

ALTER FUNCTION nexus.validate_role_assignment_tenant()
  SET search_path = nexus, public;

ALTER FUNCTION nexus.nexus_current_tenant()
  SET search_path = nexus, public;

ALTER FUNCTION nexus.nexus_is_global_admin()
  SET search_path = nexus, public;

ALTER FUNCTION nexus.validate_academic_tenant_links()
  SET search_path = nexus, public;

ALTER FUNCTION nexus.validate_section_enrollment_state()
  SET search_path = nexus, public;

ALTER FUNCTION nexus.validate_section_instructor_state()
  SET search_path = nexus, public;

ALTER FUNCTION nexus.validate_yayasan_tenant_links()
  SET search_path = nexus, public;
