-- Nexus Campus Step 5: database guardrails for section enrollment.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE OR REPLACE FUNCTION validate_section_enrollment_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  section_capacity INTEGER;
  section_status TEXT;
  active_enrollment_count INTEGER;
BEGIN
  -- Serialize writes for one section so a concurrent request cannot exceed capacity.
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.section_id::text, 0));
  SELECT capacity, status INTO section_capacity, section_status
  FROM course_sections
  WHERE id = NEW.section_id
  FOR UPDATE;

  IF section_capacity IS NULL THEN
    RAISE EXCEPTION 'section does not exist';
  END IF;
  IF section_status <> 'open' THEN
    RAISE EXCEPTION 'only open sections accept enrollment';
  END IF;

  IF NEW.status = 'enrolled' THEN
    SELECT count(*) INTO active_enrollment_count
    FROM section_enrollments
    WHERE section_id = NEW.section_id
      AND status = 'enrolled'
      AND id <> COALESCE(NEW.id, gen_random_uuid());
    IF active_enrollment_count >= section_capacity THEN
      RAISE EXCEPTION 'section capacity has been reached';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_section_enrollment_state
BEFORE INSERT OR UPDATE ON section_enrollments
FOR EACH ROW EXECUTE FUNCTION validate_section_enrollment_state();

CREATE OR REPLACE FUNCTION validate_section_instructor_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  user_status TEXT;
BEGIN
  SELECT status INTO user_status FROM users WHERE id = NEW.user_id;
  IF user_status IS NULL OR user_status <> 'active' THEN
    RAISE EXCEPTION 'only active users can be assigned to a section';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_section_instructor_state
BEFORE INSERT OR UPDATE ON section_instructors
FOR EACH ROW EXECUTE FUNCTION validate_section_instructor_state();
