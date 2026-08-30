-- Activate the linked Nexus profile when the Supabase Auth invitation is accepted.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE OR REPLACE FUNCTION nexus.sync_nexus_user_confirmation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = nexus, public
AS $$
BEGIN
  IF NEW.confirmed_at IS NOT NULL THEN
    UPDATE nexus.users
    SET status = 'active',
        email = COALESCE(NEW.email, email),
        updated_at = now()
    WHERE external_subject = NEW.id::text;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS nexus_sync_user_confirmation ON auth.users;
CREATE TRIGGER nexus_sync_user_confirmation
AFTER UPDATE OF confirmed_at ON auth.users
FOR EACH ROW EXECUTE FUNCTION nexus.sync_nexus_user_confirmation();
