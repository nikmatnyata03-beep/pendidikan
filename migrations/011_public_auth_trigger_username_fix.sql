-- Compatibility fix for the existing public application Auth trigger.
-- Supabase Auth inserts into auth.users; the existing public.users table also
-- requires username, so derive one deterministically when metadata is absent.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  base_username TEXT;
  candidate_username TEXT;
  display_name_value TEXT;
BEGIN
  base_username := lower(coalesce(
    new.raw_user_meta_data->>'username',
    split_part(new.email, '@', 1),
    'user'
  ));
  base_username := regexp_replace(base_username, '[^a-z0-9_]+', '_', 'g');
  base_username := trim(both '_' from base_username);
  IF base_username = '' THEN
    base_username := 'user';
  END IF;

  candidate_username := left(base_username, 40);
  IF EXISTS (SELECT 1 FROM public.profiles WHERE username = candidate_username)
     OR EXISTS (SELECT 1 FROM public.users WHERE username = candidate_username) THEN
    candidate_username := left(base_username, 31) || '_' || substr(replace(new.id::text, '-', ''), 1, 8);
  END IF;

  display_name_value := coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1), candidate_username);

  INSERT INTO public.profiles (id, username, display_name, avatar)
  VALUES (
    new.id,
    candidate_username,
    display_name_value,
    coalesce(new.raw_user_meta_data->>'avatar', 'https://api.dicebear.com/7.x/avataaars/svg?seed=' || new.id)
  )
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.users (id, username, nickname, display_name, auth_provider)
  VALUES (new.id, candidate_username, candidate_username, display_name_value, 'email')
  ON CONFLICT (id) DO UPDATE
    SET username = EXCLUDED.username,
        nickname = EXCLUDED.nickname,
        display_name = EXCLUDED.display_name;
  RETURN new;
END;
$function$;
