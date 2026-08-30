-- Nexus Campus Step 6: baseline the application migration ledger.
-- Supabase applies tracked migrations outside app/migrate.py. This table keeps
-- the package runner idempotent if the same database is later managed by CI.

CREATE SCHEMA IF NOT EXISTS nexus;
SET search_path = nexus, public;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version, checksum) VALUES
  ('001_foundation.sql', '2b7fd72f8ad6b612e1f7f27528bae9b87aa300d6c11ad87148ddaa939059f35e'),
  ('002_permissions.sql', 'bc5f98d7ab1c58bbda6ec1e72acc1a252ff491dc9e5759c007366554a4ca38db'),
  ('003_tenant_rls.sql', 'aa3c46f93e21bd1f87ed4c324ddc7e8197c32db02032af15b85a8c37ae18f031'),
  ('004_academic_foundation.sql', '51de5bbd75e01089299f9ad9733bdba2d8e872efc51f90d8ce365523cbb4dd13'),
  ('005_enrollment_integrity.sql', 'c48ee0b33049385c5e563cd026b68df883e8235334bfc5c1cc3bc8696b06ba73')
ON CONFLICT (version) DO NOTHING;
