-- 0001_rls_and_grants.sql — Row-Level Security + least-privilege grants.
--
-- Tenant isolation is enforced at the DATABASE layer here, independent of
-- application correctness. The application connects as the restricted role
-- `capybara_app` (created by the migrator: NOSUPERUSER, NOBYPASSRLS) and sets
-- a per-transaction GUC `app.current_org` (and, at auth time, an identity GUC
-- `app.current_user_id`) via SET LOCAL. Because the role cannot bypass RLS, a
-- forgotten WHERE clause cannot leak across tenants.
--
-- Scope of this slice: RLS is demonstrated on `memberships`, the canonical
-- tenant-scoped authorization table. P0 extends the same pattern to all
-- tenant tables. `users`/`sessions` remain identity/auth tables accessed
-- before a tenant context exists and are governed at the application layer.

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
-- FORCE so the policy applies even to the table owner / migration role,
-- leaving superuser as the only intentional bypass (used for seeding/admin).
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;

-- current_setting(..., true) returns NULL when the GUC is unset; a NULL
-- comparison yields no rows => deny-by-default (fail closed).
DROP POLICY IF EXISTS memberships_tenant_isolation ON memberships;
CREATE POLICY memberships_tenant_isolation ON memberships
  USING (
    org_id = current_setting('app.current_org', true)::uuid
    OR user_id = current_setting('app.current_user_id', true)::uuid
  )
  WITH CHECK (
    org_id = current_setting('app.current_org', true)::uuid
  );

-- Least-privilege grants for the application role. CONNECT on the database is
-- granted by the migrator (needs the concrete DB name).
GRANT USAGE ON SCHEMA public TO capybara_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO capybara_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO capybara_app;
