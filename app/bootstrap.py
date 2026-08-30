"""Create the first tenant and OIDC-backed global administrator.

Run this only from a protected release job. No password or access token is
created here; the admin must already exist in the configured OIDC provider.
"""

from __future__ import annotations

import argparse
import asyncio


async def bootstrap(
    database_url: str,
    *,
    tenant_slug: str,
    tenant_name: str,
    institution_code: str,
    institution_name: str,
    admin_subject: str,
    admin_name: str,
    admin_email: str,
) -> None:
    try:
        import asyncpg
    except ImportError as exc:
        raise RuntimeError("asyncpg is required for bootstrap") from exc
    pool = await asyncpg.create_pool(
        database_url,
        min_size=1,
        max_size=2,
        command_timeout=30,
        statement_cache_size=0,
        server_settings={"search_path": "nexus,public"},
    )
    try:
        async with pool.acquire() as connection:
            async with connection.transaction():
                tenant_id = await connection.fetchval(
                    """
                    INSERT INTO tenants (slug, name) VALUES ($1, $2)
                    ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
                    RETURNING id
                    """,
                    tenant_slug,
                    tenant_name,
                )
                institution_id = await connection.fetchval(
                    """
                    INSERT INTO institutions (tenant_id, code, name) VALUES ($1, $2, $3)
                    ON CONFLICT (tenant_id, code) DO UPDATE SET name = EXCLUDED.name
                    RETURNING id
                    """,
                    tenant_id,
                    institution_code,
                    institution_name,
                )
                scope_id = await connection.fetchval(
                    """
                    INSERT INTO authorization_scopes (tenant_id, kind, resource_id, label)
                    VALUES ($1, 'institution', $2, $3)
                    ON CONFLICT (kind, resource_id) DO UPDATE SET label = EXCLUDED.label
                    RETURNING id
                    """,
                    tenant_id,
                    institution_id,
                    institution_name,
                )
                await connection.execute(
                    """
                    INSERT INTO authorization_scope_closure (ancestor_id, descendant_id, depth)
                    VALUES ($1, $1, 0) ON CONFLICT DO NOTHING
                    """,
                    scope_id,
                )
                user_id = await connection.fetchval(
                    """
                    INSERT INTO users (tenant_id, external_subject, display_name, email)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (tenant_id, external_subject) DO UPDATE
                      SET display_name = EXCLUDED.display_name, email = EXCLUDED.email, status = 'active', updated_at = now()
                    RETURNING id
                    """,
                    tenant_id,
                    admin_subject,
                    admin_name,
                    admin_email,
                )
                role_id = await connection.fetchval("SELECT id FROM roles WHERE role_key = 'super_admin'")
                if role_id is None:
                    raise RuntimeError("system roles are missing; run migrations first")
                await connection.execute(
                    """
                    INSERT INTO user_role_assignments (tenant_id, user_id, role_id, effect)
                    SELECT NULL, $1, $2, 'allow'
                    WHERE NOT EXISTS (
                      SELECT 1 FROM user_role_assignments
                      WHERE tenant_id IS NULL AND user_id = $1 AND role_id = $2
                        AND scope_id IS NULL AND effect = 'allow'
                    )
                    """,
                    user_id,
                    role_id,
                )
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--institution-code", required=True)
    parser.add_argument("--institution-name", required=True)
    parser.add_argument("--admin-subject", required=True)
    parser.add_argument("--admin-name", required=True)
    parser.add_argument("--admin-email", required=True)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(bootstrap(**vars(args))) or 0)


if __name__ == "__main__":
    main()
