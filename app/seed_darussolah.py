"""Seed the Darussolah Wal Jinan foundation structure without creating users."""

from __future__ import annotations

import argparse
import asyncio


INSTITUTIONS = (
    ("TPQ", "TPQ Darul Jinan", "tpq-darul-jinan", "Taman Pendidikan Al-Qur'an"),
    ("MDT", "MDT Darussolah", "mdt-darussolah", "Madrasah Diniyah Takmiliyah"),
    ("RA", "RA Darussolah", "ra-darussolah", "Raudhatul Athfal"),
    ("RTQ", "RTQ Darussolah", "rtq-darussolah", "Rumah Tahfidz Qur'an"),
)


async def seed(database_url: str) -> None:
    try:
        import asyncpg
    except ImportError as exc:
        raise RuntimeError("asyncpg is required for seeding") from exc

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
                    INSERT INTO tenants (slug, name)
                    VALUES ('yayasan-darussolah-wal-jinan', 'Yayasan Darussolah Wal Jinan')
                    ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
                    RETURNING id
                    """
                )
                await connection.execute(
                    """
                    INSERT INTO foundation_sites (tenant_id, slug, name, is_published)
                    VALUES ($1, 'yayasan-darussolah-wal-jinan', 'Yayasan Darussolah Wal Jinan', false)
                    ON CONFLICT (tenant_id) DO UPDATE
                      SET name = EXCLUDED.name, is_published = false, updated_at = now()
                    """,
                    tenant_id,
                )
                for code, name, site_slug, program_name in INSTITUTIONS:
                    institution_id = await connection.fetchval(
                        """
                        INSERT INTO institutions (tenant_id, code, name)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (tenant_id, code) DO UPDATE SET name = EXCLUDED.name
                        RETURNING id
                        """,
                        tenant_id,
                        code,
                        name,
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
                        name,
                    )
                    await connection.execute(
                        """
                        INSERT INTO authorization_scope_closure (ancestor_id, descendant_id, depth)
                        VALUES ($1, $1, 0) ON CONFLICT DO NOTHING
                        """,
                        scope_id,
                    )
                    await connection.execute(
                        """
                        INSERT INTO institution_sites (tenant_id, institution_id, slug, name, is_published)
                        VALUES ($1, $2, $3, $4, false)
                        ON CONFLICT (institution_id) DO UPDATE
                          SET slug = EXCLUDED.slug, name = EXCLUDED.name,
                              is_published = false, updated_at = now()
                        """,
                        tenant_id,
                        institution_id,
                        site_slug,
                        name,
                    )
                    await connection.execute(
                        """
                        INSERT INTO institution_programs (tenant_id, institution_id, code, name)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (institution_id, code) DO UPDATE SET name = EXCLUDED.name
                        """,
                        tenant_id,
                        institution_id,
                        code,
                        program_name,
                    )
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(seed(args.database_url)) or 0)


if __name__ == "__main__":
    main()
