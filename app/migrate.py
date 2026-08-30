"""Idempotent migration runner for the Nexus SQL directory."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
from pathlib import Path


async def run_migrations(database_url: str, migrations_dir: str) -> int:
    try:
        import asyncpg
    except ImportError as exc:
        raise RuntimeError("asyncpg is required to run migrations") from exc
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
            await connection.execute("CREATE SCHEMA IF NOT EXISTS nexus")
            await connection.execute("SET search_path = nexus, public")
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version TEXT PRIMARY KEY,
                  checksum TEXT NOT NULL,
                  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            applied = {row["version"]: row["checksum"] for row in await connection.fetch("SELECT version, checksum FROM schema_migrations")}
            for path in sorted(Path(migrations_dir).glob("*.sql")):
                version = path.name
                checksum = hashlib.sha256(path.read_bytes()).hexdigest()
                if version in applied:
                    if applied[version] != checksum:
                        raise RuntimeError(f"migration checksum changed after apply: {version}")
                    continue
                async with connection.transaction():
                    await connection.execute(path.read_text(encoding="utf-8"))
                    await connection.execute(
                        "INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)",
                        version,
                        checksum,
                    )
        return 0
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--migrations-dir", default="migrations")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run_migrations(args.database_url, args.migrations_dir)))


if __name__ == "__main__":
    main()
