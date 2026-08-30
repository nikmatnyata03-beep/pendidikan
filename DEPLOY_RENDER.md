# Deploy University Nexus ke Render

## Isi repository

Upload isi folder ini ke GitHub atau GitLab. Pastikan `Dockerfile`, `app`, `migrations`, `pyproject.toml`, dan `render.yaml` berada di root repository.

## Pilihan service

Pilih **New -> Blueprint** jika ingin Render membaca `render.yaml`, atau pilih **New -> Web Service** lalu gunakan:

- Runtime: Docker
- Health Check Path: `/health/ready`
- Port: `8000`
- Plan: Free untuk percobaan awal, Starter untuk testing yang tidak sering sleep

Database tidak dibuat di Render. Gunakan Supabase PostgreSQL pooler.

## Environment variable

Lengkapi nilai yang ditandai `sync: false` pada dashboard Render. Gunakan connection string pooler Supabase dengan SSL. Jangan memasukkan `service_role` key ke frontend atau repository.

Untuk staging, gunakan `NEXUS_ENVIRONMENT=staging` dan isi `NEXUS_ALLOWED_ORIGINS` dengan URL frontend staging yang sebenarnya.

## Pemeriksaan setelah deploy

1. Buka `https://alamat-render-anda.onrender.com/health/live`.
2. Buka `https://alamat-render-anda.onrender.com/health/ready`.
3. Pastikan keduanya merespons sukses.
4. Arahkan frontend dengan query `?api=https://alamat-render-anda.onrender.com`.

Migration dan seed tetap dijalankan sebagai langkah release terpisah sebelum memakai data production.
