# Nexus Campus Production Foundation · Step 1–10

Step ini mengunci fondasi authorization dan hierarchy untuk platform yayasan dengan banyak lembaga. Fokusnya bukan membuat demo baru, tetapi memastikan kuasa admin, guru, dan santri dapat dibatasi, diaudit, dan diperluas tanpa membuka akses lintas lembaga.

## Model Kuasa

| Role | Scope | Contoh kuasa |
| --- | --- | --- |
| `super_admin` | global | Semua tenant dan semua modul |
| `institution_admin` | lembaga | Semua fakultas, prodi, kelas, dan modul dalam satu lembaga |
| `faculty_admin` | fakultas | Semua prodi dan mata kuliah di fakultas tersebut |
| `program_admin` | prodi | Semua mahasiswa, mata kuliah, kelas, nilai, dan layanan prodi |
| `course_admin` | mata kuliah | Semua section, materi, roster, presensi, dan nilai mata kuliah |
| `section_admin` | kelas/section | Hanya satu kelas pada satu semester |
| `academic_admin` | configurable | Modul akademik sesuai permission yang diberikan |
| `finance_admin` | configurable | Modul keuangan sesuai scope yang diberikan |
| `instructor` | course/section | Presensi, materi, tugas, dan penilaian kelas yang ditugaskan |
| `lembaga_admin` | satu lembaga | Konten, pendaftaran, kelas, dan kegiatan lembaga |
| `operator_pendaftaran` | satu lembaga/tenant | Verifikasi pendaftaran dan dokumen calon santri |
| `guru` | course/section | Presensi, materi, tugas, dan penilaian |
| `santri` | data sendiri | Materi, tugas, presensi, dan nilai miliknya |
| `wali` | santri terkait | Pemantauan data santri yang diizinkan |

Satu user dapat memiliki beberapa assignment. Contoh yang didukung:

- Budi sebagai `institution_admin` untuk Universitas A.
- Budi sekaligus `course_admin` untuk IF-305 di Universitas B bila tenant dan kebijakan mengizinkan.
- Citra sebagai `finance_admin` untuk satu fakultas tanpa dapat mengubah nilai.
- Deni memiliki grant `deny` pada satu mata kuliah ketika akses perlu dicabut sementara.

## Kontrak Otorisasi

`app/authorization.py` memakai deny-by-default dan mengevaluasi:

1. Identitas subject.
2. Status dan masa berlaku grant.
3. Batas tenant.
4. Kecocokan scope resource: global, institution, faculty, program, course, atau section.
5. Permission exact atau wildcard domain seperti `attendance.*`.
6. Grant `deny` yang selalu menang atas grant `allow`.

Contoh permission: `student.read`, `course.manage`, `attendance.adjust`, `grade.write`, `finance.invoice.write`, `audit.read`.

Engine ini sengaja tidak memverifikasi JWT dan tidak mengambil data dari database. Adapter IAM dan repository database pada Step 2 wajib memvalidasi token, mengisi `ResourceContext` dari database, lalu mengirim audit event untuk setiap keputusan sensitif.

## Database

Seluruh tabel dan function Nexus dibuat di schema PostgreSQL `nexus`, bukan `public`. Ini penting bila project Supabase sudah memiliki aplikasi lain. Repository, bootstrap, dan migration runner mengatur `search_path` ke `nexus,public` sehingga tabel seperti `public.users` tidak pernah dipakai oleh Nexus.

`migrations/001_foundation.sql` menyediakan:

- tenant dan hierarchy institution → faculty → program → course → section;
- role, permission, assignment, dan assignment-specific permission;
- generic authorization scope plus transitive closure untuk ancestry;
- audit log append-only dengan request ID dan metadata JSON;
- index awal untuk query hierarchy, assignment, dan audit.

Catatan: migration membuat PostgreSQL extension `citext` bila deployment user memiliki privilege extension. Bila policy database melarangnya, siapkan extension melalui DBA sebelum migration:

```sql
CREATE EXTENSION IF NOT EXISTS citext;
```

Jalankan migration di staging terlebih dahulu. Seeder role system harus ditinjau oleh pemilik kebijakan akses kampus sebelum production.

## Test

Pasang dependency test lalu jalankan dari folder ini:

```bash
python -m pip install -e ".[test]"
python -m pytest
```

Acceptance Step 1:

- super admin dapat lintas tenant;
- admin lembaga tidak dapat menyeberang tenant;
- admin prodi dapat mengelola course/section dalam prodinya;
- admin mata kuliah dapat mengelola section course itu saja;
- finance admin tidak dapat menulis nilai;
- grant deny mengalahkan allow;
- grant kadaluarsa tidak berlaku;
- wildcard permission hanya berlaku pada domain yang sesuai.

## Yang Belum Diklaim Production

Artefak ini belum menjadi deployment lengkap. Adapter IAM, API, migration runner, dan RLS sudah ditulis, tetapi provider OIDC, PostgreSQL runtime, secret management, rate limit, observability, backup, dan frontend yang terhubung ke database belum dipasang. Itu sengaja dipisahkan agar setiap langkah dapat ditinjau dan diuji sebelum membuka langkah berikutnya.

## Next Step After Step 1

Step 1 sudah menjadi dasar Step 2 di bawah. Jangan menghubungkan payment gateway atau presensi produksi sebelum Step 2 dan security review selesai.

## Step 2 · Runtime Contract

Step 2 menambahkan komponen berikut:

- `app/config.py`: konfigurasi environment dan fail-fast validation untuk production.
- `app/identity.py`: OIDC JWT verification dengan issuer, audience, JWKS, algorithm allowlist, expiry, not-before, dan clock skew.
- `app/tenant.py`: resolusi `X-Tenant-ID` hanya setelah membership database tervalidasi; user multi-tenant wajib memilih tenant eksplisit.
- `app/db.py`: asyncpg repository dengan query tenant-filtered untuk user, grant, resource context, assignment, academic master data, dan audit.
- `app/audit.py`: event contract dan redaksi token/password/CVV/PIN.
- `app/main.py`: FastAPI app, request ID, health endpoints, `/v1/me`, `/v1/access/check`, dan `/v1/admin/grants`.
- `app/migrate.py`: migration runner idempotent dengan checksum dan tabel `schema_migrations`.
- `migrations/002_permissions.sql`: katalog permission serta mode explicit permission override.
- `Dockerfile`, `.env.example`, dan `docker-compose.dev.yml` untuk staging/dev bootstrap.

### Jalur admin yang aman

`POST /v1/admin/grants` tidak hanya mengecek `admin.grant.manage`. Sistem juga membandingkan level authority actor dengan role target sehingga admin prodi tidak dapat mengangkat dirinya atau orang lain menjadi admin institusi/super admin. Global `super_admin` tetap menjadi satu-satunya role yang dapat membuat assignment global.

### Menjalankan runtime

1. Salin `.env.example` ke secret store deployment, lalu isi issuer, audience, JWKS URL, origin, dan PostgreSQL URL yang sebenarnya.
2. Jalankan `python -m app.migrate --database-url "$NEXUS_DATABASE_URL" --migrations-dir migrations` sebagai job release terpisah.
3. Jalankan `uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers`.
4. Cek `/health/live` untuk liveness dan `/health/ready` untuk kesiapan database.

Jangan memakai nilai `docker-compose.dev.yml` di production. Jangan menonaktifkan verifikasi JWT, CORS allowlist, atau audit fail-closed.

### Acceptance Step 2

- token tanpa Bearer, issuer, audience, signature, key, atau expiry valid ditolak;
- JWKS di-cache dan di-refresh jika `kid` baru muncul;
- user multi-tenant wajib memilih `X-Tenant-ID`;
- user biasa tidak dapat memilih tenant yang tidak memiliki membership;
- query resource dan grant selalu diberi tenant filter;
- audit menyimpan request ID dan tidak menyimpan credential sensitif;
- role delegation tidak dapat menaikkan authority actor;
- migration yang checksum-nya berubah setelah apply menghentikan deployment;
- endpoint health live tidak bergantung database, readiness bergantung database.

PyJWT, asyncpg, FastAPI, httpx, dan uvicorn sudah dideklarasikan di `pyproject.toml`. Test aplikasi dijalankan lokal; migration production dijalankan sebagai release job atau melalui Supabase Management API.

## Step 3 · Database Provider dan RLS

### Rekomendasi provider

- **Supabase**: pilihan tercepat untuk pilot production. PostgreSQL, Auth, Storage, dan Realtime sudah tersedia. Gunakan pooled connection string untuk aplikasi, nonaktifkan statement cache asyncpg seperti yang sudah dilakukan di repository, aktifkan asymmetric signing key (RS256/ES256) pada Auth, dan simpan secret di secret manager.
- **Managed PostgreSQL + OIDC**: pilihan terbaik bila universitas sudah memiliki cloud account, SSO, backup, dan compliance sendiri. Contohnya PostgreSQL managed ditambah Keycloak, Auth0, Azure AD, atau Google Workspace OIDC.
- **Firestore**: tidak disarankan sebagai system of record untuk KRS, prasyarat, presensi, nilai, dan keuangan karena relasi, transaksi, constraint, serta laporan lintas domain lebih alami di PostgreSQL.
- **Google Sheets**: gunakan hanya sebagai jalur import/export yang dikontrol, misalnya import master mahasiswa atau laporan keuangan. Jangan menjadikannya database utama, sumber permission, atau ledger pembayaran.

Kode Step 3 memakai kontrak PostgreSQL standar sehingga tidak mengunci vendor. Pilih Supabase bila ingin setup cepat; pilih managed PostgreSQL + OIDC bila membutuhkan kontrol jaringan, compliance, dan operasi enterprise lebih besar.

Untuk Supabase, gunakan connection pooler yang disediakan project, `NEXUS_OIDC_ISSUER=https://<project-ref>.supabase.co/auth/v1`, `NEXUS_OIDC_AUDIENCE=authenticated`, dan `NEXUS_OIDC_JWKS_URL=https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json`. Aktifkan asymmetric signing key pada Auth terlebih dahulu. Jangan menaruh `service_role` key di frontend atau mengirimkannya melalui browser.

### RLS dan bootstrap

- `migrations/003_tenant_rls.sql` mengaktifkan Row-Level Security pada hierarchy akademik, scope, closure, dan audit.
- Repository mengisi `app.tenant_id` dan `app.global_admin` dengan `set_config(..., true)` yang setara dengan `SET LOCAL` di dalam transaksi setiap kali membaca resource tenant.
- `app/bootstrap.py` membuat tenant, institution scope, dan `super_admin` pertama dari OIDC subject. Tidak ada password atau token yang dibuat oleh script.
- `app/seed_darussolah.py` membuat struktur Yayasan Darussolah Wal Jinan, empat lembaga, site lembaga, program pendidikan, dan institution scope tanpa membuat user.
- `docker-compose.dev.yml` hanya untuk development. Migrasi production tetap dijalankan sebagai release job terpisah.

Contoh bootstrap:

```bash
python -m app.bootstrap \
  --database-url "$NEXUS_DATABASE_URL" \
  --tenant-slug kampus-utama \
  --tenant-name "Universitas Contoh" \
  --institution-code UNIV \
  --institution-name "Universitas Contoh" \
  --admin-subject "oidc-subject-dari-provider" \
  --admin-name "Administrator Utama" \
  --admin-email admin@kampus.example
```

Jalankan setelah migration dan setelah subject admin dibuat di provider OIDC. Periksa hasilnya di staging sebelum memberi akses production.

### Acceptance Step 3

- query tenant A tidak dapat membaca atau mengubah resource tenant B walaupun ID diketahui;
- global admin dapat mengelola tenant yang dipilih tanpa mematikan RLS;
- koneksi pool mengatur context tenant secara lokal dan tidak membocorkan context antar request;
- bootstrap dapat dijalankan ulang tanpa membuat global admin duplikat;
- Supabase pooler tidak mengalami konflik prepared statement;
- backup, restore drill, RPO/RTO, dan audit retention disetujui sebelum go-live.

## Step 4 · Academic Master Data

`migrations/004_academic_foundation.sql` menambahkan:

- academic terms dengan tanggal dan status;
- student profiles yang menghubungkan OIDC-backed user ke program studi;
- course prerequisites;
- instructor assignments pada section;
- section enrollments dengan status dan final grade;
- constraint database yang menolak relasi lintas tenant;
- RLS untuk tabel akademik baru.

Endpoint master data yang tersedia:

- `GET /v1/academic/institution`, `/faculty`, `/program`, `/course`, `/section`, `/term`, `/student` dengan pagination `limit` dan `offset`;
- `POST /v1/academic/institutions`, `/faculties`, `/programs`, `/courses`, `/sections`, `/terms`, `/students`;
- setiap operasi create memakai permission `*.manage` pada parent resource, bukan hanya pemeriksaan tenant header;
- list memfilter hasil lagi melalui authorization engine sehingga resource sibling yang tidak diizinkan tidak ikut dikembalikan.

### Acceptance Step 4

- admin fakultas hanya dapat membuat atau melihat program di fakultasnya;
- admin prodi hanya dapat membuat atau melihat course di prodinya;
- admin mata kuliah hanya dapat membuat atau melihat section pada course-nya;
- pembuatan mahasiswa memastikan user dan program berada pada tenant yang sama;
- section baru hanya dapat memakai academic term pada tenant yang sama;
- prerequisite, instructor, dan enrollment lintas tenant ditolak oleh trigger database;
- duplicate code, student number, enrollment, dan assignment ditangani oleh unique constraint;
- migration dan test suite dapat dijalankan tanpa provider cloud tertentu.

Migration Step 4 sudah diterapkan ke staging Supabase pada schema `nexus`. Smoke test dengan data tenant nyata dan verifikasi backup/restore tetap harus dilakukan sebelum production.

## Step 5 · Section Operations

Operasi section yang mengubah state sudah ditambahkan dengan transaksi database:

- `POST /v1/academic/sections/{section_id}/instructors` menugaskan user aktif sebagai instructor atau assistant;
- `GET /v1/academic/sections/{section_id}/instructors` membaca daftar pengajar;
- `POST /v1/academic/enrollments` mendaftarkan student aktif ke section;
- `GET /v1/academic/sections/{section_id}/enrollments` membaca roster dengan pagination.

Enrollment memerlukan `section.manage` pada section dan `student.manage` pada student profile. Request concurrent untuk section yang sama diserialisasi dengan row lock dan advisory lock; bila kapasitas penuh, request `enrolled` otomatis menjadi `waitlisted`. Unique constraint mencegah duplicate enrollment dan duplicate instructor assignment. Migration `005_enrollment_integrity.sql` juga menolak enrollment ke section tertutup dan assignment ke user nonaktif.

Self-service enrollment mahasiswa, approval workflow, prerequisite evaluation, grade entry, dan payment ledger sengaja belum dibuka. Modul-modul tersebut membutuhkan kebijakan akademik universitas sebelum dibuat sebagai state transition production.

### Acceptance Step 5

- section tertutup tidak menerima enrollment;
- student nonaktif tidak dapat didaftarkan;
- kapasitas section tidak terlampaui saat dua request datang bersamaan;
- enrollment yang melebihi kapasitas masuk waitlist;
- instructor assignment dan enrollment lintas tenant ditolak;
- instructor nonaktif ditolak oleh database;
- roster hanya dapat dibaca oleh actor yang memiliki akses section;
- operasi enrollment dan instructor assignment menghasilkan audit event.

## Step 6 · Supabase Staging

Project Supabase yang terhubung sudah aktif dan sehat. Migration `001` sampai `011` sudah diterapkan dan tercatat. Nexus memiliki schema `nexus` yang terisolasi; 23 tabel lama di schema `public` dibiarkan tanpa perubahan.

Seed awal client juga sudah dibuat dalam keadaan belum dipublikasikan: satu tenant `yayasan-darussolah-wal-jinan`, empat institution, empat site lembaga, dan empat program pendidikan. Patch migration `008` sampai `010` memastikan function trigger tetap aman ketika dipanggil dari koneksi Supabase dengan `search_path` berbeda. Migration `011` memperbaiki trigger Auth lama pada schema `public` agar pendaftaran user tetap kompatibel dengan aplikasi existing.

Yang masih dibutuhkan untuk bootstrap:

- buat atau undang user administrator di Supabase Auth atau provider OIDC;
- tentukan nama kampus, slug tenant, kode institution, dan nama institution;
- bila perlu mengulang seed struktur, jalankan `python -m app.seed_darussolah --database-url "$NEXUS_DATABASE_URL"`;
- gunakan subject OIDC user tersebut saat menjalankan `app/bootstrap.py`;
- aktifkan asymmetric JWT signing dan isi issuer, audience, serta JWKS URL sebelum API menerima login.

Belum ada tenant atau user Nexus yang dibuat otomatis karena belum ada identitas admin yang dikonfirmasi. Jangan memakai user dummy atau `service_role` key sebagai identitas aplikasi.
