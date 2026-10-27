# Sistem Nilai — Zero Trust Security

Tugas Praktikum Individu · Keamanan Informasi (KP70065004) · Informatika Universitas Siliwangi

Sistem Nilai dengan **API Gateway sebagai Policy Enforcement Point (PEP)** yang terpisah dari service,
mengikuti NIST SP 800-207. Prinsip yang diterapkan: *never trust, always verify*, *least privilege*, *assume breach*.

- Bahasa/framework: Node.js (≥ 18) + Express, `http-proxy-middleware`, `jsonwebtoken`, SQLite (`better-sqlite3`)
- Pengujian: `curl`/Postman, plus **76 tes otomatis** (`npm test`)

---

## 1. Arsitektur

```
Client (curl/Postman)
   │  Authorization: Bearer <access token> + X-Device-ID
   ▼
┌─────────────────────────────────────────────┐
│ API GATEWAY :3000  = PEP                    │──► Audit Log (tabel audit_log)
│  ├─ pep.js      verifikasi token, sesi,     │
│  │              device, panggil policy      │
│  ├─ policy.js   POLICY ENGINE (allow/deny)  │──► baca atribut dari Database
│  └─ auth.js     POLICY ADMINISTRATOR        │
│                 (login/refresh/logout/token)│
└───────┬──────────────────────┬──────────────┘
        │ jika allow           │ jika allow
        │ + X-Gateway-Secret   │ + X-Gateway-Secret
        ▼                      ▼
  Service Nilai :3001     Service Transkrip :3002
  (cek secret + token)    (cek secret + token)
        │  finalisasi: ambil token service (POST /auth/service)
        └──► POST /transkrip/sinkron  ──► (lewat GATEWAY lagi!)
                         │
                         ▼
                 Database SQLite bersama
```

| Komponen | Peran NIST | File |
|---|---|---|
| API Gateway :3000 | PEP | `gateway/index.js`, `gateway/pep.js` |
| Policy Engine | PE | `gateway/policy.js`, `gateway/time-window.js` |
| Policy Administrator | PA | `gateway/auth.js` |
| Service Nilai :3001 | Resource | `service-nilai/index.js` |
| Service Transkrip :3002 | Resource | `service-transkrip/index.js` |
| Database | Resource | `db/schema.sql`, `scripts/setup.js` |
| Audit Log | Data source | `gateway/audit.js` (tabel `audit_log`) |

Pilihan desain yang memperkuat zero trust:

- **JWT RS256 (asimetris).** Gateway menandatangani dengan *private key*; service hanya memegang *public key*.
  Jika sebuah service dibobol, penyerang tidak bisa memalsukan token (*assume breach*).
- **Default deny.** Endpoint/method yang tidak punya aturan di `policy.js` ditolak.
- **Fail-closed.** Error tak terduga di PEP menghasilkan penolakan, bukan lolos.
- **Atribut dari database.** Role pada token dicocokkan dengan DB; kepemilikan kelas/NIM/status final dibaca dari DB.
- **Defense in depth.** Service tetap memeriksa kepemilikan dan status final sendiri, tidak hanya mengandalkan gateway.

---

## 2. Cara Menjalankan

### Opsi A — Langsung (Node.js ≥ 18)

```bash
npm install
npm run setup      # membuat keypair RSA, secret, database, dan data seed
npm start          # menjalankan gateway + service-nilai + service-transkrip
```

Gateway: `http://127.0.0.1:3000`. Ctrl+C menghentikan semuanya.
(`npm run setup` dapat diulang kapan saja untuk **mereset data** ke kondisi awal — hentikan dulu servernya.)

Perintah lain:

```bash
npm run audit        # tampilkan 30 entri audit log terakhir (npm run audit 100 untuk 100 entri)
npm test             # tes otomatis end-to-end (memakai data & port sementara 4000-4002)
npm run start:gateway / start:nilai / start:transkrip   # jalankan satu per satu di terminal terpisah
```

### Opsi B — Docker Compose

```bash
docker compose up --build
```

Hanya gateway (3000) yang menjadi pintu masuk. Port 3001/3002 sengaja dipublikasikan untuk demo
"akses langsung ditolak". Reset data: `docker compose down -v`.

---

## 3. Data Awal (Seed)

| Username | Password | Role | NIM | Device ID terdaftar |
|---|---|---|---|---|
| `admin`  | `Admin#123` | admin     | –       | `DEV-ADMIN-01`  |
| `dosen1` | `Dosen#123` | dosen     | –       | `DEV-DOSEN1-01` |
| `dosen2` | `Dosen#123` | dosen     | –       | `DEV-DOSEN2-01` |
| `mhs1`   | `Mhs#123`   | mahasiswa | 2210001 | `DEV-MHS1-01`   |
| `mhs2`   | `Mhs#123`   | mahasiswa | 2210002 | `DEV-MHS2-01`   |
| `mhs3`   | `Mhs#123`   | mahasiswa | 2210003 | `DEV-MHS3-01`   |

Setiap user memiliki tepat 1 device terdaftar.

| Kelas | id | Kode | Pengampu | Mahasiswa (nilai awal) |
|---|---|---|---|---|
| Keamanan Informasi | 1 | KP70065004 | dosen1 | mhs1=85, mhs2=78, mhs3=90 |
| Basis Data         | 2 | KP70031002 | dosen2 | mhs1=80, mhs2=88, mhs3=70 |

ID baris `nilai` (dipakai di `PUT /nilai/:id`): kelas 1 → id 1–3 (mhs1, mhs2, mhs3), kelas 2 → id 4–6.
Gunakan `GET /nilai` sebagai dosen untuk melihat id sebenarnya.

Secret (`X-Gateway-Secret`, client secret service) dibuat acak oleh `npm run setup` dan disimpan di
`data/secrets.json` (tidak masuk repository).

---

## 4. Pemetaan Kebutuhan → Kode (untuk video demo)

### 4.1 Autentikasi dan Token

| Kebutuhan | Lokasi kode |
|---|---|
| Access token JWT 10 menit (`sub`, `role`) via `Authorization: Bearer` | `gateway/auth.js` → `signToken`, `tokenResponse`; `shared/config.js` (`accessTtlSec`) |
| Refresh token 1 hari, disimpan di DB (hash SHA-256), bisa dicabut | `gateway/auth.js` → `newRefreshToken`, route `/refresh`; tabel `refresh_tokens` |
| Rotasi + deteksi *reuse* (token lama dipakai lagi ⇒ seluruh sesi dicabut) | `gateway/auth.js` → route `/refresh` |
| Logout mencabut refresh token (access token ikut mati: PEP cek sesi via klaim `sid`) | `gateway/auth.js` → `/logout`; `gateway/pep.js` langkah 2 |
| Token service dari `POST /auth/service` (client id + secret, 5 menit, `role: service`) | `gateway/auth.js` → `/service`; `service-nilai/index.js` → `getServiceToken` |
| Gateway secret `X-Gateway-Secret` (service tak bisa diakses langsung) | `gateway/index.js` (`proxyReq`); `shared/verify.js` → `gatewayGuard` |
| Verifikasi ulang token di service (tanda tangan + masa berlaku) | `shared/verify.js` → `tokenGuard` (RS256, issuer, audience, hanya public key) |

### 4.2 Kebijakan Akses (Tabel 3)

Seluruhnya ada di `gateway/policy.js` (array `rules`, satu aturan per baris Tabel 3).
Pemeriksaan ulang oleh service: `service-nilai/index.js`, `service-transkrip/index.js`.

| Endpoint | Aturan di Policy Engine | Data dari DB |
|---|---|---|
| `POST /auth/login` | `evaluateLogin` — kredensial valid + device terdaftar | `devices` |
| `POST /auth/refresh`, `/auth/logout` | `gateway/auth.js` — token valid, belum dicabut | `refresh_tokens` |
| `POST /auth/service` | `gateway/auth.js` — client id & secret valid | `service_clients` |
| `GET /nilai` | mahasiswa: hanya miliknya dan hanya yang sudah final (disaring di Service Nilai); dosen: hanya kelas diampu | `users`, `kelas` |
| `PUT /nilai/:id` | dosen pengampu + belum final + jam akses | `nilai`, `kelas` |
| `POST /kelas/:id/finalisasi` | dosen pengampu + jam akses → Service Nilai memanggil sinkron | `kelas` |
| `GET /transkrip/:nim` | mahasiswa: NIM sendiri; admin: semua | `users` |
| `POST /transkrip/sinkron` | hanya token service; token user mana pun ditolak | – |

### 4.3 Verifikasi Konteks

- **Device terdaftar:** `gateway/pep.js` langkah 3 (`X-Device-ID` harus terdaftar untuk user **dan** sama dengan device saat login — klaim `did`).
- **Jam akses 07.00–21.00:** `gateway/time-window.js`, dipanggil dari `policy.js` untuk `PUT /nilai/:id` dan finalisasi.
  Rentang dapat diatur di **`config/policy.config.json`** — file dibaca pada setiap keputusan, jadi cukup edit & simpan saat demo (tanpa restart):

  ```json
  { "access_hours": { "enabled": true, "start": "07:00", "end": "21:00", "timezone": "Asia/Jakarta" } }
  ```

### 4.4 Audit Log

`gateway/audit.js` — setiap keputusan (termasuk `/auth/*`, token tak valid, dan panggilan antar-service)
dicatat di tabel `audit_log`: waktu, subjek, role, endpoint, device, hasil (`allow`/`deny`), alasan.
Lihat dengan `npm run audit`.

---

## 5. Contoh Pengujian dengan curl

```bash
GW=http://127.0.0.1:3000

# Login dosen1 (device terdaftar)
curl -s -X POST $GW/auth/login -H 'Content-Type: application/json' -H 'X-Device-ID: DEV-DOSEN1-01' \
  -d '{"username":"dosen1","password":"Dosen#123"}'
# simpan access_token dan refresh_token dari hasilnya:
D1=<access_token dosen1>

# Dosen melihat nilai kelas yang diampu
curl -s "$GW/nilai?kelas_id=1" -H "Authorization: Bearer $D1" -H 'X-Device-ID: DEV-DOSEN1-01'

# Ubah nilai
curl -s -X PUT $GW/nilai/1 -H "Authorization: Bearer $D1" -H 'X-Device-ID: DEV-DOSEN1-01' \
  -H 'Content-Type: application/json' -d '{"nilai":88}'

# Finalisasi kelas -> Service Nilai memanggil sinkron transkrip lewat gateway
curl -s -X POST $GW/kelas/1/finalisasi -H "Authorization: Bearer $D1" -H 'X-Device-ID: DEV-DOSEN1-01'

# Transkrip mahasiswa (login sebagai mhs1 dulu)
curl -s $GW/transkrip/2210001 -H "Authorization: Bearer $M1" -H 'X-Device-ID: DEV-MHS1-01'

# Refresh & logout
curl -s -X POST $GW/auth/refresh -H 'X-Device-ID: DEV-DOSEN1-01' -H 'Content-Type: application/json' -d '{"refresh_token":"<rt>"}'
curl -s -X POST $GW/auth/logout  -H 'Content-Type: application/json' -d '{"refresh_token":"<rt>"}'
```

### Skenario penolakan (untuk didemokan)

```bash
# 1. Device salah -> 403
curl -i $GW/nilai -H "Authorization: Bearer $D1" -H 'X-Device-ID: DEV-MHS1-01'

# 2. Akses langsung ke service tanpa gateway secret -> 403
curl -i http://127.0.0.1:3001/nilai -H "Authorization: Bearer $D1"

# 3. Dengan secret tapi tanpa token -> 401   (SECRET ada di data/secrets.json)
curl -i http://127.0.0.1:3001/nilai -H "X-Gateway-Secret: <gateway_secret>"

# 4. Mahasiswa mengakses transkrip NIM lain -> 403
curl -i $GW/transkrip/2210002 -H "Authorization: Bearer $M1" -H 'X-Device-ID: DEV-MHS1-01'

# 5. Token user memanggil /transkrip/sinkron -> 403
curl -i -X POST $GW/transkrip/sinkron -H "Authorization: Bearer $D1" -H 'X-Device-ID: DEV-DOSEN1-01' \
  -H 'Content-Type: application/json' -d '{"entries":[]}'

# 6. Jam akses: ubah config/policy.config.json (mis. start 02:00, end 03:00), lalu PUT /nilai/1 -> 403 "Di luar jam akses"
```

---

## 6. Pengujian Otomatis

`npm test` menjalankan seluruh stack pada data & port sementara lalu menguji **76 skenario**:
token (masa berlaku, rotasi, reuse, logout), gateway secret, verifikasi ulang di service (token palsu, kedaluwarsa, `alg=none`),
device, seluruh baris Tabel 3 (kasus *allow* dan *deny*), jam akses, finalisasi + sinkron antar-service, default deny,
pembatasan brute force, dan isi audit log.

---

## 7. Usulan Alur Video Demo (6–9 menit)

| Menit | Isi | Tunjukkan di kode |
|---|---|---|
| 0:00–0:45 | Tujuan & arsitektur, peran PEP/PE/PA | Diagram README, struktur folder |
| 0:45–2:15 | **4.1** Login → JWT (decode di jwt.io), refresh disimpan hash di DB, rotasi, logout | `auth.js`, tabel `refresh_tokens` |
| 2:15–3:30 | **4.1** Gateway secret: curl langsung ke :3001 (403), dengan secret tanpa token (401), token palsu (401) | `shared/verify.js`, `index.js` `proxyReq` |
| 3:30–5:30 | **4.2** Tabel 3: demo allow/deny tiap role (mahasiswa NIM lain, dosen kelas lain, admin) | `policy.js` `rules` |
| 5:30–6:30 | Finalisasi → token service → sinkron lewat gateway; token user ke `/sinkron` ditolak | `service-nilai/index.js`, rule sinkron |
| 6:30–7:30 | **4.3** Device salah; ubah jam akses di config tanpa restart | `pep.js`, `time-window.js`, `policy.config.json` |
| 7:30–8:30 | **4.4** `npm run audit` memperlihatkan allow/deny + alasan; jalankan `npm test` | `audit.js` |
| 8:30–9:00 | Penutup: prinsip zero trust yang terpenuhi | – |

---

## 8. Catatan Keamanan & Batasan

- Berjalan di satu komputer: keypair/secret disimpan di folder `data/`. Pada produksi, simpan di secret manager dan
  berikan **hanya public key** ke service (di sini service memang hanya membaca `public.pem`).
- Gateway secret dan komunikasi antar-komponen memakai HTTP tanpa TLS; produksi wajib TLS/mTLS.
- Penguncian login gagal (5×/5 menit) disimpan di memori gateway (hilang saat restart).
- Access token yang sudah terbit tetap berlaku sampai 10 menit untuk *service* (mereka hanya memverifikasi tanda tangan),
  namun **di gateway** token ikut tidak berlaku begitu sesi dicabut (logout) karena PEP memeriksa sesi pada setiap request.
