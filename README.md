# Sistem Nilai dengan Zero Trust

Nama: Christine Angelica Soeharyanto
NIM: 247006111025

## Tentang proyek ini

Ini sistem nilai sederhana untuk prodi Informatika. Dosen mengisi dan memfinalisasi nilai kelas yang diampunya, lalu nilai yang sudah final dikirim ke Service Transkrip. Mahasiswa melihat nilai dan transkripnya sendiri, admin bisa melihat transkrip semua mahasiswa.

Fokus program ada di kontrol akses, bukan tampilan, jadi tidak ada frontend. Semua dicoba lewat `test.http` (REST Client di VS Code), Postman, atau curl.

Ada tiga proses yang berjalan bersamaan:

| Komponen | Port | Fungsi |
|---|---|---|
| API Gateway | 3000 | Satu-satunya pintu masuk. Memeriksa setiap request, memutuskan allow atau deny, mencatat audit log, lalu meneruskan ke service. |
| Service Nilai | 3001 | Data nilai dan kelas. |
| Service Transkrip | 3002 | Data transkrip mahasiswa. |

Database-nya satu file SQLite yang dipakai bersama. Di dalam gateway ada dua modul yang sesuai peran di NIST SP 800-207: `policy.js` sebagai Policy Engine (memutuskan allow atau deny) dan `auth.js` sebagai Policy Administrator (login dan penerbitan token). Gateway sendiri berperan sebagai Policy Enforcement Point.

## Cara menjalankan

Butuh Node.js 18 atau lebih baru.

```
npm install
npm run setup
npm start
```

`npm run setup` membuat keypair RSA, secret, database, dan data awal, semuanya disimpan di folder `data/` (folder ini tidak ikut di-commit). Setelah itu `npm start` menjalankan gateway dan kedua service sekaligus. Hentikan dengan Ctrl+C.

Kalau mau mengembalikan data ke kondisi awal, hentikan server, jalankan `npm run setup` lagi, lalu `npm start`. Keypair dan secret tidak berubah, hanya isi database yang di-reset.

Ketiga proses juga bisa dijalankan terpisah di tiga terminal: `npm run start:gateway`, `npm run start:nilai`, dan `npm run start:transkrip`.

## Menjalankan dengan Docker (opsional)

Kalau lebih suka Docker, ada `docker-compose.yml` yang menjalankan gateway dan kedua service sekaligus:

```
docker compose up --build
```

Pertama kali butuh beberapa menit untuk build. Container `setup` jalan dulu untuk membuat keypair, secret, dan data awal, lalu tiga service lainnya menyusul. Gateway bisa diakses di `http://localhost:3000`, dan cek cepatnya di `http://localhost:3000/health`.

Beberapa hal yang berbeda dari menjalankan langsung:

- Data, keypair, dan secret disimpan di volume Docker, bukan di folder `data/` lokal. Untuk melihat gateway secret: `docker compose exec gateway cat /app/data/secrets.json`.
- Port 3001 dan 3002 sengaja ikut dibuka ke host supaya bisa didemokan bahwa akses langsung ke service ditolak. Di lingkungan sebenarnya port ini tidak perlu dibuka.
- Folder `config/` dipasang ke container, jadi jam akses tetap bisa diubah dari file lokal tanpa restart.
- Melihat audit log: `docker compose exec gateway node scripts/show-audit.js 30`.
- Mengembalikan data ke awal: `docker compose down -v`, lalu `docker compose up`.


## Akun dan device ID data awal

Setiap user punya satu device terdaftar. Device ID dikirim lewat header `X-Device-ID`.

| Username | Password | Role | NIM | Device ID |
|---|---|---|---|---|
| admin | Admin#123 | admin | - | DEV-ADMIN-01 |
| dosen1 | Dosen#123 | dosen | - | DEV-DOSEN1-01 |
| dosen2 | Dosen#123 | dosen | - | DEV-DOSEN2-01 |
| mhs1 | Mhs#123 | mahasiswa | 2210001 | DEV-MHS1-01 |
| mhs2 | Mhs#123 | mahasiswa | 2210002 | DEV-MHS2-01 |
| mhs3 | Mhs#123 | mahasiswa | 2210003 | DEV-MHS3-01 |

Dua kelas, masing-masing diampu dosen yang berbeda. Nilai awalnya belum difinalisasi.

| Kelas | id | Pengampu | mhs1 | mhs2 | mhs3 |
|---|---|---|---|---|---|
| KP70065004 Keamanan Informasi | 1 | dosen1 | 85 | 78 | 90 |
| KP70031002 Basis Data | 2 | dosen2 | 80 | 88 | 70 |

Id baris nilai untuk `PUT /nilai/:id` adalah 1 sampai 3 untuk kelas 1 (urut mhs1, mhs2, mhs3) dan 4 sampai 6 untuk kelas 2.

Client secret untuk `/auth/service` dan gateway secret dibuat acak saat setup. Isinya ada di `data/secrets.json`.

## Endpoint dan aturannya

Semua request lewat gateway di port 3000. Selain `/auth/*`, setiap request wajib membawa `Authorization: Bearer <access token>` dan `X-Device-ID` yang terdaftar untuk user tersebut.

| Endpoint | Siapa | Syarat |
|---|---|---|
| POST /auth/login | semua user | username dan password benar, device terdaftar |
| POST /auth/refresh | semua user | refresh token valid, belum dicabut, device sama dengan saat login |
| POST /auth/logout | semua user | refresh token valid dan belum dicabut |
| POST /auth/service | Service Nilai | client ID dan secret benar |
| GET /nilai | mahasiswa, dosen | mahasiswa hanya nilai miliknya yang sudah final; dosen hanya kelas yang diampu |
| PUT /nilai/:id | dosen | kelas yang diampu, nilai belum final, dalam jam akses |
| POST /kelas/:id/finalisasi | dosen | kelas yang diampu, dalam jam akses |
| GET /transkrip/:nim | mahasiswa, admin | mahasiswa hanya NIM sendiri; admin semua NIM |
| POST /transkrip/sinkron | Service Nilai | hanya token service, token user mana pun ditolak |

Contoh login:

```
curl -X POST http://127.0.0.1:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DOSEN1-01" \
  -d '{"username":"dosen1","password":"Dosen#123"}'
```

Endpoint yang tidak ada di tabel di atas otomatis ditolak.

## Cara kerja singkat

**Token.** Access token berupa JWT berlaku 10 menit, ditandatangani RS256, isinya `sub`, `role`, `did` (device saat login), dan `sid` (id sesi). Refresh token berlaku 1 hari, disimpan di database dalam bentuk hash supaya bisa dicabut. Setiap kali dipakai, refresh token diganti yang baru. Kalau token lama dipakai lagi, seluruh sesinya dicabut. Logout mencabut sesi, dan karena gateway mengecek sesi di setiap request, access token yang masih berlaku ikut tidak bisa dipakai.

**Token service.** Service Nilai mengambil token dari `POST /auth/service` memakai client ID dan secret. Token ini berlaku 5 menit dengan `role: service`. Saat finalisasi, Service Nilai memanggil `POST /transkrip/sinkron` lewat gateway memakai token itu, jadi panggilan antar-service juga diperiksa dan tercatat.

**Gateway secret.** Gateway menambahkan header `X-Gateway-Secret` saat meneruskan request. Kedua service menolak request tanpa header itu (403), jadi tidak bisa diakses langsung.

**Verifikasi ulang di service.** Walaupun sudah lewat gateway, service tetap memeriksa tanda tangan dan masa berlaku token. Request yang membawa gateway secret tapi tanpa token valid tetap ditolak (401). Service hanya memegang public key, jadi kalau salah satu service bocor, token tidak bisa dipalsukan.

**Policy Engine.** Aturan kepemilikan data (kelas yang diampu, NIM milik mahasiswa, status final) tidak bisa diputuskan dari isi token, jadi `policy.js` membaca data user, kelas, dan nilai dari database. Role di token juga dicocokkan dengan role di database. Kalau tidak ada aturan yang cocok, hasilnya deny.

**Audit log.** Setiap keputusan gateway disimpan di tabel `audit_log`: waktu, subjek (user atau service), endpoint, device, hasil (allow atau deny), dan alasannya. Lihat dengan `npm run audit` (atau `npm run audit 100` untuk 100 baris terakhir). Kolom waktunya dalam UTC.

## Jam akses

Mengubah dan memfinalisasi nilai hanya boleh pukul 07.00 sampai 21.00 (WIB). Rentangnya diatur di `config/policy.config.json`:

```json
{
  "access_hours": {
    "enabled": true,
    "start": "07:00",
    "end": "21:00",
    "timezone": "Asia/Jakarta"
  }
}
```

File ini dibaca setiap kali ada keputusan, jadi cukup edit lalu simpan, tidak perlu restart. Itu berguna saat demo: ubah ke rentang yang tidak mencakup jam sekarang, maka `PUT /nilai/:id` dan finalisasi akan ditolak.

## Pengujian

**Lewat REST Client.** Pasang ekstensi REST Client di VS Code, buka `test.http`, dan kirim request dari atas ke bawah (klik Send Request di atas tiap blok). Ada 39 request bernomor 1.1 sampai 7.6, tiap blok mencantumkan hasil yang benar. Satu hal yang perlu disiapkan: ganti `ISI_SECRET_DI_SINI` di baris `@secret` dengan `gateway_secret` dari `data/secrets.json`. Nilai ini dipakai untuk mencoba akses langsung ke service. Jangan di-commit.

Beberapa hal yang perlu diperhatikan:

- Token berlaku 10 menit. Kalau muncul 401 kedaluwarsa, kirim ulang request login (1.1 sampai 1.4).
- Setelah VS Code dibuka ulang, request login perlu dikirim lagi. Peringatan "Request ... has not been sent" di tab Problems itu normal.
- Finalisasi (7.1) hanya bisa sekali. Untuk mengulang, reset data seperti di bagian cara menjalankan.

**Tes otomatis.**

```
npm test
```

Ini menjalankan seluruh sistem pada data dan port sementara (4000 sampai 4002), jadi tidak mengganggu server yang sedang jalan. Ada 76 pemeriksaan yang mencakup token, gateway secret, device, semua baris tabel kebijakan, jam akses, finalisasi dan sinkron, serta audit log.

## Struktur folder

```
gateway/            API gateway
  index.js            server dan proxy ke service
  pep.js              pemeriksaan tiap request (token, sesi, device)
  policy.js           Policy Engine
  auth.js             login, refresh, logout, token service
  time-window.js      pengecekan jam akses
  audit.js            pencatatan audit log
service-nilai/      Service Nilai
service-transkrip/  Service Transkrip
shared/             konfigurasi, koneksi database, verifikasi token di service
db/schema.sql       skema database
config/             konfigurasi jam akses
scripts/            setup, start semua, lihat audit
tests/e2e.js        tes otomatis
test.http           kumpulan request untuk REST Client
Dockerfile, docker-compose.yml   menjalankan lewat Docker (opsional)
```

## Catatan dan batasan

- Mahasiswa hanya melihat nilai yang sudah difinalisasi. Soal tidak mengatur hal ini, saya tambahkan karena nilai yang masih bisa berubah tidak perlu terlihat.
- Percobaan login yang gagal dibatasi: lima kali salah, akun dikunci lima menit. Hitungannya disimpan di memori gateway, jadi hilang kalau gateway di-restart.
- Semuanya berjalan lewat HTTP biasa di satu komputer. Untuk penggunaan sebenarnya, komunikasi antar komponen perlu TLS atau mTLS, dan keypair serta secret sebaiknya disimpan di secret manager, bukan di folder `data/`.
