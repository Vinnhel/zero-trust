PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  nama          TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nim           TEXT UNIQUE            -- hanya untuk mahasiswa
);

CREATE TABLE devices (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id   INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  UNIQUE (user_id, device_id)
);

CREATE TABLE kelas (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  kode     TEXT NOT NULL UNIQUE,
  nama     TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);

CREATE TABLE nilai (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id     INTEGER NOT NULL REFERENCES kelas(id),
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  nilai        REAL,                         -- 0..100, NULL = belum diisi
  final        INTEGER NOT NULL DEFAULT 0,   -- 1 = sudah difinalisasi
  UNIQUE (kelas_id, mahasiswa_id)
);

CREATE TABLE transkrip (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  nim       TEXT NOT NULL,
  kelas_id  INTEGER NOT NULL,
  kode      TEXT NOT NULL,
  nama_kelas TEXT NOT NULL,
  nilai     REAL NOT NULL,
  synced_at TEXT NOT NULL,
  UNIQUE (nim, kelas_id)
);

-- Refresh token disimpan (hash SHA-256) agar dapat dicabut.
-- "family" = satu sesi login; dipakai untuk rotasi dan deteksi reuse.
CREATE TABLE refresh_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  family     TEXT NOT NULL,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  device_id  TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,   -- epoch ms
  revoked_at INTEGER,            -- epoch ms, NULL = masih aktif
  created_at TEXT NOT NULL
);
CREATE INDEX idx_rt_family ON refresh_tokens(family);

CREATE TABLE service_clients (
  client_id   TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL
);

CREATE TABLE audit_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       TEXT NOT NULL,
  subject  TEXT NOT NULL,   -- username / client id / anonymous
  role     TEXT,
  endpoint TEXT NOT NULL,   -- "METHOD /path"
  device   TEXT,
  result   TEXT NOT NULL CHECK (result IN ('allow','deny')),
  reason   TEXT NOT NULL
);
