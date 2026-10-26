'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cfg = require('../shared/config');

if (process.argv.includes('--if-missing') && fs.existsSync(cfg.paths.db)) {
  console.log('Database sudah ada, setup dilewati.');
  process.exit(0);
}

fs.mkdirSync(path.dirname(cfg.paths.privateKey), { recursive: true });

// 1. Keypair RSA: gateway menandatangani (private), service memverifikasi (public)
if (!fs.existsSync(cfg.paths.privateKey)) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(cfg.paths.privateKey, privateKey, { mode: 0o600 });
  fs.writeFileSync(cfg.paths.publicKey, publicKey);
  console.log('Keypair RSA dibuat.');
}

if (!fs.existsSync(cfg.paths.secrets)) {
  fs.writeFileSync(cfg.paths.secrets, JSON.stringify({
    gateway_secret: crypto.randomBytes(32).toString('hex'),
    service_client_id: 'service-nilai',
    service_client_secret: crypto.randomBytes(32).toString('hex'),
  }, null, 2), { mode: 0o600 });
  console.log('Secret dibuat.');
}
const secrets = JSON.parse(fs.readFileSync(cfg.paths.secrets, 'utf8'));

for (const ext of ['', '-wal', '-shm']) fs.rmSync(cfg.paths.db + ext, { force: true });
const { openDb } = require('../shared/db');
const db = openDb();
db.exec(fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8'));

const USERS = [
  { u: 'admin',  nama: 'Administrator Akademik', role: 'admin',     nim: null,      pw: 'Admin#123', dev: 'DEV-ADMIN-01'  },
  { u: 'dosen1', nama: 'Dr. Budi Santoso',       role: 'dosen',     nim: null,      pw: 'Dosen#123', dev: 'DEV-DOSEN1-01' },
  { u: 'dosen2', nama: 'Dr. Sari Wulandari',     role: 'dosen',     nim: null,      pw: 'Dosen#123', dev: 'DEV-DOSEN2-01' },
  { u: 'mhs1',   nama: 'Andi Pratama',           role: 'mahasiswa', nim: '2210001', pw: 'Mhs#123',   dev: 'DEV-MHS1-01'   },
  { u: 'mhs2',   nama: 'Budi Hartono',           role: 'mahasiswa', nim: '2210002', pw: 'Mhs#123',   dev: 'DEV-MHS2-01'   },
  { u: 'mhs3',   nama: 'Citra Lestari',          role: 'mahasiswa', nim: '2210003', pw: 'Mhs#123',   dev: 'DEV-MHS3-01'   },
];
const ids = {};
const insU = db.prepare('INSERT INTO users(username,password_hash,nama,role,nim) VALUES (?,?,?,?,?)');
const insD = db.prepare('INSERT INTO devices(user_id,device_id) VALUES (?,?)');
for (const x of USERS) {
  ids[x.u] = insU.run(x.u, bcrypt.hashSync(x.pw, 10), x.nama, x.role, x.nim).lastInsertRowid;
  insD.run(ids[x.u], x.dev);
}
const insK = db.prepare('INSERT INTO kelas(kode,nama,dosen_id) VALUES (?,?,?)');
const k1 = insK.run('KP70065004', 'Keamanan Informasi', ids.dosen1).lastInsertRowid;
const k2 = insK.run('KP70031002', 'Basis Data', ids.dosen2).lastInsertRowid;
const insN = db.prepare('INSERT INTO nilai(kelas_id,mahasiswa_id,nilai,final) VALUES (?,?,?,0)');
const NILAI = { [k1]: { mhs1: 85, mhs2: 78, mhs3: 90 }, [k2]: { mhs1: 80, mhs2: 88, mhs3: 70 } };
for (const [k, m] of Object.entries(NILAI)) for (const [u, v] of Object.entries(m)) insN.run(Number(k), ids[u], v);

db.prepare('INSERT INTO service_clients(client_id,secret_hash) VALUES (?,?)')
  .run(secrets.service_client_id, bcrypt.hashSync(secrets.service_client_secret, 10));

db.close();
console.log('Database & data seed siap di', cfg.paths.db);
