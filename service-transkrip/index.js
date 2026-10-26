'use strict';
const express = require('express');
const cfg = require('../shared/config');
const { openDb } = require('../shared/db');
const { gatewayGuard, tokenGuard, requireRole, jsonErrorHandler } = require('../shared/verify');

const db = openDb();
const app = express();
app.disable('x-powered-by');
app.use(gatewayGuard);
app.use(express.json({ limit: '200kb' }));
app.use(tokenGuard);

app.post('/transkrip/sinkron', requireRole('service'), (req, res) => {
  const entries = req.body && req.body.entries;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 500) {
    return res.status(422).json({ error: 'entries harus array berisi 1-500 item' });
  }
  const findNim = db.prepare("SELECT 1 FROM users WHERE nim = ? AND role = 'mahasiswa'");
  for (const e of entries) {
    const okShape = e && typeof e.nim === 'string' && Number.isInteger(e.kelas_id) &&
      typeof e.kode === 'string' && typeof e.nama_kelas === 'string' &&
      typeof e.nilai === 'number' && e.nilai >= 0 && e.nilai <= 100;
    if (!okShape) return res.status(422).json({ error: 'Format entry tidak valid' });
    if (!findNim.get(e.nim)) return res.status(422).json({ error: `NIM ${e.nim} tidak dikenal` });
  }
  const up = db.prepare(`
    INSERT INTO transkrip(nim,kelas_id,kode,nama_kelas,nilai,synced_at) VALUES (?,?,?,?,?,?)
    ON CONFLICT(nim,kelas_id) DO UPDATE SET nilai = excluded.nilai, kode = excluded.kode,
      nama_kelas = excluded.nama_kelas, synced_at = excluded.synced_at`);
  const now = new Date().toISOString();
  db.transaction(() => entries.forEach((e) => up.run(e.nim, e.kelas_id, e.kode, e.nama_kelas, e.nilai, now)))();
  res.json({ message: 'Transkrip disinkronkan', upserted: entries.length, by: req.auth.sub });
});

app.get('/transkrip/:nim', requireRole('mahasiswa', 'admin'), (req, res) => {
  const { nim } = req.params;
  if (req.auth.role === 'mahasiswa') {
    // Cek ulang kepemilikan di service
    const me = db.prepare('SELECT nim FROM users WHERE id = ?').get(Number(req.auth.sub));
    if (!me || me.nim !== nim) return res.status(403).json({ error: 'Bukan transkrip milik Anda' });
  }
  const mhs = db.prepare("SELECT nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'").get(nim);
  if (!mhs) return res.status(404).json({ error: 'Mahasiswa tidak ditemukan' });
  const entries = db.prepare(
    'SELECT kelas_id, kode, nama_kelas, nilai, synced_at FROM transkrip WHERE nim = ? ORDER BY kelas_id'
  ).all(nim);
  const rata = entries.length ? Math.round((entries.reduce((a, b) => a + b.nilai, 0) / entries.length) * 100) / 100 : null;
  res.json({ nim: mhs.nim, nama: mhs.nama, jumlah_mk: entries.length, rata_rata: rata, entries });
});

app.use(jsonErrorHandler);
app.listen(cfg.ports.transkrip, cfg.host, () => console.log(`[service-transkrip] http://${cfg.host}:${cfg.ports.transkrip}`));
