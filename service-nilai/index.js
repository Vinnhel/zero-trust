'use strict';
const express = require('express');
const cfg = require('../shared/config');
const { openDb } = require('../shared/db');
const { gatewayGuard, tokenGuard, requireRole, jsonErrorHandler, secrets } = require('../shared/verify');

const db = openDb();
const app = express();
app.disable('x-powered-by');
app.use(gatewayGuard); // 1. hanya lewat gateway
app.use(express.json({ limit: '10kb' }));
app.use(tokenGuard); // 2. verifikasi ulang tanda tangan + masa berlaku token

let cached = { token: null, exp: 0 };
async function getServiceToken() {
  if (cached.token && Date.now() < cached.exp - 30_000) return cached.token;
  const r = await fetch(`${cfg.urls.gateway}/auth/service`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: secrets.serviceClientId, client_secret: secrets.serviceClientSecret }),
  });
  if (!r.ok) throw new Error(`Gagal mendapat token service (HTTP ${r.status})`);
  const j = await r.json();
  cached = { token: j.access_token, exp: Date.now() + j.expires_in * 1000 };
  return cached.token;
}

async function syncTranskrip(entries) {
  const token = await getServiceToken();
  const r = await fetch(`${cfg.urls.gateway}/transkrip/sinkron`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ entries }),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Sinkron transkrip ditolak (HTTP ${r.status}): ${body.error || 'tanpa detail'}`);
  return body;
}

const SELECT_NILAI = `
  SELECT n.id, n.kelas_id, k.kode AS kode_kelas, k.nama AS nama_kelas,
         u.nim, u.nama AS nama_mahasiswa, n.nilai, n.final
  FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.id = n.mahasiswa_id`;

app.get('/nilai', requireRole('mahasiswa', 'dosen'), (req, res) => {
  const uid = Number(req.auth.sub);
  const { nim, kelas_id: kelasId } = req.query;
  const where = []; const args = [];

  if (req.auth.role === 'mahasiswa') {
    // Row-level filtering dari token (bukan dari parameter client)
    const me = db.prepare('SELECT nim FROM users WHERE id = ?').get(uid);
    if (nim !== undefined && (!me || nim !== me.nim)) return res.status(403).json({ error: 'Bukan nilai milik Anda' });
    where.push('n.mahasiswa_id = ?', 'n.final = 1'); args.push(uid);
  } else {
    where.push('k.dosen_id = ?'); args.push(uid);
    if (nim !== undefined) { where.push('u.nim = ?'); args.push(String(nim)); }
  }
  if (kelasId !== undefined) { where.push('n.kelas_id = ?'); args.push(Number(kelasId)); }

  const rows = db.prepare(`${SELECT_NILAI} WHERE ${where.join(' AND ')} ORDER BY n.kelas_id, u.nim`).all(...args);
  res.json({ count: rows.length, data: rows.map((r) => ({ ...r, final: !!r.final })) });
});

app.put('/nilai/:id', requireRole('dosen'), (req, res) => {
  const v = req.body && req.body.nilai;
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 100) {
    return res.status(422).json({ error: 'nilai harus angka 0-100' });
  }
  const row = db.prepare(
    'SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'
  ).get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Nilai tidak ditemukan' });
  // Cek ulang kepemilikan & status final (jangan hanya percaya gateway)
  if (row.dosen_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Bukan kelas yang Anda ampu' });
  if (row.final) return res.status(409).json({ error: 'Nilai sudah final' });
  db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(v, row.id);
  res.json({ message: 'Nilai diperbarui', id: row.id, nilai: v });
});

app.post('/kelas/:id/finalisasi', requireRole('dosen'), async (req, res) => {
  const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(Number(req.params.id));
  if (!kelas) return res.status(404).json({ error: 'Kelas tidak ditemukan' });
  if (kelas.dosen_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Bukan kelas yang Anda ampu' });

  const rows = db.prepare(
    `SELECT n.id, n.final, n.nilai, u.nim FROM nilai n JOIN users u ON u.id = n.mahasiswa_id WHERE n.kelas_id = ?`
  ).all(kelas.id);
  if (!rows.length) return res.status(422).json({ error: 'Kelas belum memiliki data nilai' });
  if (rows.every((r) => r.final)) return res.status(409).json({ error: 'Kelas sudah difinalisasi' });
  if (rows.some((r) => r.nilai === null)) return res.status(422).json({ error: 'Masih ada nilai yang belum diisi' });

  const toFinal = rows.filter((r) => !r.final).map((r) => r.id);
  const mark = db.prepare('UPDATE nilai SET final = ? WHERE id = ?');
  db.transaction((v) => toFinal.forEach((id) => mark.run(v, id)))(1);

  try {
    const entries = rows.map((r) => ({
      nim: r.nim, kelas_id: kelas.id, kode: kelas.kode, nama_kelas: kelas.nama, nilai: r.nilai,
    }));
    const sync = await syncTranskrip(entries);
    res.json({ message: 'Kelas difinalisasi dan transkrip disinkronkan', kelas_id: kelas.id, jumlah_nilai: rows.length, sinkron: sync });
  } catch (err) {
    // Sinkron gagal -> kembalikan status final agar data tetap konsisten
    db.transaction(() => toFinal.forEach((id) => mark.run(0, id)))();
    console.error('[service-nilai]', err.message);
    res.status(502).json({ error: 'Finalisasi dibatalkan karena sinkron transkrip gagal', detail: err.message });
  }
});

app.use(jsonErrorHandler);
app.listen(cfg.ports.nilai, cfg.host, () => console.log(`[service-nilai] http://${cfg.host}:${cfg.ports.nilai}`));
