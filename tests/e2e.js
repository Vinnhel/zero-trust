'use strict';
const fs = require('fs'); const os = require('os'); const path = require('path'); const net = require('net');
const { spawn, spawnSync } = require('child_process');
const jwt = require('jsonwebtoken');

const ROOT = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'zt-test-'));
const CONFIG_DIR = path.join(TMP, 'config'); fs.mkdirSync(CONFIG_DIR);
const POLICY_CFG = path.join(CONFIG_DIR, 'policy.config.json');
const setHours = (start, end) => fs.writeFileSync(POLICY_CFG, JSON.stringify({ access_hours: { enabled: true, start, end, timezone: 'Asia/Jakarta' } }));
setHours('00:00', '24:00');

const env = {
  ...process.env, DATA_DIR: path.join(TMP, 'data'), CONFIG_DIR,
  GATEWAY_PORT: '4000', NILAI_PORT: '4001', TRANSKRIP_PORT: '4002',
};
Object.assign(process.env, env);
const GW = 'http://127.0.0.1:4000'; const NILAI = 'http://127.0.0.1:4001'; const TRANSKRIP = 'http://127.0.0.1:4002';

let pass = 0; let fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log(`  \x1b[32m✓\x1b[0m ${name}`); } else { fail++; console.log(`  \x1b[31m✗ ${name}\x1b[0m ${extra}`); }
}
const section = (t) => console.log(`\n\x1b[1m${t}\x1b[0m`);

async function call(base, method, p, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const r = await fetch(base + p, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  let json = null; try { json = await r.json(); } catch (_) { }
  return { status: r.status, json };
}
const gw = (m, p, o) => call(GW, m, p, o);
const DEV = { admin: 'DEV-ADMIN-01', dosen1: 'DEV-DOSEN1-01', dosen2: 'DEV-DOSEN2-01', mhs1: 'DEV-MHS1-01', mhs2: 'DEV-MHS2-01', mhs3: 'DEV-MHS3-01' };
const PW = { admin: 'Admin#123', dosen1: 'Dosen#123', dosen2: 'Dosen#123', mhs1: 'Mhs#123', mhs2: 'Mhs#123', mhs3: 'Mhs#123' };
async function login(u) {
  const r = await gw('POST', '/auth/login', { body: { username: u, password: PW[u] }, device: DEV[u] });
  return { ...r.json, status: r.status };
}
const waitPort = (port) => new Promise((resolve, reject) => {
  const t0 = Date.now();
  (function tryOnce() {
    const s = net.connect(port, '127.0.0.1');
    s.on('connect', () => { s.destroy(); resolve(); });
    s.on('error', () => { s.destroy(); Date.now() - t0 > 10000 ? reject(new Error('timeout port ' + port)) : setTimeout(tryOnce, 150); });
  })();
});

(async () => {
  const st = spawnSync(process.execPath, ['scripts/setup.js'], { cwd: ROOT, env, encoding: 'utf8' });
  if (st.status !== 0) { console.error(st.stdout, st.stderr); process.exit(1); }
  const kids = ['gateway/index.js', 'service-nilai/index.js', 'service-transkrip/index.js']
    .map((f) => spawn(process.execPath, [f], { cwd: ROOT, env, stdio: 'ignore' }));
  const cleanup = () => { kids.forEach((k) => k.kill()); };
  process.on('exit', cleanup);
  await Promise.all([4000, 4001, 4002].map(waitPort));

  const cfg = require('../shared/config');
  const { openDb } = require('../shared/db');
  const db = openDb();
  const secrets = cfg.loadSecrets();
  const uid = (u) => db.prepare('SELECT id FROM users WHERE username=?').get(u).id;
  const kelasId = (kode) => db.prepare('SELECT id FROM kelas WHERE kode=?').get(kode).id;
  const K1 = kelasId('KP70065004'); const K2 = kelasId('KP70031002');
  const nilaiId = (k, u) => db.prepare('SELECT id FROM nilai WHERE kelas_id=? AND mahasiswa_id=?').get(k, uid(u)).id;

  section('4.1 Autentikasi dan token');
  const t = {};
  for (const u of ['admin', 'dosen1', 'dosen2', 'mhs1']) t[u] = await login(u);
  check('login valid menghasilkan access & refresh token', t.mhs1.status === 200 && t.mhs1.access_token && t.mhs1.refresh_token);
  const dec = jwt.decode(t.mhs1.access_token);
  check('access token berisi sub & role', dec.sub && dec.role === 'mahasiswa');
  check('access token berlaku 10 menit', dec.exp - dec.iat === 600, `exp-iat=${dec.exp - dec.iat}`);
  const rt = db.prepare('SELECT expires_at FROM refresh_tokens WHERE user_id=? LIMIT 1').get(uid('mhs1'));
  check('refresh token tersimpan di DB & berlaku 1 hari', Math.abs((rt.expires_at - Date.now()) - 86400000) < 5000);
  check('refresh token disimpan sebagai hash (bukan plaintext)', !db.prepare('SELECT 1 FROM refresh_tokens WHERE token_hash=?').get(t.mhs1.refresh_token));
  let r = await gw('POST', '/auth/login', { body: { username: 'mhs1', password: 'salah' }, device: DEV.mhs1 });
  check('login password salah -> 401', r.status === 401);
  r = await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PW.mhs1 }, device: 'DEV-ASING' });
  check('login dari device tidak terdaftar -> 403', r.status === 403, JSON.stringify(r));
  r = await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PW.mhs1 }, device: DEV.mhs2 });
  check('login memakai device milik user lain -> 403', r.status === 403);
  r = await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PW.mhs1 } });
  check('login tanpa X-Device-ID -> 403', r.status === 403);

  r = await gw('POST', '/auth/service', { body: { client_id: secrets.serviceClientId, client_secret: 'salah' } });
  check('/auth/service secret salah -> 401', r.status === 401);
  r = await gw('POST', '/auth/service', { body: { client_id: secrets.serviceClientId, client_secret: secrets.serviceClientSecret } });
  const svcTok = r.json && r.json.access_token; const sd = jwt.decode(svcTok || '') || {};
  check('/auth/service valid -> token role service, berlaku 5 menit', r.status === 200 && sd.role === 'service' && sd.exp - sd.iat === 300);

  const l2 = await login('mhs2');
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: l2.refresh_token }, device: DEV.mhs2 });
  check('refresh valid -> token baru (rotasi)', r.status === 200 && r.json.refresh_token && r.json.refresh_token !== l2.refresh_token);
  const newRt = r.json.refresh_token;
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: l2.refresh_token }, device: DEV.mhs2 });
  check('refresh token lama (reuse) ditolak -> 401', r.status === 401);
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: newRt }, device: DEV.mhs2 });
  check('reuse mencabut seluruh sesi (token baru ikut mati)', r.status === 401);
  const l2b = await login('mhs2');
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: l2b.refresh_token }, device: DEV.mhs1 });
  check('refresh dari device lain -> 403', r.status === 403);

  const l1 = await login('mhs1');
  r = await gw('GET', '/nilai', { token: l1.access_token, device: DEV.mhs1 });
  check('sebelum logout access token berfungsi', r.status === 200);
  r = await gw('POST', '/auth/logout', { body: { refresh_token: l1.refresh_token } });
  check('logout berhasil', r.status === 200);
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: l1.refresh_token }, device: DEV.mhs1 });
  check('refresh setelah logout ditolak (token dicabut)', r.status === 401);
  r = await gw('GET', '/nilai', { token: l1.access_token, device: DEV.mhs1 });
  check('access token tidak berlaku lagi setelah logout', r.status === 401, JSON.stringify(r));

  section('4.1 Gateway secret & verifikasi ulang di service');
  r = await call(NILAI, 'GET', '/nilai', { token: t.mhs1.access_token });
  check('akses langsung ke Service Nilai tanpa secret -> 403', r.status === 403);
  r = await call(TRANSKRIP, 'GET', '/transkrip/2210001', { token: t.mhs1.access_token, headers: { 'X-Gateway-Secret': 'tebakan' } });
  check('akses langsung ke Service Transkrip, secret salah -> 403', r.status === 403);
  r = await call(NILAI, 'GET', '/nilai', { headers: { 'X-Gateway-Secret': secrets.gatewaySecret } });
  check('secret benar tapi tanpa token -> 401', r.status === 401);
  r = await call(NILAI, 'GET', '/nilai', { token: 'abc.def.ghi', headers: { 'X-Gateway-Secret': secrets.gatewaySecret } });
  check('secret benar tapi token palsu -> 401', r.status === 401);
  const priv = fs.readFileSync(cfg.paths.privateKey);
  const sign = (claims, o = {}) => jwt.sign(claims, priv, { algorithm: 'RS256', issuer: cfg.jwt.issuer, audience: cfg.jwt.audience, ...o });
  const expired = sign({ sub: String(uid('mhs1')), role: 'mahasiswa' }, { expiresIn: -10 });
  r = await call(NILAI, 'GET', '/nilai', { token: expired, headers: { 'X-Gateway-Secret': secrets.gatewaySecret } });
  check('secret benar tapi token kedaluwarsa -> 401', r.status === 401);
  const forged = jwt.sign({ sub: String(uid('mhs1')), role: 'admin' }, 'kunci-palsu', { issuer: cfg.jwt.issuer, audience: cfg.jwt.audience });
  r = await call(TRANSKRIP, 'GET', '/transkrip/2210002', { token: forged, headers: { 'X-Gateway-Secret': secrets.gatewaySecret } });
  check('token dipalsukan (kunci salah) -> 401 di service', r.status === 401);
  const noneTok = Buffer.from('{"alg":"none"}').toString('base64url') + '.' + Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString('base64url') + '.';
  r = await gw('GET', '/transkrip/2210001', { token: noneTok, device: DEV.admin });
  check('token alg=none ditolak gateway -> 401', r.status === 401);
  r = await call(TRANSKRIP, 'POST', '/transkrip/sinkron', { token: t.mhs1.access_token, headers: { 'X-Gateway-Secret': secrets.gatewaySecret }, body: { entries: [] } });
  check('service menolak token user di /sinkron walau membawa secret -> 403', r.status === 403);
  r = await gw('GET', '/nilai');
  check('lewat gateway tanpa token -> 401', r.status === 401);
  r = await gw('GET', '/nilai', { token: expired, device: DEV.mhs1 });
  check('lewat gateway token kedaluwarsa -> 401', r.status === 401);

  section('4.3 Verifikasi konteks: device');
  const m1 = await login('mhs1');
  r = await gw('GET', '/nilai', { token: m1.access_token });
  check('request tanpa X-Device-ID -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: m1.access_token, device: 'DEV-ASING' });
  check('device tidak terdaftar -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: m1.access_token, device: DEV.mhs2 });
  check('device terdaftar milik user lain -> 403', r.status === 403);

  section('4.2 Kebijakan akses: GET /nilai');
  const m2 = await login('mhs2');
  r = await gw('GET', '/nilai', { token: m2.access_token, device: DEV.mhs2 });
  check('mahasiswa tidak melihat nilai yang belum final', r.status === 200 && r.json.count === 0, JSON.stringify(r.json));
  r = await gw('GET', '/nilai?nim=2210001', { token: m2.access_token, device: DEV.mhs2 });
  check('mahasiswa minta nilai NIM lain -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: t.admin.access_token, device: DEV.admin });
  check('admin tidak boleh melihat nilai -> 403', r.status === 403);
  r = await gw('GET', `/nilai?kelas_id=${K1}`, { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('dosen melihat kelas yang diampu', r.status === 200 && r.json.count === 3);
  r = await gw('GET', `/nilai?kelas_id=${K2}`, { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('dosen minta kelas yang tidak diampu -> 403', r.status === 403);
  r = await gw('GET', '/nilai', { token: t.dosen2.access_token, device: DEV.dosen2 });
  check('dosen tanpa filter hanya mendapat kelas yang diampu', r.status === 200 && r.json.count === 3 && r.json.data.every((x) => x.kelas_id === K2));

  section('4.2 Kebijakan akses: PUT /nilai/:id');
  const n1m1 = nilaiId(K1, 'mhs1');
  r = await gw('PUT', `/nilai/${n1m1}`, { token: m2.access_token, device: DEV.mhs2, body: { nilai: 100 } });
  check('mahasiswa mengubah nilai -> 403', r.status === 403);
  r = await gw('PUT', `/nilai/${n1m1}`, { token: t.dosen2.access_token, device: DEV.dosen2, body: { nilai: 100 } });
  check('dosen non-pengampu mengubah nilai -> 403', r.status === 403);
  r = await gw('PUT', `/nilai/${n1m1}`, { token: t.dosen1.access_token, device: DEV.dosen1, body: { nilai: 88 } });
  check('dosen pengampu mengubah nilai -> 200', r.status === 200 && r.json.nilai === 88);
  r = await gw('PUT', `/nilai/${n1m1}`, { token: t.dosen1.access_token, device: DEV.dosen1, body: { nilai: 150 } });
  check('nilai di luar 0-100 ditolak service -> 422', r.status === 422);
  r = await gw('PUT', '/nilai/99999', { token: t.dosen1.access_token, device: DEV.dosen1, body: { nilai: 80 } });
  check('id nilai tidak ada -> 404', r.status === 404);

  section('4.3 Verifikasi konteks: jam akses (dapat dikonfigurasi)');
  const h = (new Date().getUTCHours() + 7) % 24;
  setHours(`${String((h + 2) % 24).padStart(2, '0')}:00`, `${String((h + 3) % 24).padStart(2, '0')}:00`);
  r = await gw('PUT', `/nilai/${n1m1}`, { token: t.dosen1.access_token, device: DEV.dosen1, body: { nilai: 77 } });
  check('ubah nilai di luar jam akses -> 403', r.status === 403 && /jam akses/i.test(r.json.error), JSON.stringify(r.json));
  r = await gw('POST', `/kelas/${K1}/finalisasi`, { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('finalisasi di luar jam akses -> 403', r.status === 403);
  r = await gw('GET', `/nilai?kelas_id=${K1}`, { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('membaca nilai tetap boleh di luar jam akses', r.status === 200);
  setHours('00:00', '24:00');
  r = await gw('PUT', `/nilai/${n1m1}`, { token: t.dosen1.access_token, device: DEV.dosen1, body: { nilai: 85 } });
  check('jam akses diubah via config tanpa restart -> kembali 200', r.status === 200);

  section('4.2 Kebijakan akses: finalisasi & sinkron transkrip');
  r = await gw('POST', `/kelas/${K1}/finalisasi`, { token: t.dosen2.access_token, device: DEV.dosen2 });
  check('dosen non-pengampu finalisasi -> 403', r.status === 403);
  r = await gw('POST', `/kelas/${K1}/finalisasi`, { token: m2.access_token, device: DEV.mhs2 });
  check('mahasiswa finalisasi -> 403', r.status === 403);
  r = await gw('GET', '/transkrip/2210001', { token: t.admin.access_token, device: DEV.admin });
  check('sebelum finalisasi transkrip masih kosong', r.status === 200 && r.json.jumlah_mk === 0);
  r = await gw('POST', `/kelas/${K1}/finalisasi`, { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('dosen pengampu finalisasi -> 200 + sinkron', r.status === 200 && r.json.sinkron && r.json.sinkron.upserted === 3, JSON.stringify(r));
  r = await gw('POST', `/kelas/${K1}/finalisasi`, { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('finalisasi ulang -> 409', r.status === 409);
  r = await gw('PUT', `/nilai/${n1m1}`, { token: t.dosen1.access_token, device: DEV.dosen1, body: { nilai: 50 } });
  check('ubah nilai yang sudah final -> 403', r.status === 403 && /final/i.test(r.json.error));
  const audSvc = db.prepare("SELECT * FROM audit_log WHERE subject='service-nilai' AND endpoint='POST /transkrip/sinkron'").get();
  check('panggilan antar-service lewat gateway tercatat di audit (subjek service)', audSvc && audSvc.result === 'allow' && audSvc.role === 'service');

  r = await gw('GET', '/nilai', { token: m1.access_token, device: DEV.mhs1 });
  check('setelah final, mahasiswa melihat nilainya sendiri saja', r.status === 200 && r.json.count === 1 && r.json.data[0].nim === '2210001' && r.json.data[0].final === true, JSON.stringify(r.json));
  r = await gw('GET', '/nilai', { token: m2.access_token, device: DEV.mhs2 });
  check('mahasiswa lain hanya melihat nilai miliknya yang sudah final', r.status === 200 && r.json.count === 1 && r.json.data[0].nim === '2210002');

  section('4.2 Kebijakan akses: GET /transkrip/:nim');
  r = await gw('GET', '/transkrip/2210001', { token: m1.access_token, device: DEV.mhs1 });
  check('mahasiswa melihat transkrip sendiri (berisi hasil sinkron)', r.status === 200 && r.json.jumlah_mk === 1 && r.json.entries[0].nilai === 85, JSON.stringify(r.json));
  r = await gw('GET', '/transkrip/2210002', { token: m1.access_token, device: DEV.mhs1 });
  check('mahasiswa melihat transkrip NIM lain -> 403', r.status === 403);
  r = await gw('GET', '/transkrip/2210002', { token: t.admin.access_token, device: DEV.admin });
  check('admin melihat transkrip semua NIM', r.status === 200 && r.json.nim === '2210002');
  r = await gw('GET', '/transkrip/2210002', { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('dosen melihat transkrip -> 403', r.status === 403);
  r = await gw('GET', '/transkrip/9999999', { token: t.admin.access_token, device: DEV.admin });
  check('NIM tidak ada -> 404', r.status === 404);

  section('4.2 Kebijakan akses: POST /transkrip/sinkron (hanya token service)');
  const body = { entries: [{ nim: '2210003', kelas_id: K2, kode: 'KP70031002', nama_kelas: 'Basis Data', nilai: 70 }] };
  for (const [u, tk] of [['mhs1', m1], ['dosen1', t.dosen1], ['admin', t.admin]]) {
    r = await gw('POST', '/transkrip/sinkron', { token: tk.access_token, device: DEV[u], body });
    check(`token user (${u}) ke /sinkron -> 403`, r.status === 403);
  }
  r = await gw('POST', '/transkrip/sinkron', { token: svcTok, body });
  check('token service ke /sinkron -> 200', r.status === 200);
  r = await gw('GET', '/nilai', { token: svcTok });
  check('token service ke endpoint lain -> 403', r.status === 403);
  r = await gw('GET', '/transkrip/2210001', { token: svcTok });
  check('token service membaca transkrip -> 403', r.status === 403);

  section('Default deny & pembatasan brute force');
  r = await gw('GET', '/admin/rahasia', { token: t.admin.access_token, device: DEV.admin });
  check('endpoint tidak dikenal -> ditolak (default deny)', r.status === 404);
  r = await gw('DELETE', '/nilai/1', { token: t.dosen1.access_token, device: DEV.dosen1 });
  check('method tidak diatur kebijakan -> ditolak', r.status === 404);
  for (let i = 0; i < 5; i++) await gw('POST', '/auth/login', { body: { username: 'mhs3', password: 'x' }, device: DEV.mhs3 });
  r = await gw('POST', '/auth/login', { body: { username: 'mhs3', password: PW.mhs3 }, device: DEV.mhs3 });
  check('5x gagal login -> akun dikunci sementara (429)', r.status === 429);

  r = await fetch(GW + '/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{rusak' });
  check('JSON rusak ke /auth -> 400', r.status === 400);
  r = await fetch(GW + '/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'a'.repeat(20000) }) });
  check('body terlalu besar -> 413', r.status === 413);
  check('penolakan JSON rusak/terlalu besar tercatat di audit',
    db.prepare("SELECT COUNT(*) c FROM audit_log WHERE reason IN ('Body JSON tidak valid','Body terlalu besar')").get().c === 2);

  section('4.4 Audit log');
  const total = db.prepare('SELECT COUNT(*) c FROM audit_log').get().c;
  const allow = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE result='allow'").get().c;
  const deny = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE result='deny'").get().c;
  check(`audit mencatat allow (${allow}) dan deny (${deny})`, allow > 10 && deny > 10 && allow + deny === total);
  const miss = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE ts IS NULL OR subject IS NULL OR endpoint IS NULL OR reason IS NULL OR reason=''").get().c;
  check('setiap entri punya waktu, subjek, endpoint, hasil, alasan', miss === 0);
  const dd = db.prepare("SELECT * FROM audit_log WHERE endpoint LIKE 'PUT /nilai/%' AND device IS NOT NULL LIMIT 1").get();
  check('audit mencatat device', !!dd);

  console.log(`\n${fail === 0 ? '\x1b[32m' : '\x1b[31m'}Hasil: ${pass} lulus, ${fail} gagal\x1b[0m`);
    db.close();
  await Promise.all(kids.map((k) => new Promise((res) => {
    if (k.exitCode !== null || k.signalCode) return res();
    k.once('exit', res); k.kill();
  })));
  try { fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch (_) { /* folder Temp, aman bila gagal dihapus */ }
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
