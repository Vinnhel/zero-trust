'use strict';
const db = require('./db');
const { checkAccessHours } = require('./time-window');

const q = {
  user: db.prepare('SELECT id, username, role, nim FROM users WHERE id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  kelas: db.prepare('SELECT id, dosen_id FROM kelas WHERE id = ?'),
  nilaiKelas: db.prepare(
    'SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'
  ),
};

const allow = (reason) => ({ allow: true, reason, status: 200 });
const deny = (reason, status = 403) => ({ allow: false, reason, status });

function isDeviceRegistered(userId, deviceId) {
  return !!deviceId && !!q.device.get(userId, deviceId);
}

function evaluateLogin(user, deviceId) {
  if (!deviceId) return deny('Header X-Device-ID wajib');
  if (!isDeviceRegistered(user.id, deviceId)) return deny(`Device '${deviceId}' tidak terdaftar untuk user ini`);
  return allow('Kredensial valid dan device terdaftar');
}

function intParam(v) {
  return typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : null;
}

const rules = [
  {
    method: 'GET', re: /^\/nilai\/?$/,
    decide(s, m, ctx) {
      const { nim, kelas_id: kelasId } = ctx.query;
      if ([nim, kelasId].some((v) => v !== undefined && typeof v !== 'string')) return deny('Parameter query tidak valid', 400);
      if (s.user.role === 'mahasiswa') {
        if (nim !== undefined && nim !== s.user.nim) return deny('Mahasiswa hanya boleh melihat nilai miliknya sendiri');
        return allow('Mahasiswa melihat nilai miliknya sendiri');
      }
      if (s.user.role === 'dosen') {
        if (kelasId !== undefined) {
          const id = intParam(kelasId);
          if (id === null) return deny('kelas_id tidak valid', 400);
          const k = q.kelas.get(id);
          if (!k || k.dosen_id !== s.user.id) return deny('Dosen hanya boleh melihat kelas yang diampunya');
        }
        return allow('Dosen melihat nilai kelas yang diampunya');
      }
      return deny(`Role '${s.user.role}' tidak diizinkan melihat nilai`);
    },
  },
  {
    method: 'PUT', re: /^\/nilai\/(\d+)\/?$/,
    decide(s, m) {
      if (s.user.role !== 'dosen') return deny(`Role '${s.user.role}' tidak boleh mengubah nilai`);
      const n = q.nilaiKelas.get(Number(m[1]));
      if (!n) return deny('Data nilai tidak ditemukan', 404);
      if (n.dosen_id !== s.user.id) return deny('Dosen bukan pengampu kelas ini');
      if (n.final) return deny('Nilai sudah difinalisasi, tidak dapat diubah');
      const t = checkAccessHours();
      if (!t.ok) return deny(`Di luar jam akses (${t.info})`);
      return allow('Dosen pengampu mengubah nilai yang belum final dalam jam akses');
    },
  },
  {
    method: 'POST', re: /^\/kelas\/(\d+)\/finalisasi\/?$/,
    decide(s, m) {
      if (s.user.role !== 'dosen') return deny(`Role '${s.user.role}' tidak boleh memfinalisasi nilai`);
      const k = q.kelas.get(Number(m[1]));
      if (!k) return deny('Kelas tidak ditemukan', 404);
      if (k.dosen_id !== s.user.id) return deny('Dosen bukan pengampu kelas ini');
      const t = checkAccessHours();
      if (!t.ok) return deny(`Di luar jam akses (${t.info})`);
      return allow('Dosen pengampu memfinalisasi kelas dalam jam akses');
    },
  },
  {
    method: 'GET', re: /^\/transkrip\/(?!sinkron\/?$)([A-Za-z0-9_-]+)\/?$/,
    decide(s, m) {
      if (s.user.role === 'admin') return allow('Admin melihat transkrip seluruh mahasiswa');
      if (s.user.role === 'mahasiswa') {
        if (m[1] !== s.user.nim) return deny('Mahasiswa hanya boleh melihat transkrip NIM sendiri');
        return allow('Mahasiswa melihat transkrip NIM sendiri');
      }
      return deny(`Role '${s.user.role}' tidak diizinkan melihat transkrip`);
    },
  },
  {
    method: 'POST', re: /^\/transkrip\/sinkron\/?$/, serviceOnly: true,
    decide(s) {
      if (s.type !== 'service') return deny('Endpoint sinkron hanya untuk token service; token user ditolak');
      return allow('Token service Service Nilai memanggil sinkron transkrip');
    },
  },
];

function decide(subject, ctx) {
  const rule = rules.find((r) => r.method === ctx.method && r.re.test(ctx.path));
  if (!rule) return deny('Tidak ada kebijakan untuk endpoint ini (default deny)', 404);

  const m = rule.re.exec(ctx.path);
  if (subject.type === 'service') {
    // Token service hanya sah untuk endpoint sinkron
    if (!rule.serviceOnly) return deny('Token service hanya boleh memanggil POST /transkrip/sinkron');
    if (subject.sub !== subject.expectedClientId) return deny('Client ID pada token service tidak dikenal');
    return rule.decide(subject, m, ctx);
  }

  // Subjek user: atribut dibaca dari DB, jangan percaya isi token saja
  const user = q.user.get(Number(subject.sub));
  if (!user) return deny('User tidak ditemukan', 401);
  if (user.role !== subject.tokenRole) return deny('Role pada token tidak sesuai dengan data di database', 401);
  return rule.decide({ ...subject, user }, m, ctx);
}

module.exports = { decide, evaluateLogin, isDeviceRegistered };
