'use strict';
const { openDb } = require('../shared/db');
const n = Number(process.argv[2]) || 30;
const rows = openDb().prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(n).reverse();
console.table(rows.map((r) => ({
  waktu: r.ts.replace('T', ' ').slice(0, 19), subjek: r.subject, role: r.role, endpoint: r.endpoint,
  device: r.device, hasil: r.result, alasan: r.reason,
})));
