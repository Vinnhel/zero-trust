'use strict';
const db = require('./db');
const ins = db.prepare(
  'INSERT INTO audit_log(ts,subject,role,endpoint,device,result,reason) VALUES (?,?,?,?,?,?,?)'
);

function audit({ subject, role, method, path, device, result, reason }) {
  const ts = new Date().toISOString();
  ins.run(ts, subject || 'anonymous', role || null, `${method} ${path}`, device || null, result, reason);
  console.log(`[AUDIT] ${ts} ${result.toUpperCase().padEnd(5)} ${subject || 'anonymous'}(${role || '-'}) ${method} ${path} dev=${device || '-'} :: ${reason}`);
}
module.exports = { audit };
