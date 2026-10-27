'use strict';
const { spawn } = require('child_process');
const path = require('path');
const root = path.resolve(__dirname, '..');
const procs = [
  ['gateway ', 'gateway/index.js', '\x1b[32m'],
  ['nilai   ', 'service-nilai/index.js', '\x1b[36m'],
  ['transkrip', 'service-transkrip/index.js', '\x1b[35m'],
];
const children = procs.map(([name, file, color]) => {
  const c = spawn(process.execPath, [path.join(root, file)], { cwd: root, env: process.env });
  const pipe = (s) => s.on('data', (d) => String(d).split('\n').filter(Boolean)
    .forEach((l) => console.log(`${color}[${name.trim()}]\x1b[0m ${l}`)));
  pipe(c.stdout); pipe(c.stderr);
  c.on('exit', (code) => { console.log(`[${name.trim()}] berhenti (kode ${code})`); shutdown(); });
  return c;
});
function shutdown() { children.forEach((c) => c.kill()); setTimeout(() => process.exit(0), 200); }
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
