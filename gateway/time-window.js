'use strict';
const fs = require('fs');
const cfg = require('../shared/config');

const DEFAULT = { enabled: true, start: '07:00', end: '21:00', timezone: 'Asia/Jakarta' };

function loadAccessHours() {
  try {
    const j = JSON.parse(fs.readFileSync(cfg.paths.policyConfig, 'utf8'));
    return { ...DEFAULT, ...(j.access_hours || {}) };
  } catch (_) {
    return DEFAULT; // config rusak/hilang -> pakai default yang aman
  }
}
const toMin = (s) => { const [h, m] = String(s).split(':').map(Number); return h * 60 + (m || 0); };

function localMinutes(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone, hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(date);
  const h = Number(parts.find((p) => p.type === 'hour').value) % 24;
  const m = Number(parts.find((p) => p.type === 'minute').value);
  return h * 60 + m;
}

/** Jam akses: start <= sekarang < end. Mendukung rentang yang melewati tengah malam. */
function checkAccessHours(now = new Date()) {
  const c = loadAccessHours();
  if (!c.enabled) return { ok: true, info: 'pembatasan jam akses nonaktif' };
  const t = localMinutes(now, c.timezone);
  const s = toMin(c.start); const e = toMin(c.end);
  const ok = s <= e ? (t >= s && t < e) : (t >= s || t < e);
  const hhmm = `${String(Math.floor(t / 60)).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
  return { ok, info: `sekarang ${hhmm} ${c.timezone}, jam akses ${c.start}-${c.end}` };
}
module.exports = { checkAccessHours };
