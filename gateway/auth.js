'use strict';
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cfg = require('../shared/config');
const db = require('./db');
const { audit } = require('./audit');
const policy = require('./policy');

const privateKey = fs.readFileSync(cfg.paths.privateKey);
const router = express.Router();

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10); // supaya waktu respons user tak dikenal ~ sama

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  rtByHash: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
  rtInsert: db.prepare(
    'INSERT INTO refresh_tokens(family,user_id,device_id,token_hash,expires_at,created_at) VALUES (?,?,?,?,?,?)'
  ),
  rtRevoke: db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL'),
  rtRevokeFamily: db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family = ? AND revoked_at IS NULL'),
  client: db.prepare('SELECT * FROM service_clients WHERE client_id = ?'),
};

function signToken(claims, ttlSec) {
  return jwt.sign(claims, privateKey, {
    algorithm: 'RS256', expiresIn: ttlSec, issuer: cfg.jwt.issuer, audience: cfg.jwt.audience, jwtid: crypto.randomUUID(),
  });
}

function out(req, res, status, reason, { subject = 'anonymous', role = null, body } = {}) {
  const ok = status < 400;
  audit({
    subject, role, method: req.method, path: req.originalUrl.split('?')[0],
    device: req.get('x-device-id'), result: ok ? 'allow' : 'deny', reason,
  });
  res.status(status).json(body || (ok ? { message: reason } : { error: reason }));
}

function newRefreshToken(userId, deviceId, family, expiresAt) {
  const token = crypto.randomBytes(48).toString('hex');
  q.rtInsert.run(family, userId, deviceId, sha256(token), expiresAt, new Date().toISOString());
  return token;
}

function tokenResponse(user, deviceId, family, refreshToken) {
  return {
    token_type: 'Bearer',
    access_token: signToken({ sub: String(user.id), role: user.role, did: deviceId, sid: family }, cfg.jwt.accessTtlSec),
    expires_in: cfg.jwt.accessTtlSec,
    refresh_token: refreshToken,
    refresh_expires_in: cfg.jwt.refreshTtlMs / 1000,
    role: user.role,
  };
}

const MAX_FAIL = 5; const LOCK_MS = 5 * 60 * 1000;
const fails = new Map();
const failKey = (u) => String(u).toLowerCase();
function lockedFor(u) {
  const f = fails.get(failKey(u));
  return f && f.lockedUntil > Date.now() ? Math.ceil((f.lockedUntil - Date.now()) / 1000) : 0;
}
function recordFail(u) {
  const k = failKey(u); const f = fails.get(k) || { n: 0, lockedUntil: 0 };
  f.n += 1;
  if (f.n >= MAX_FAIL) { f.lockedUntil = Date.now() + LOCK_MS; f.n = 0; }
  fails.set(k, f);
}

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const deviceId = req.get('x-device-id');
  if (typeof username !== 'string' || typeof password !== 'string') {
    return out(req, res, 400, 'Body harus berisi username dan password');
  }
  const wait = lockedFor(username);
  if (wait) return out(req, res, 429, `Terlalu banyak percobaan gagal, coba lagi ${wait} detik lagi`, { subject: username });

  const user = q.userByName.get(username);
  const valid = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH) && !!user;
  if (!valid) {
    recordFail(username);
    return out(req, res, 401, user ? 'Password salah' : 'User tidak ditemukan', { subject: username });
  }

  const d = policy.evaluateLogin(user, deviceId);
  if (!d.allow) return out(req, res, 403, d.reason, { subject: username, role: user.role });

  fails.delete(failKey(username));
  const family = crypto.randomUUID();
  const rt = newRefreshToken(user.id, deviceId, family, Date.now() + cfg.jwt.refreshTtlMs);
  out(req, res, 200, d.reason, { subject: username, role: user.role, body: tokenResponse(user, deviceId, family, rt) });
});

router.post('/refresh', (req, res) => {
  const rt = (req.body || {}).refresh_token;
  const deviceId = req.get('x-device-id');
  if (typeof rt !== 'string') return out(req, res, 400, 'refresh_token wajib diisi');

  const row = q.rtByHash.get(sha256(rt));
  if (!row) return out(req, res, 401, 'Refresh token tidak dikenal');
  const user = q.userById.get(row.user_id);
  const who = { subject: user ? user.username : String(row.user_id), role: user && user.role };

  if (row.revoked_at) {
    // Token lama dipakai lagi => kemungkinan dicuri (assume breach): cabut seluruh sesi.
    q.rtRevokeFamily.run(Date.now(), row.family);
    return out(req, res, 401, 'Refresh token sudah dicabut/dipakai ulang; seluruh sesi dicabut', who);
  }
  if (row.expires_at < Date.now()) return out(req, res, 401, 'Refresh token kedaluwarsa', who);
  if (!user) return out(req, res, 401, 'User tidak ditemukan', who);
  if (deviceId !== row.device_id || !policy.isDeviceRegistered(user.id, deviceId)) {
    return out(req, res, 403, 'Device tidak sesuai/tidak terdaftar untuk refresh token ini', who);
  }

  // Rotasi: token lama dicabut, token baru diterbitkan (kedaluwarsa sesi tetap sama)
  const rotate = db.transaction(() => {
    q.rtRevoke.run(Date.now(), row.id);
    return newRefreshToken(user.id, deviceId, row.family, row.expires_at);
  });
  out(req, res, 200, 'Refresh token valid, token baru diterbitkan', { ...who, body: tokenResponse(user, deviceId, row.family, rotate()) });
});

router.post('/logout', (req, res) => {
  const rt = (req.body || {}).refresh_token;
  if (typeof rt !== 'string') return out(req, res, 400, 'refresh_token wajib diisi');
  const row = q.rtByHash.get(sha256(rt));
  if (!row || row.revoked_at || row.expires_at < Date.now()) {
    return out(req, res, 401, 'Refresh token tidak valid atau sudah dicabut');
  }
  const user = q.userById.get(row.user_id);
  q.rtRevokeFamily.run(Date.now(), row.family); // sesi berakhir: access token ikut tidak berlaku (dicek PEP via sid)
  out(req, res, 200, 'Logout berhasil, refresh token dicabut', { subject: user && user.username, role: user && user.role });
});

router.post('/service', (req, res) => {
  const { client_id: clientId, client_secret: clientSecret } = req.body || {};
  if (typeof clientId !== 'string' || typeof clientSecret !== 'string') {
    return out(req, res, 400, 'client_id dan client_secret wajib diisi');
  }
  const c = q.client.get(clientId);
  if (!(bcrypt.compareSync(clientSecret, c ? c.secret_hash : DUMMY_HASH) && c)) {
    return out(req, res, 401, 'Client ID atau secret tidak valid', { subject: clientId, role: 'service' });
  }
  const accessToken = signToken({ sub: c.client_id, role: 'service' }, cfg.jwt.serviceTtlSec);
  out(req, res, 200, 'Token service diterbitkan', {
    subject: c.client_id, role: 'service',
    body: { token_type: 'Bearer', access_token: accessToken, expires_in: cfg.jwt.serviceTtlSec, role: 'service' },
  });
});

router.use((req, res) => out(req, res, 404, 'Endpoint /auth tidak dikenal'));

module.exports = { router, revokeFamilyActive: db.prepare(
  'SELECT 1 FROM refresh_tokens WHERE family = ? AND revoked_at IS NULL AND expires_at > ? LIMIT 1'
) };
