'use strict';
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cfg = require('../shared/config');
const policy = require('./policy');
const { audit } = require('./audit');
const { revokeFamilyActive } = require('./auth');

const publicKey = fs.readFileSync(cfg.paths.publicKey);
const secrets = cfg.loadSecrets();

async function pep(req, res, next) {
  const base = { method: req.method, path: req.path, device: req.get('x-device-id') };
  let subject = 'anonymous'; let role = null;
  const finish = (status, reason) => {
    const ok = status < 400;
    audit({ ...base, subject, role, result: ok ? 'allow' : 'deny', reason });
    if (!ok) return res.status(status).json({ error: reason });
    return next();
  };

  try {
    // 1. Token
    const m = /^Bearer (.+)$/i.exec(req.get('authorization') || '');
    if (!m) return finish(401, 'Access token tidak ada');
    let claims;
    try {
      claims = jwt.verify(m[1], publicKey, { algorithms: ['RS256'], issuer: cfg.jwt.issuer, audience: cfg.jwt.audience });
    } catch (e) {
      return finish(401, e.name === 'TokenExpiredError' ? 'Access token kedaluwarsa' : 'Access token tidak valid');
    }
    subject = String(claims.sub); role = claims.role;

    let sub;
    if (claims.role === 'service') {
      // Token service: tanpa device, tanpa sesi user
      sub = { type: 'service', sub: String(claims.sub), tokenRole: 'service', expectedClientId: secrets.serviceClientId };
    } else {
      // 2. Sesi aktif
      if (!claims.sid || !revokeFamilyActive.get(claims.sid, Date.now())) {
        return finish(401, 'Sesi sudah berakhir (logout/dicabut), silakan login ulang');
      }
      // 3. Device
      const deviceId = base.device;
      if (!deviceId) return finish(403, 'Header X-Device-ID wajib untuk request user');
      if (!policy.isDeviceRegistered(Number(claims.sub), deviceId)) {
        return finish(403, `Device '${deviceId}' tidak terdaftar untuk user ini`);
      }
      if (claims.did !== deviceId) return finish(403, 'Device tidak sama dengan device saat login');
      sub = { type: 'user', sub: String(claims.sub), tokenRole: claims.role };
    }

    // 4. Keputusan Policy Engine
    const d = policy.decide(sub, { method: req.method, path: req.path, query: req.query });
    if (sub.type === 'user') {
      const u = require('./db').prepare('SELECT username FROM users WHERE id = ?').get(Number(sub.sub));
      if (u) subject = u.username;
    }
    return finish(d.allow ? 200 : d.status, d.reason);
  } catch (err) {
    console.error('PEP error:', err);
    return finish(500, 'Kesalahan internal pada gateway (fail-closed)');
  }
}

module.exports = { pep, gatewaySecret: secrets.gatewaySecret };
