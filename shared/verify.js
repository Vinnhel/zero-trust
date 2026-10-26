'use strict';
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('./config');

const secrets = cfg.loadSecrets();
const publicKey = fs.readFileSync(cfg.paths.publicKey);

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function gatewayGuard(req, res, next) {
  const got = req.get('x-gateway-secret');
  if (!got || !safeEqual(got, secrets.gatewaySecret)) {
    console.warn(`[DITOLAK] ${req.method} ${req.originalUrl} : X-Gateway-Secret tidak ada/salah (akses langsung)`);
    return res.status(403).json({ error: 'Akses langsung ditolak: X-Gateway-Secret tidak valid' });
  }
  next();
}

function tokenGuard(req, res, next) {
  const m = /^Bearer (.+)$/i.exec(req.get('authorization') || '');
  if (!m) return res.status(401).json({ error: 'Access token tidak ada' });
  try {
    const c = jwt.verify(m[1], publicKey, {
      algorithms: ['RS256'], issuer: cfg.jwt.issuer, audience: cfg.jwt.audience,
    });
    req.auth = { sub: String(c.sub), role: c.role };
    next();
  } catch (e) {
    const reason = e.name === 'TokenExpiredError' ? 'Token kedaluwarsa' : 'Token tidak valid';
    console.warn(`[DITOLAK] ${req.method} ${req.originalUrl} : ${reason}`);
    return res.status(401).json({ error: reason });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return res.status(403).json({ error: `Role '${req.auth && req.auth.role}' tidak diizinkan di service ini` });
    }
    next();
  };
}

function jsonErrorHandler(err, req, res, _next) {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON tidak valid' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Body terlalu besar' });
  console.error(err);
  res.status(500).json({ error: 'Kesalahan internal' });
}

module.exports = { gatewayGuard, tokenGuard, requireRole, jsonErrorHandler, secrets };
