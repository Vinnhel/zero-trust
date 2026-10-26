'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const CONFIG_DIR = process.env.CONFIG_DIR ? path.resolve(process.env.CONFIG_DIR) : path.join(ROOT, 'config');

const paths = {
  db: path.join(DATA_DIR, 'app.db'),
  privateKey: path.join(DATA_DIR, 'keys', 'private.pem'), // hanya dibaca gateway
  publicKey: path.join(DATA_DIR, 'keys', 'public.pem'),   // dibaca service untuk verifikasi
  secrets: path.join(DATA_DIR, 'secrets.json'),
  policyConfig: path.join(CONFIG_DIR, 'policy.config.json'),
};

const ports = {
  gateway: Number(process.env.GATEWAY_PORT) || 3000,
  nilai: Number(process.env.NILAI_PORT) || 3001,
  transkrip: Number(process.env.TRANSKRIP_PORT) || 3002,
};

const urls = {
  gateway: process.env.GATEWAY_URL || `http://127.0.0.1:${ports.gateway}`,
  nilai: process.env.NILAI_URL || `http://127.0.0.1:${ports.nilai}`,
  transkrip: process.env.TRANSKRIP_URL || `http://127.0.0.1:${ports.transkrip}`,
};

const jwtOpts = {
  issuer: 'zt-gateway',
  audience: 'zt-services',
  accessTtlSec: 10 * 60,        // access token user: 10 menit
  serviceTtlSec: 5 * 60,        // token service: 5 menit
  refreshTtlMs: 24 * 60 * 60 * 1000, // refresh token: 1 hari
};

function loadSecrets() {
  let f = {};
  try { f = JSON.parse(fs.readFileSync(paths.secrets, 'utf8')); } catch (_) { /* belum setup */ }
  const s = {
    gatewaySecret: process.env.GATEWAY_SECRET || f.gateway_secret,
    serviceClientId: process.env.SERVICE_CLIENT_ID || f.service_client_id,
    serviceClientSecret: process.env.SERVICE_CLIENT_SECRET || f.service_client_secret,
  };
  if (!s.gatewaySecret) {
    throw new Error('Secret belum ada. Jalankan "npm run setup" terlebih dahulu.');
  }
  return s;
}

module.exports = {
  ROOT, DATA_DIR, CONFIG_DIR, paths, ports, urls, jwt: jwtOpts, loadSecrets,
  host: process.env.HOST || '127.0.0.1',
};
