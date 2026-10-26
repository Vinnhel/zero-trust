'use strict';
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cfg = require('../shared/config');
const auth = require('./auth');
const { audit } = require('./audit');
const { pep, gatewaySecret } = require('./pep');

const app = express();
app.disable('x-powered-by');

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.use('/auth', express.json({ limit: '10kb' }), auth.router);

// Semua selain /auth wajib melewati PEP
app.use(pep);

function proxyTo(target, pathFilter) {
  return createProxyMiddleware({
    target, changeOrigin: true, pathFilter,
    on: {
      // Hanya gateway yang tahu secret ini. Nilai kiriman client (jika ada) ditimpa.
      proxyReq: (proxyReq) => proxyReq.setHeader('X-Gateway-Secret', gatewaySecret),
      error: (err, _req, res) => {
        console.error('Proxy error:', err.message);
        if (res.writeHead && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Service tujuan tidak dapat dihubungi' }));
        }
      },
    },
  });
}
app.use(proxyTo(cfg.urls.nilai, ['/nilai', '/kelas']));
app.use(proxyTo(cfg.urls.transkrip, ['/transkrip']));

app.use((err, req, res, _next) => {
  const known = { 'entity.parse.failed': [400, 'Body JSON tidak valid'], 'entity.too.large': [413, 'Body terlalu besar'] }[err.type];
  const [status, reason] = known || [500, 'Kesalahan internal pada gateway'];
  if (!known) console.error(err);
  audit({ subject: 'anonymous', method: req.method, path: req.originalUrl.split('?')[0], device: req.get('x-device-id'), result: 'deny', reason });
  res.status(status).json({ error: reason });
});

app.listen(cfg.ports.gateway, cfg.host, () => {
  console.log(`[gateway] PEP berjalan di http://${cfg.host}:${cfg.ports.gateway}`);
});
