const express = require('express');
const https = require('https');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET;
const C6_CERTIFICATE = process.env.C6_CERTIFICATE;
const C6_PRIVATE_KEY = process.env.C6_PRIVATE_KEY;

function formatPEM(content, type) {
  const cleaned = content
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\\n/g, '')
    .replace(/\s+/g, '');
  const lines = [];
  for (let i = 0; i < cleaned.length; i += 64) {
    lines.push(cleaned.substring(i, i + 64));
  }
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

function createMTLSAgent() {
  if (!C6_CERTIFICATE || !C6_PRIVATE_KEY) throw new Error('Certs not configured');
  return new https.Agent({
    cert: formatPEM(C6_CERTIFICATE, 'CERTIFICATE'),
    key: formatPEM(C6_PRIVATE_KEY, 'RSA PRIVATE KEY'),
    rejectUnauthorized: true,
  });
}

let mtlsAgent;
try { mtlsAgent = createMTLSAgent(); console.log('✅ mTLS Agent OK'); }
catch (err) { console.error('❌ mTLS failed:', err.message); }

function authenticate(req, res, next) {
  if (!PROXY_SECRET || req.headers['x-proxy-secret'] !== PROXY_SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.get('/health', (req, res) => res.json({ status: 'ok', mtls: !!mtlsAgent }));

app.post('/p
