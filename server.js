const express = require('express');
const https = require('https');
const tls = require('tls');
const { URL } = require('url');

const app = express();
app.use(express.json({ limit: '10mb' }));

const VERSION = 'v4.1.0';
const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.proxy_secret || process.env.C6_PROXY_SECRET;

const C6_CERTIFICATE_RAW = process.env.C6_CERTIFICATE;
const C6_PRIVATE_KEY_RAW = process.env.C6_PRIVATE_KEY;
const C6_CERTIFICATE_B64 = process.env.C6_CERTIFICATE_B64;
const C6_PRIVATE_KEY_B64 = process.env.C6_PRIVATE_KEY_B64;

console.log(`[proxy ${VERSION}] ENV CHECK:`);
console.log('- PORT:', PORT);
console.log('- PROXY_SECRET set:', !!PROXY_SECRET);
console.log('- C6_CERTIFICATE set:', !!C6_CERTIFICATE_RAW, 'length:', (C6_CERTIFICATE_RAW || '').length);
console.log('- C6_PRIVATE_KEY set:', !!C6_PRIVATE_KEY_RAW, 'length:', (C6_PRIVATE_KEY_RAW || '').length);
console.log('- C6_CERTIFICATE_B64 set:', !!C6_CERTIFICATE_B64, 'length:', (C6_CERTIFICATE_B64 || '').length);
console.log('- C6_PRIVATE_KEY_B64 set:', !!C6_PRIVATE_KEY_B64, 'length:', (C6_PRIVATE_KEY_B64 || '').length);

function chunk64(value) {
  const lines = [];
  for (let i = 0; i < value.length; i += 64) {
    lines.push(value.slice(i, i + 64));
  }
  return lines.join('\n');
}

function detectPemType(content, fallback) {
  if (!content) return fallback;
  const normalized = String(content).replace(/\\n/g, '\n');
  const match = normalized.match(/-----BEGIN ([^-]+)-----/);
  return match?.[1]?.trim() || fallback;
}

function loadPEM(rawVar, b64Var) {
  if (b64Var) {
    try {
      return Buffer.from(String(b64Var).trim(), 'base64').toString('utf8').trim();
    } catch (error) {
      console.error('[pem] Failed to decode Base64 PEM:', error?.message || error);
    }
  }

  if (rawVar) {
    return String(rawVar).replace(/\\n/g, '\n').trim();
  }

  return null;
}

// Robust PEM formatter:
// - supports escaped newlines
// - keeps original BEGIN/END type when available
// - strips metadata lines like "Proc-Type"/"DEK-Info"
function formatPEM(content, fallbackType) {
  if (!content) return null;

  const normalized = String(content).replace(/\\n/g, '\n').trim();
  const detectedType = detectPemType(normalized, fallbackType);

  const beginMatch = normalized.match(/-----BEGIN [^-]+-----/);
  const endMatch = normalized.match(/-----END [^-]+-----/);

  if (beginMatch && endMatch) {
    const beginIndex = normalized.indexOf(beginMatch[0]) + beginMatch[0].length;
    const endIndex = normalized.indexOf(endMatch[0]);
    const middle = normalized.slice(beginIndex, endIndex);

    const base64Lines = middle
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .filter((line) => !line.includes(':'))
      .filter((line) => /^[A-Za-z0-9+/=]+$/.test(line));

    const merged = base64Lines.join('');
    if (!merged) return null;

    return `-----BEGIN ${detectedType}-----\n${chunk64(merged)}\n-----END ${detectedType}-----`;
  }

  // Raw base64 or one-line value without headers
  const raw = normalized.replace(/[^A-Za-z0-9+/=]/g, '');
  if (!raw) return null;

  return `-----BEGIN ${detectedType}-----\n${chunk64(raw)}\n-----END ${detectedType}-----`;
}

const C6_CERTIFICATE = loadPEM(C6_CERTIFICATE_RAW, C6_CERTIFICATE_B64);
const C6_PRIVATE_KEY = loadPEM(C6_PRIVATE_KEY_RAW, C6_PRIVATE_KEY_B64);

const keyType = detectPemType(C6_PRIVATE_KEY, 'PRIVATE KEY');
const certType = detectPemType(C6_CERTIFICATE, 'CERTIFICATE');

const formattedCert = formatPEM(C6_CERTIFICATE, certType);
const formattedKey = formatPEM(C6_PRIVATE_KEY, keyType);

let secureContextReady = false;
let secureContextError = null;

if (formattedCert && formattedKey) {
  try {
    tls.createSecureContext({ cert: formattedCert, key: formattedKey });
    secureContextReady = true;
    console.log('mTLS certificates formatted successfully');
    console.log('- Cert type:', certType);
    console.log('- Key type:', keyType);
  } catch (error) {
    secureContextError = error instanceof Error ? error.message : String(error);
    console.error('mTLS secure context validation failed:', secureContextError);
  }
} else {
  console.log('WARNING: mTLS certificates NOT available');
}

function makeHTTPSRequest(url, method, headers, body, cert, key) {
  return new Promise(function(resolve, reject) {
    const parsed = new URL(url);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: method,
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers),
      cert: cert,
      key: key,
      rejectUnauthorized: true,
    };

    console.log('[mtls] Request to:', parsed.hostname, parsed.pathname);

    const req = https.request(options, function(res) {
      let data = '';
      res.on('data', function(chunk) { data += chunk; });
      res.on('end', function() {
        const responseHeaders = {};
        Object.keys(res.headers).forEach(function(k) {
          responseHeaders[k] = res.headers[k];
        });
        resolve({
          status: res.statusCode,
          headers: responseHeaders,
          body: data,
        });
      });
    });

    req.on('error', function(err) {
      console.error('[mtls] Request error:', err.message);
      reject(err);
    });

    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

function authenticate(req, res, next) {
  const authHeader = req.headers['x-proxy-secret'];
  if (!PROXY_SECRET || authHeader !== PROXY_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/health', function(req, res) {
  const envNames = Object.keys(process.env).filter(function(k) {
    return k.indexOf('C6') >= 0 || k.indexOf('PROXY') >= 0 || k.indexOf('proxy') >= 0;
  });

  res.json({
    status: 'ok',
    mtls: !!(formattedCert && formattedKey),
    tls_ready: secureContextReady,
    tls_error: secureContextError,
    cert_type: certType,
    key_type: keyType,
    env_keys: envNames,
    cert_len: (C6_CERTIFICATE_RAW || '').length,
    key_len: (C6_PRIVATE_KEY_RAW || '').length,
    cert_b64_len: (C6_CERTIFICATE_B64 || '').length,
    key_b64_len: (C6_PRIVATE_KEY_B64 || '').length,
    cert_formatted_len: (formattedCert || '').length,
    key_formatted_len: (formattedKey || '').length,
    timestamp: new Date().toISOString()
  });
});

app.post('/proxy', authenticate, async function(req, res) {
  try {
    const url = req.body.url;
    const method = req.body.method || 'POST';
    const headers = req.body.headers || {};
    const body = req.body.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    if (!formattedCert || !formattedKey) {
      return res.status(500).json({ error: 'mTLS certificates not configured' });
    }

    if (!secureContextReady) {
      return res.status(500).json({ error: `mTLS certificate/key invalid: ${secureContextError || 'unknown error'}` });
    }

    console.log('[proxy] ' + method + ' ' + url);

    const result = await makeHTTPSRequest(url, method, headers, body, formattedCert, formattedKey);

    console.log('[proxy] Response: ' + result.status);

    res.status(result.status).json(result);
  } catch (error) {
    console.error('[proxy] Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, function() {
  console.log('C6 mTLS Proxy running on port ' + PORT);
});
