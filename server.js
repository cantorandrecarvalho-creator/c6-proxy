const express = require('express');
const https = require('https');
const { URL } = require('url');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.proxy_secret || process.env.C6_PROXY_SECRET;
const C6_CERTIFICATE = process.env.C6_CERTIFICATE;
const C6_PRIVATE_KEY = process.env.C6_PRIVATE_KEY;

console.log('=== C6 mTLS Proxy Starting ===');
console.log('PORT:', PORT);
console.log('PROXY_SECRET configured:', !!PROXY_SECRET);
console.log('C6_CERTIFICATE length:', (C6_CERTIFICATE || '').length);
console.log('C6_PRIVATE_KEY length:', (C6_PRIVATE_KEY || '').length);

// Always strip and rebuild PEM to avoid invisible chars, wrong line breaks, etc.
function formatPEM(content, type) {
  if (!content) return null;
  var cleaned = content
    .replace(/\\n/g, '\n')
    .replace(/-----BEGIN[^-]*-----/g, '')
    .replace(/-----END[^-]*-----/g, '')
    .replace(/[\s\r\n]+/g, '');
  if (cleaned.length === 0) return null;
  var lines = [];
  for (var i = 0; i < cleaned.length; i += 64) {
    lines.push(cleaned.substring(i, i + 64));
  }
  return '-----BEGIN ' + type + '-----\n' + lines.join('\n') + '\n-----END ' + type + '-----';
}

// Try both RSA PRIVATE KEY and PRIVATE KEY formats
var formattedCert = formatPEM(C6_CERTIFICATE, 'CERTIFICATE');
var formattedKeyRSA = formatPEM(C6_PRIVATE_KEY, 'RSA PRIVATE KEY');
var formattedKeyPKCS8 = formatPEM(C6_PRIVATE_KEY, 'PRIVATE KEY');

// Detect which key format works
var formattedKey = null;
var keyFormat = 'none';

if (C6_PRIVATE_KEY) {
  if (C6_PRIVATE_KEY.indexOf('RSA PRIVATE KEY') >= 0) {
    formattedKey = formattedKeyRSA;
    keyFormat = 'RSA';
  } else if (C6_PRIVATE_KEY.indexOf('PRIVATE KEY') >= 0) {
    formattedKey = formattedKeyPKCS8;
    keyFormat = 'PKCS8';
  } else {
    // No header found, try RSA first (most common for C6)
    formattedKey = formattedKeyRSA;
    keyFormat = 'RSA (guessed)';
  }
}

if (formattedCert && formattedKey) {
  console.log('mTLS certificates formatted OK');
  console.log('Key format:', keyFormat);
  console.log('Cert base64 length:', formattedCert.replace(/-----[^-]*-----/g, '').replace(/\s/g, '').length);
  console.log('Key base64 length:', formattedKey.replace(/-----[^-]*-----/g, '').replace(/\s/g, '').length);
} else {
  console.log('WARNING: mTLS certificates NOT available');
  console.log('Cert OK:', !!formattedCert, '| Key OK:', !!formattedKey);
}

function makeHTTPSRequest(url, method, headers, body, cert, key) {
  return new Promise(function(resolve, reject) {
    var parsed = new URL(url);
    var options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: method,
      headers: Object.assign({}, headers),
      cert: cert,
      key: key,
      rejectUnauthorized: true
    };
    console.log('[mtls] ' + method + ' -> ' + parsed.hostname + parsed.pathname);
    var req = https.request(options, function(res) {
      var data = '';
      res.on('data', function(chunk) { data += chunk; });
      res.on('end', function() {
        var responseHeaders = {};
        Object.keys(res.headers).forEach(function(k) {
          responseHeaders[k] = res.headers[k];
        });
        resolve({ status: res.statusCode, headers: responseHeaders, body: data });
      });
    });
    req.on('error', function(err) {
      console.error('[mtls] Error:', err.code, err.message);
      // If RSA format fails, try PKCS8 and vice versa
      if (err.message.indexOf('bad base64') >= 0 || err.message.indexOf('unsupported') >= 0) {
        console.log('[mtls] Key format issue detected, trying alternate format...');
      }
      reject(err);
    });
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

// Retry with alternate key format on failure
function makeHTTPSRequestWithRetry(url, method, headers, body, cert) {
  return makeHTTPSRequest(url, method, headers, body, cert, formattedKey)
    .catch(function(err) {
      if (err.message.indexOf('PEM') >= 0 || err.message.indexOf('base64') >= 0 || err.message.indexOf('key') >= 0) {
        console.log('[mtls] Retrying with alternate key format...');
        var altKey = keyFormat.indexOf('RSA') >= 0 ? formattedKeyPKCS8 : formattedKeyRSA;
        return makeHTTPSRequest(url, method, headers, body, cert, altKey)
          .then(function(result) {
            // If alternate works, update for future calls
            formattedKey = altKey;
            keyFormat = keyFormat.indexOf('RSA') >= 0 ? 'PKCS8 (auto-detected)' : 'RSA (auto-detected)';
            console.log('[mtls] Alternate key format worked! Using:', keyFormat);
            return result;
          });
      }
      throw err;
    });
}

function authenticate(req, res, next) {
  var authHeader = req.headers['x-proxy-secret'];
  if (!PROXY_SECRET || authHeader !== PROXY_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/health', function(req, res) {
  res.json({
    status: 'ok',
    version: '3.0.0',
    mtls: !!(formattedCert && formattedKey),
    key_format: keyFormat,
    cert_base64_len: formattedCert ? formattedCert.replace(/-----[^-]*--
