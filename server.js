const express = require('express');
const https = require('https');
const { URL } = require('url');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.proxy_secret || process.env.C6_PROXY_SECRET;
const C6_CERTIFICATE = process.env.C6_CERTIFICATE;
const C6_PRIVATE_KEY = process.env.C6_PRIVATE_KEY;

console.log('ENV CHECK:');
console.log('- PORT:', PORT);
console.log('- PROXY_SECRET set:', !!PROXY_SECRET);
console.log('- C6_CERTIFICATE set:', !!C6_CERTIFICATE, 'length:', (C6_CERTIFICATE || '').length);
console.log('- C6_PRIVATE_KEY set:', !!C6_PRIVATE_KEY, 'length:', (C6_PRIVATE_KEY || '').length);

function formatPEM(content, type) {
  if (!content) return null;
  if (content.includes('-----BEGIN') && content.includes('\n')) {
    return content.trim();
  }
  if (content.includes('\\n')) {
    return content.replace(/\\n/g, '\n').trim();
  }
  var cleaned = content
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\s+/g, '');
  var lines = [];
  for (var i = 0; i < cleaned.length; i += 64) {
    lines.push(cleaned.substring(i, i + 64));
  }
  return '-----BEGIN ' + type + '-----\n' + lines.join('\n') + '\n-----END ' + type + '-----';
}

function makeHTTPSRequest(url, method, headers, body, cert, key) {
  return new Promise(function(resolve, reject) {
    var parsed = new URL(url);
    var options = {
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
      console.error('[mtls] Request error:', err.message);
      reject(err);
    });
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

var formattedCert = formatPEM(C6_CERTIFICATE, 'CERTIFICATE');
var formattedKey = formatPEM(C6_PRIVATE_KEY, 'RSA PRIVATE KEY');

if (formattedCert && formattedKey) {
  console.log('mTLS certificates formatted successfully');
  console.log('- Cert starts with:', formattedCert.substring(0, 40));
  console.log('- Key starts with:', formattedKey.substring(0, 40));
} else {
  console.log('WARNING: mTLS certificates NOT available');
}

function authenticate(req, res, next) {
  var authHeader = req.headers['x-proxy-secret'];
  if (!PROXY_SECRET || authHeader !== PROXY_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/health', function(req, res) {
  var certRawPreview = (C6_CERTIFICATE || '').substring(0, 100);
  var keyRawPreview = (C6_PRIVATE_KEY || '').substring(0, 100);
  var certFmtPreview = (formattedCert || '').substring(0, 100);
  var keyFmtPreview = (formattedKey || '').substring(0, 100);
  res.json({
    status: 'ok',
    mtls: !!(formattedCert && formattedKey),
    cert_len: (C6_CERTIFICATE || '').length,
    key_len: (C6_PRIVATE_KEY || '').length,
    cert_formatted_len: (formattedCert || '').length,
    key_formatted_len: (formattedKey || '').length,
    cert_raw_preview: certRawPreview,
    cert_fmt_preview: certFmtPreview,
    key_raw_preview: keyRawPreview.substring(0, 40),
    key_fmt_preview: keyFmtPreview.substring(0, 40),
    cert_has_real_newlines: (C6_CERTIFICATE || '').includes('\n'),
    cert_has_escaped_newlines: (C6_CERTIFICATE || '').includes('\\n'),
    timestamp: new Date().toISOString()
  });
});


app.post('/proxy', authenticate, async function(req, res) {
  try {
    var url = req.body.url;
    var method = req.body.method || 'POST';
    var headers = req.body.headers || {};
    var body = req.body.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    if (!formattedCert || !formattedKey) {
      return res.status(500).json({ error: 'mTLS certificates not configured' });
    }
    console.log('[proxy] ' + method + ' ' + url);
    var result = await makeHTTPSRequest(url, method, headers, body, formattedCert, formattedKey);
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
