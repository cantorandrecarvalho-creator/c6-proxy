const express = require('express');
const https = require('https');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.proxy_secret;
const C6_CERTIFICATE = process.env.C6_CERTIFICATE;
const C6_PRIVATE_KEY = process.env.C6_PRIVATE_KEY;

function formatPEM(content, type) {
  if (!content) return null;
  
  var cleaned = content
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\\n/g, '')
    .replace(/\s+/g, '');

  var lines = [];
  for (var i = 0; i < cleaned.length; i += 64) {
    lines.push(cleaned.substring(i, i + 64));
  }

  return '-----BEGIN ' + type + '-----\n' + lines.join('\n') + '\n-----END ' + type + '-----';
}

function createMTLSAgent() {
  if (!C6_CERTIFICATE || !C6_PRIVATE_KEY) {
    console.warn('C6_CERTIFICATE or C6_PRIVATE_KEY not configured - mTLS disabled');
    return null;
  }

  try {
    var cert = formatPEM(C6_CERTIFICATE, 'CERTIFICATE');
    var key = formatPEM(C6_PRIVATE_KEY, 'RSA PRIVATE KEY');

    return new https.Agent({
      cert: cert,
      key: key,
      rejectUnauthorized: true
    });
  } catch (err) {
    console.error('Failed to create mTLS Agent:', err.message);
    return null;
  }
}

var mtlsAgent = createMTLSAgent();
if (mtlsAgent) {
  console.log('mTLS Agent created successfully');
} else {
  console.log('mTLS Agent NOT created - check certificates');
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
    mtls: !!mtlsAgent,
    timestamp: new Date().toISOString()
  });
});

app.post('/proxy', authenticate, function(req, res) {
  var url = req.body.url;
  var method = req.body.method || 'POST';
  var headers = req.body.headers || {};
  var body = req.body.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  if (!mtlsAgent) {
    return res.status(500).json({ error: 'mTLS agent not configured' });
  }

  console.log('[proxy] ' + method + ' ' + url);

  var fetchOptions = {
    method: method,
    headers: Object.assign({ 'Content-Type': 'application/json' }, headers),
    agent: mtlsAgent
  };

  if (body) {
    fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  fetch(url, fetchOptions)
    .then(function(response) {
      var status = response.status;
      var responseHeaders = {};
      response.headers.forEach(function(value, key) {
        responseHeaders[key] = value;
      });
      return response.text().then(function(responseText) {
        console.log('[proxy] Response: ' + status);
        res.status(status).json({
          status: status,
          headers: responseHeaders,
          body: responseText
        });
      });
    })
    .catch(function(error) {
      console.error('[proxy] Error:', error.message);
      res.status(500).json({ error: error.message });
    });
});

app.listen(PORT, function() {
  console.log('C6 mTLS Proxy running on port ' + PORT);
});
