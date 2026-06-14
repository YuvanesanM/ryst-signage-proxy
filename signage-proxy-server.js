const https = require('https');
const http  = require('http');
const crypto = require('crypto');

const PORT        = process.env.PORT         || 3000;
const GH_TOKEN    = process.env.GH_TOKEN;          // Render env var — never in code
const SET_PASS    = process.env.SET_PASSWORD || 'RYST@set2026'; // Render env var
const GH_OWNER    = 'yuvanesanm';
const GH_REPO     = 'ryst-signage';
const GH_FILE     = 'schedule.json';

// ── CORS origins allowed ──────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://signage.ryst.in',
  'https://yuvanesanm.github.io',
  'http://localhost:3000',
  'http://localhost:5500',
];

// ── HMAC session tokens (24 h) ────────────────────────────────────────
const TOKEN_SECRET = crypto
  .createHash('sha256')
  .update('ryst-signage-proxy-' + SET_PASS)
  .digest('hex');
const TOKEN_TTL = 24 * 60 * 60 * 1000;

function issueToken() {
  const exp = Date.now() + TOKEN_TTL;
  const sig  = crypto.createHmac('sha256', TOKEN_SECRET).update(String(exp)).digest('hex');
  return `${exp}.${sig}`;
}

function verifyToken(token) {
  if (!token) return false;
  const dot = token.indexOf('.');
  if (dot < 0) return false;
  const exp = parseInt(token.slice(0, dot));
  const sig  = token.slice(dot + 1);
  if (isNaN(exp) || Date.now() > exp) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(String(exp)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
}

// ── GitHub API helper ─────────────────────────────────────────────────
function ghRequest(method, body, cb) {
  const path = `/repos/${GH_OWNER}/${GH_REPO}/contents/${GH_FILE}`;
  const data = body ? JSON.stringify(body) : null;
  const opts = {
    hostname: 'api.github.com',
    path,
    method,
    headers: {
      'Authorization': `token ${GH_TOKEN}`,
      'Accept':        'application/vnd.github.v3+json',
      'User-Agent':    'ryst-signage-proxy',
      ...(data ? {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(data),
      } : {}),
    },
  };
  const req = https.request(opts, r => {
    let resp = '';
    r.on('data', c => resp += c);
    r.on('end',  () => cb(null, resp, r.statusCode));
  });
  req.on('error', err => cb(err.message, null, 500));
  if (data) req.write(data);
  req.end();
}

// ── HTTP Server ───────────────────────────────────────────────────────
http.createServer((req, res) => {
  // CORS
  const origin = req.headers.origin || '';
  const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  res.setHeader('Access-Control-Allow-Origin',  corsOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Token');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = req.url.split('?')[0];

  // ── POST /auth — password → token ────────────────────────────────
  if (req.method === 'POST' && url === '/auth') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { password } = JSON.parse(body);
        if (password === SET_PASS) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, token: issueToken() }));
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Incorrect password' }));
        }
      } catch(e) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Bad request' }));
      }
    });
    return;
  }

  // ── All /schedule routes require valid token ──────────────────────
  if (url === '/schedule') {
    const token = req.headers['x-token'] || '';
    if (!verifyToken(token)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized — invalid or expired token' }));
      return;
    }

    // GET /schedule — read schedule.json
    if (req.method === 'GET') {
      ghRequest('GET', null, (err, data, status) => {
        if (err) { res.writeHead(500); res.end(JSON.stringify({ error: err })); return; }
        res.writeHead(status === 404 ? 200 : status, { 'Content-Type': 'application/json' });
        // 404 = file doesn't exist yet, return empty schedule
        res.end(status === 404 ? JSON.stringify({ sessions: [] }) : data);
      });
      return;
    }

    // PUT /schedule — write schedule.json
    if (req.method === 'PUT') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const scheduleData = JSON.parse(body);

          // First GET to obtain current SHA (required by GitHub API for updates)
          ghRequest('GET', null, (err, existing, status) => {
            const sha = status !== 404 ? (() => {
              try { return JSON.parse(existing).sha; } catch(e) { return null; }
            })() : null;

            const content = Buffer.from(JSON.stringify(scheduleData, null, 2)).toString('base64');
            const payload = {
              message: `Update schedule — ${new Date().toLocaleString('en-IN')}`,
              content,
              ...(sha ? { sha } : {}),
            };

            ghRequest('PUT', payload, (err2, data2, status2) => {
              if (err2) { res.writeHead(500); res.end(JSON.stringify({ error: err2 })); return; }
              res.writeHead(status2, { 'Content-Type': 'application/json' });
              res.end(data2);
            });
          });
        } catch(e) {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        }
      });
      return;
    }

    res.writeHead(405); res.end('Method not allowed');
    return;
  }

  // ── GET / — TV display fetches schedule (no auth, read-only) ─────
  // index.html polls this for live schedule
  if (req.method === 'GET' && url === '/public-schedule') {
    ghRequest('GET', null, (err, data, status) => {
      if (err || status === 404) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessions: [] })); return;
      }
      try {
        const ghData = JSON.parse(data);
        const schedule = JSON.parse(Buffer.from(ghData.content, 'base64').toString('utf8'));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(schedule));
      } catch(e) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessions: [] }));
      }
    });
    return;
  }

  // ── Health check ──────────────────────────────────────────────────
  if (url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      service: 'Studio RYST Signage Proxy',
      status:  'ok',
      time:    new Date().toISOString(),
    }));
    return;
  }

  res.writeHead(404); res.end('Not found');

}).listen(PORT, () => {
  console.log(`🎙️  RYST Signage Proxy running on port ${PORT}`);
  console.log(`    GH_TOKEN: ${GH_TOKEN ? '✓ set' : '✗ MISSING'}`);
  console.log(`    Password: ${SET_PASS ? '✓ set' : '✗ MISSING'}`);
});
