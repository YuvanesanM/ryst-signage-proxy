const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const zlib   = require('zlib');

// ── In-memory TTL cache for Frigate API responses ──────────────────────────
const _cache = new Map();
const CACHE_TTL_MS = {
  '/api/stats':   15_000,   // 15 s  — FPS numbers update frequently
  '/api/events':  45_000,   // 45 s  — dashboard polls every 60 s
  '/api/config': 300_000,   // 5 min — rarely changes
};
function cacheGet(key) {
  const e = _cache.get(key);
  if (!e) return null;
  if (Date.now() > e.exp) { _cache.delete(key); return null; }
  return e;
}
// Pre-compute the gzip form once at fill time so cache HITs never re-compress.
function cacheSet(key, raw, ct, ttl) {
  const entry = { raw, gz: zlib.gzipSync(raw), ct, exp: Date.now() + ttl };
  _cache.set(key, entry);
  return entry;
}
// Evict stale entries every 5 minutes to avoid memory growth
setInterval(() => { const now = Date.now(); for (const [k,v] of _cache) if (now > v.exp) _cache.delete(k); }, 300_000);

// ── Serve a cache entry — picks the pre-gzipped body when the client accepts
// gzip, else the raw body. Always no-store (downstream must respect our TTL,
// not cache independently) and Vary: Accept-Encoding so shared caches never
// hand a gzipped body to a client that didn't ask for it.
function sendCacheEntry(req, res, entry, cacheState) {
  const gzipOk = (req.headers['accept-encoding'] || '').includes('gzip');
  const headers = {
    'Content-Type': entry.ct,
    'Cache-Control': 'no-store',
    'Vary': 'Accept-Encoding',
    'X-Cache': cacheState,
  };
  if (gzipOk) headers['Content-Encoding'] = 'gzip';
  res.writeHead(200, headers);
  res.end(gzipOk ? entry.gz : entry.raw);
}

const PORT        = process.env.PORT         || 3000;
const GH_TOKEN    = process.env.GH_TOKEN;
if (!process.env.SET_PASSWORD) {
  console.error('FATAL: SET_PASSWORD environment variable is required');
  process.exit(1);
}
const SET_PASS = process.env.SET_PASSWORD;
const GH_OWNER    = 'yuvanesanm';
const GH_REPO     = 'signage';
const GH_FILE     = 'schedule.json';

// Frigate (behind nginx Basic Auth) — credentials live here, never in the browser
const FRIGATE_HOST = process.env.FRIGATE_HOST || 'frigate.ryst.in';
const FRIGATE_USER = process.env.FRIGATE_USER;
const FRIGATE_PASS = process.env.FRIGATE_PASS;

const ALLOWED_ORIGINS = [
  'https://signage.ryst.in',
  'https://yuvanesanm.github.io',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
];

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

// Authenticated GitHub API — used for reads (fresh data) and writes
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


http.createServer((req, res) => {
  const origin = req.headers.origin || '';
  const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  res.setHeader('Access-Control-Allow-Origin', corsOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Token');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = req.url.split('?')[0];

  // POST /auth — password -> token
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

  // /schedule — requires valid session token
  if (url === '/schedule') {
    const token = req.headers['x-token'] || '';
    if (!verifyToken(token)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized — invalid or expired token' }));
      return;
    }

    // GET /schedule — fetch via GitHub API for always-fresh data
    if (req.method === 'GET') {
      ghRequest('GET', null, (err, data, status) => {
        if (err) { res.writeHead(500); res.end(JSON.stringify({ error: err })); return; }
        if (status === 404) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ sessions: [] })); return;
        }
        if (status === 403) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'GitHub API rate limit reached — try again shortly' })); return;
        }
        if (status !== 200) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'GitHub API error: ' + status })); return;
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

    // PUT /schedule — write schedule.json
    if (req.method === 'PUT') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const scheduleData = JSON.parse(body);

          // GET current SHA (required by GitHub API for updates)
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

  // GET /public-schedule — TV display, no auth required on this route but uses token internally
  if (req.method === 'GET' && url === '/public-schedule') {
    ghRequest('GET', null, (err, data, status) => {
      if (err || status === 404 || status === 403) {
        if (status === 403) console.warn('GitHub API 403 on public-schedule — check GH_TOKEN permissions');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessions: [] })); return;
      }
      if (status !== 200) {
        console.warn('GitHub API unexpected status on public-schedule:', status);
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

  // GET /frigate/api/... — authenticated read-only proxy to Frigate.
  // Injects HTTP Basic Auth server-side so the camera password never reaches
  // the browser. Only a whitelisted set of read-only endpoints is forwarded.
  if (req.method === 'GET' && url.startsWith('/frigate/')) {
    if (!FRIGATE_USER || !FRIGATE_PASS) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Frigate credentials not configured on proxy' }));
      return;
    }
    const fwd = req.url.replace(/^\/frigate/, '');   // remainder, query string preserved
    const fwdPath = fwd.split('?')[0];
    const allowed =
      /^\/api\/stats$/.test(fwdPath) ||
      /^\/api\/events$/.test(fwdPath) ||
      /^\/api\/config$/.test(fwdPath) ||
      /^\/api\/[A-Za-z0-9_-]+\/latest\.jpg$/.test(fwdPath);
    if (!allowed) { res.writeHead(403); res.end('Forbidden'); return; }

    const auth = 'Basic ' + Buffer.from(`${FRIGATE_USER}:${FRIGATE_PASS}`).toString('base64');

    // Only the JSON endpoints are cacheable; the lone image endpoint ends in .jpg.
    const isJson = !fwdPath.endsWith('.jpg');
    const cacheKey = req.url; // includes query string
    const ttl = isJson ? CACHE_TTL_MS[fwdPath] : 0;

    // Serve from cache if fresh
    if (ttl) {
      const hit = cacheGet(cacheKey);
      if (hit) { sendCacheEntry(req, res, hit, 'HIT'); return; }
    }

    // /api/config: fetch then strip RTSP paths (may contain camera credentials)
    if (fwdPath === '/api/config') {
      const cfgReq = https.request({
        hostname: FRIGATE_HOST, path: fwd, method: 'GET',
        headers: { 'Authorization': auth, 'User-Agent': 'ryst-signage-proxy', 'Accept': 'application/json' },
      }, cfgRes => {
        const chunks = [];
        cfgRes.on('data', c => chunks.push(c));
        cfgRes.on('end', () => {
          try {
            const cfg = JSON.parse(Buffer.concat(chunks).toString());
            if (cfg.cameras) {
              Object.values(cfg.cameras).forEach(cam => {
                if (cam.ffmpeg && cam.ffmpeg.inputs) {
                  cam.ffmpeg.inputs = cam.ffmpeg.inputs.map(i => ({ ...i, path: '[redacted]' }));
                }
              });
            }
            const out = Buffer.from(JSON.stringify(cfg));
            const entry = cacheSet(cacheKey, out, 'application/json', CACHE_TTL_MS['/api/config']);
            sendCacheEntry(req, res, entry, 'MISS');
          } catch(e) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Config parse error: ' + e.message }));
          }
        });
      });
      cfgReq.on('error', err => { res.writeHead(502); res.end(JSON.stringify({ error: err.message })); });
      cfgReq.setTimeout(10000, () => cfgReq.destroy(new Error('timeout')));
      cfgReq.end();
      return;
    }

    const fReq = https.request({
      hostname: FRIGATE_HOST,
      path: fwd,
      method: 'GET',
      headers: { 'Authorization': auth, 'User-Agent': 'ryst-signage-proxy', 'Accept': '*/*' },
    }, fRes => {
      const chunks = [];
      fRes.on('data', c => chunks.push(c));
      fRes.on('end', () => {
        const buf = Buffer.concat(chunks);
        const ct  = fRes.headers['content-type'] || 'application/octet-stream';
        if (ttl && fRes.statusCode === 200) {
          const entry = cacheSet(cacheKey, buf, ct, ttl);
          sendCacheEntry(req, res, entry, 'MISS');
        } else {
          // Images and non-200s: pass through untouched, never cached.
          res.writeHead(fRes.statusCode, { 'Content-Type': ct, 'Cache-Control': 'no-store' });
          res.end(buf);
        }
      });
    });
    fReq.on('error', err => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Frigate unreachable: ' + err.message }));
    });
    fReq.setTimeout(10000, () => fReq.destroy(new Error('timeout')));
    fReq.end();
    return;
  }

  // Health check
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
  console.log(`    Frigate:  ${FRIGATE_USER && FRIGATE_PASS ? '✓ creds set' : '✗ MISSING (set FRIGATE_USER / FRIGATE_PASS)'}`);
});
