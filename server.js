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
const GH_OWNER    = 'yuvanesanm';
const GH_REPO     = 'signage';
const GH_FILE     = 'schedule.json';

// Frigate (behind nginx Basic Auth) — credentials live here, never in the browser
const FRIGATE_HOST = process.env.FRIGATE_HOST || 'frigate.ryst.in';
const FRIGATE_USER = process.env.FRIGATE_USER;
const FRIGATE_PASS = process.env.FRIGATE_PASS;

const ALLOWED_ORIGINS = [
  'https://signage.ryst.in',
  'https://stay.ryst.in',
  'https://yuvanesanm.github.io',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
];

// Google OAuth2 — only these accounts may sign in. GOOGLE_CLIENT_ID must match
// the OAuth client the browser used, so ID tokens minted for other apps are
// rejected (audience binding). Falls back to the known web client ID if unset.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ||
  '717827758789-99ugj40a6j2rr4r7db26shn0hivq0vv0.apps.googleusercontent.com';

// Owners can do everything (reimburse, top-up, set float, delete any entry).
// Caretakers can only add/edit/delete their own pending expenses.
const OWNER_EMAILS     = ['mailyuvanesh@gmail.com', 'studioryst01@gmail.com'];
// ▼▼▼ ADD THE CARETAKER'S GMAIL HERE to let them log in ▼▼▼
const CARETAKER_EMAILS = [/* 'caretaker@gmail.com' */];
// ▲▲▲
const ALLOWED_EMAILS   = [...OWNER_EMAILS, ...CARETAKER_EMAILS];
function roleFor(email) { return OWNER_EMAILS.includes(email) ? 'owner' : 'caretaker'; }

const MAX_BODY_BYTES = 16 * 1024;         // default request-body cap (16 KB)
const PC_MAX_BODY_BYTES = 4 * 1024 * 1024; // petty-cash cap (4 MB, allows a receipt)
const DEFAULT_PC_CATEGORIES = [
  'Groceries', 'Utilities', 'Repairs & Maintenance', 'Housekeeping',
  'Guest Supplies', 'Transport', 'Staff', 'Gardening', 'Pool', 'Miscellaneous',
];

// TOKEN_SECRET signs issued session tokens. Set this env var on Render.
// If absent, a random secret is generated at startup — tokens expire on restart.
const _rawSecret = process.env.TOKEN_SECRET || process.env.SET_PASSWORD;
if (!_rawSecret) console.warn('⚠  TOKEN_SECRET not set — session tokens will not survive a restart');
const TOKEN_SECRET = _rawSecret
  ? crypto.createHash('sha256').update('ryst-signage-proxy-' + _rawSecret).digest('hex')
  : crypto.randomBytes(32).toString('hex');
const TOKEN_TTL = 24 * 60 * 60 * 1000;

// Session token = base64url(payload).hmac, where payload carries the signed-in
// email, role and expiry. Self-describing so routes can authorise by role.
function b64url(str)     { return Buffer.from(str).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(s) { return Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8'); }

function issueToken(email, role) {
  const payload = b64url(JSON.stringify({ exp: Date.now() + TOKEN_TTL, email: email || null, role: role || 'owner' }));
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

// Returns the decoded payload object when the token is valid, else false.
// (Truthy on success, so existing `if (!verifyToken(t))` guards keep working.)
function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return false;
  const payload = token.slice(0, dot);
  const sig     = token.slice(dot + 1);
  // The HMAC-SHA256 signature is always 64 hex chars. Reject anything else
  // BEFORE timingSafeEqual — a non-hex or wrong-length sig yields a buffer of a
  // different length, and timingSafeEqual throws on a length mismatch, which
  // would otherwise become an uncaught exception and crash the process.
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return false;
  let data;
  try { data = JSON.parse(b64urlDecode(payload)); } catch(e) { return false; }
  if (!data || typeof data.exp !== 'number' || Date.now() > data.exp) return false;
  return data;
}

// Authenticated GitHub API — used for reads (fresh data) and writes
function ghRequest(method, body, cb, file = GH_FILE) {
  const path = `/repos/${GH_OWNER}/${GH_REPO}/contents/${file}`;
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

// ── Petty cash ledger helpers ───────────────────────────────────────────────
function pcId(prefix) {
  return prefix + '_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');
}

// Mutates the petty-cash `doc` in place according to `cmd`. Throws
// { status, msg } on any validation or authorisation failure. `role` is
// 'owner' or 'caretaker'; `email` is the signed-in user.
function pcApplyCommand(doc, cmd, role, email) {
  const isOwner = role === 'owner';
  const toNum = v => { const n = Number(v); return isFinite(n) ? n : NaN; };
  const ownerOnly = () => { if (!isOwner) throw { status: 403, msg: 'Only the owner can do this' }; };
  const cleanReceipt = r => (typeof r === 'string' && r.startsWith('data:')) ? r : null;

  switch (cmd.action) {
    case 'add-expense': {
      const amount = toNum(cmd.amount);
      if (!(amount > 0)) throw { status: 400, msg: 'Amount must be greater than 0' };
      if (!cmd.date)     throw { status: 400, msg: 'Date is required' };
      doc.entries.push({
        id: pcId('e'), type: 'expense', date: String(cmd.date),
        category: String(cmd.category || 'Miscellaneous'), amount,
        note: String(cmd.note || ''), receipt: cleanReceipt(cmd.receipt),
        status: 'pending', reimbursementId: null,
        createdBy: email, createdAt: Date.now(),
      });
      return;
    }
    case 'edit-expense': {
      const ent = doc.entries.find(x => x.id === cmd.id && x.type === 'expense');
      if (!ent) throw { status: 404, msg: 'Expense not found' };
      if (!isOwner && (ent.createdBy !== email || ent.status !== 'pending'))
        throw { status: 403, msg: 'You can only edit your own pending expenses' };
      if (ent.status === 'reimbursed' && !isOwner)
        throw { status: 403, msg: 'Reimbursed expenses cannot be edited' };
      if (cmd.amount   !== undefined) { const a = toNum(cmd.amount); if (!(a > 0)) throw { status: 400, msg: 'Amount must be greater than 0' }; ent.amount = a; }
      if (cmd.date     !== undefined) ent.date     = String(cmd.date);
      if (cmd.category !== undefined) ent.category = String(cmd.category);
      if (cmd.note     !== undefined) ent.note     = String(cmd.note);
      if (cmd.receipt  !== undefined) ent.receipt  = cleanReceipt(cmd.receipt);
      return;
    }
    case 'delete-entry': {
      const idx = doc.entries.findIndex(x => x.id === cmd.id);
      if (idx < 0) throw { status: 404, msg: 'Entry not found' };
      const ent = doc.entries[idx];
      if (!isOwner && (ent.type !== 'expense' || ent.createdBy !== email || ent.status !== 'pending'))
        throw { status: 403, msg: 'You can only delete your own pending expenses' };
      doc.entries.splice(idx, 1);
      return;
    }
    case 'reimburse': {
      ownerOnly();
      const ids = Array.isArray(cmd.entryIds) ? cmd.entryIds : [];
      const targets = doc.entries.filter(x => x.type === 'expense' && x.status === 'pending' && ids.includes(x.id));
      if (!targets.length) throw { status: 400, msg: 'No pending expenses selected' };
      const total = targets.reduce((s, x) => s + Number(x.amount || 0), 0);
      const rid = pcId('r');
      targets.forEach(t => { t.status = 'reimbursed'; t.reimbursementId = rid; });
      doc.entries.push({
        id: rid, type: 'topup', subtype: 'reimbursement',
        date: String(cmd.date || new Date().toISOString().slice(0, 10)),
        amount: total, note: String(cmd.note || `Reimbursed ${targets.length} expense(s)`),
        coversIds: targets.map(t => t.id), createdBy: email, createdAt: Date.now(),
      });
      return;
    }
    case 'topup': {
      ownerOnly();
      const amount = toNum(cmd.amount);
      if (!(amount > 0)) throw { status: 400, msg: 'Amount must be greater than 0' };
      doc.entries.push({
        id: pcId('t'), type: 'topup', subtype: 'cash',
        date: String(cmd.date || new Date().toISOString().slice(0, 10)),
        amount, note: String(cmd.note || 'Cash added to float'),
        createdBy: email, createdAt: Date.now(),
      });
      return;
    }
    case 'set-float': {
      ownerOnly();
      const f = toNum(cmd.float);
      if (!(f >= 0)) throw { status: 400, msg: 'Invalid float amount' };
      doc.float = f;
      return;
    }
    case 'set-categories': {
      ownerOnly();
      if (!Array.isArray(cmd.categories)) throw { status: 400, msg: 'Invalid categories' };
      doc.categories = cmd.categories.map(String).map(s => s.trim()).filter(Boolean).slice(0, 40);
      return;
    }
    default:
      throw { status: 400, msg: 'Unknown action' };
  }
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

  // POST /auth — Google ID token -> session token
  // Body: { googleIdToken: string }
  // Verifies the token with Google's tokeninfo endpoint and checks the email
  // against the allow-list. Returns { ok, token } on success.
  if (req.method === 'POST' && url === '/auth') {
    let body = '';
    let aborted = false;
    req.on('data', c => {
      if (aborted) return;
      body += c;
      // Cap the incoming body so a malicious client can't OOM the process.
      if (body.length > MAX_BODY_BYTES) {
        aborted = true;
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Request too large' }));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (aborted) return;
      let googleIdToken;
      try {
        ({ googleIdToken } = JSON.parse(body));
      } catch(e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Bad request' }));
        return;
      }
      // Real Google JWTs are well under 4 KB. Reject oversized values before
      // building a URL from them (avoids a 414 from Google → misleading 500).
      if (!googleIdToken || typeof googleIdToken !== 'string' || googleIdToken.length > 4096) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Missing or invalid googleIdToken' }));
        return;
      }

      // Guard against sending the HTTP response twice (e.g. the request-timeout
      // fires after the tokeninfo response has already been handled).
      let replied = false;
      const reply = (status, payload) => {
        if (replied || res.headersSent) return;
        replied = true;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };

      // Verify ID token with Google's tokeninfo endpoint
      const tokenPath = '/tokeninfo?id_token=' + encodeURIComponent(googleIdToken);
      const tokenReq = https.request({
        hostname: 'oauth2.googleapis.com',
        path: tokenPath,
        method: 'GET',
        headers: { 'User-Agent': 'ryst-signage-proxy' },
      }, tokenRes => {
        let data = '';
        let tokenAborted = false;
        tokenRes.on('data', c => {
          if (tokenAborted) return;
          data += c;
          if (data.length > MAX_BODY_BYTES) { tokenAborted = true; tokenRes.destroy(); }
        });
        tokenRes.on('end', () => {
          clearTimeout(timeoutTimer);
          if (tokenAborted) { reply(502, { ok: false, error: 'Token verification failed' }); return; }
          try {
            const info = JSON.parse(data);
            if (
              tokenRes.statusCode === 200 &&
              String(info.email_verified) === 'true' &&
              info.aud === GOOGLE_CLIENT_ID &&
              ALLOWED_EMAILS.includes(info.email)
            ) {
              const role = roleFor(info.email);
              reply(200, { ok: true, token: issueToken(info.email, role), email: info.email, role });
            } else {
              reply(403, { ok: false, error: 'Access denied' });
            }
          } catch(e) {
            reply(500, { ok: false, error: 'Token verification failed' });
          }
        });
      });
      tokenReq.on('error', () => {
        clearTimeout(timeoutTimer);
        reply(502, { ok: false, error: 'Google verification unreachable' });
      });
      // Use a plain timer (cleared on completion) rather than socket.setTimeout,
      // whose callback could fire on a lingering keep-alive socket after we have
      // already replied.
      const timeoutTimer = setTimeout(() => tokenReq.destroy(new Error('timeout')), 10000);
      tokenReq.end();
    });
    return;
  }

  // /petty-cash — RYST 109A caretaker expense ledger (imprest float model).
  //   GET  → current ledger document (any signed-in user)
  //   POST → { action, ... } command, applied server-side with role checks and
  //          optimistic-concurrency retry on the GitHub file SHA.
  if (url === '/petty-cash') {
    const auth = verifyToken(req.headers['x-token'] || '');
    if (!auth) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    const role  = auth.role  || 'owner';
    const email = auth.email || 'unknown';
    const PC_FILE = 'petty-cash.json';
    const freshDoc = () => ({ version: 1, float: 0, categories: DEFAULT_PC_CATEGORIES.slice(), entries: [] });

    const loadDoc = cb => ghRequest('GET', null, (err, data, status) => {
      if (err) return cb({ status: 502, msg: 'GitHub error' });
      if (status === 404) return cb(null, freshDoc(), null);
      if (status !== 200) return cb({ status: 502, msg: 'GitHub error ' + status });
      try {
        const gh = JSON.parse(data);
        const doc = JSON.parse(Buffer.from(gh.content, 'base64').toString('utf8'));
        cb(null, doc, gh.sha);
      } catch(e) { cb(null, freshDoc(), null); }
    }, PC_FILE);

    if (req.method === 'GET') {
      loadDoc((e, doc) => {
        if (e) { res.writeHead(e.status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: e.msg })); return; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(doc));
      });
      return;
    }

    if (req.method === 'POST') {
      let body = '', aborted = false;
      req.on('data', c => {
        if (aborted) return;
        body += c;
        if (body.length > PC_MAX_BODY_BYTES) {
          aborted = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Request too large (receipt over 4 MB?)' }));
          req.destroy();
        }
      });
      req.on('end', () => {
        if (aborted) return;
        let cmd;
        try { cmd = JSON.parse(body); } catch(e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad request' })); return;
        }
        const attempt = triesLeft => {
          loadDoc((e, doc, sha) => {
            if (e) { res.writeHead(e.status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: e.msg })); return; }
            if (!Array.isArray(doc.entries)) doc.entries = [];
            if (!Array.isArray(doc.categories)) doc.categories = DEFAULT_PC_CATEGORIES.slice();
            try { pcApplyCommand(doc, cmd, role, email); }
            catch(ex) {
              res.writeHead(ex.status || 400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: ex.msg || 'Error' })); return;
            }
            const content = Buffer.from(JSON.stringify(doc, null, 2)).toString('base64');
            const payload = { message: `Petty cash — ${new Date().toLocaleString('en-IN')}`, content, ...(sha ? { sha } : {}) };
            ghRequest('PUT', payload, (err2, data2, status2) => {
              if (err2) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: err2 })); return; }
              // 409/422 → SHA conflict from a concurrent write; reload and retry.
              if ((status2 === 409 || status2 === 422) && triesLeft > 0) { attempt(triesLeft - 1); return; }
              if (status2 !== 200 && status2 !== 201) { res.writeHead(502, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Write failed (' + status2 + ')' })); return; }
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(doc));
            }, PC_FILE);
          });
        };
        attempt(3);
      });
      return;
    }

    res.writeHead(405); res.end('Method not allowed');
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

  // Generic authenticated GitHub file route factory used by /quotes and /rates.
  // GET  → read file from GitHub, return decoded JSON
  // PUT  → write body JSON to GitHub file
  function ghFileRoute(ghFile, emptyDoc) {
    const token = req.headers['x-token'] || '';
    if (!verifyToken(token)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    if (req.method === 'GET') {
      ghRequest('GET', null, (err, data, status) => {
        if (err) { res.writeHead(500); res.end(JSON.stringify({ error: err })); return; }
        if (status === 404) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(emptyDoc)); return; }
        if (status !== 200) { res.writeHead(502); res.end(JSON.stringify({ error: 'GitHub error ' + status })); return; }
        try {
          const parsed = JSON.parse(Buffer.from(JSON.parse(data).content, 'base64').toString('utf8'));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(parsed));
        } catch(e) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(emptyDoc)); }
      }, ghFile);
      return;
    }
    if (req.method === 'PUT') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try { JSON.parse(body); } catch(e) { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' })); return; }
        ghRequest('GET', null, (err, existing, status) => {
          const sha = status !== 404 ? (() => { try { return JSON.parse(existing).sha; } catch(e) { return null; } })() : null;
          const content = Buffer.from(body).toString('base64');
          const payload = { message: `Update ${ghFile} — ${new Date().toLocaleString('en-IN')}`, content, ...(sha ? { sha } : {}) };
          ghRequest('PUT', payload, (err2, data2, status2) => {
            if (err2) { res.writeHead(500); res.end(JSON.stringify({ error: err2 })); return; }
            res.writeHead(status2, { 'Content-Type': 'application/json' });
            res.end(data2);
          }, ghFile);
        }, ghFile);
      });
      return;
    }
    res.writeHead(405); res.end('Method not allowed');
  }

  // /quotes — saved quotations (GET read, PUT write)
  if ((req.method === 'GET' || req.method === 'PUT') && url === '/quotes') {
    ghFileRoute('quotes.json', { version: 1, quotes: [] }); return;
  }

  // /rates — rate card (GET read, PUT write)
  if ((req.method === 'GET' || req.method === 'PUT') && url === '/rates') {
    ghFileRoute('rates.json', { version: 1, rateCard: [] }); return;
  }

  // /stays — saved RYST 109A villa invoices & quotes (GET read, PUT write)
  if ((req.method === 'GET' || req.method === 'PUT') && url === '/stays') {
    ghFileRoute('stays.json', { version: 1, stays: [] }); return;
  }

  // /stay-settings — RYST 109A villa business info, bank & pricing (GET/PUT)
  if ((req.method === 'GET' || req.method === 'PUT') && url === '/stay-settings') {
    ghFileRoute('stay-settings.json', { version: 1 }); return;
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
  console.log(`    GH_TOKEN:      ${GH_TOKEN ? '✓ set' : '✗ MISSING'}`);
  console.log(`    Token secret:  ${_rawSecret ? '✓ set (TOKEN_SECRET / SET_PASSWORD)' : '⚠  ephemeral (set TOKEN_SECRET)'}`);
  console.log(`    Google auth:   ✓ ${ALLOWED_EMAILS.join(', ')}`);
  console.log(`    Client ID:     ${GOOGLE_CLIENT_ID ? '✓ set' : '✗ MISSING'}`);
  console.log(`    Frigate:       ${FRIGATE_USER && FRIGATE_PASS ? '✓ creds set' : '✗ MISSING (set FRIGATE_USER / FRIGATE_PASS)'}`);
});

// Last-resort safety net: log unexpected errors instead of letting a single
// bad request take the whole proxy down. Root causes are still fixed at the
// call sites; this only prevents a total outage from an unforeseen edge case.
process.on('uncaughtException', err => {
  console.error('Uncaught exception (kept alive):', err && err.stack || err);
});
