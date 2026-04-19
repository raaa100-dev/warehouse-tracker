/**
 * Warehouse Parts Tracker — Backend Server
 * Pure Node.js, zero npm dependencies.
 * Run: node server.js
 * Then open: http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'db.json');
const SECRET = process.env.JWT_SECRET || 'wh-secret-' + crypto.randomBytes(16).toString('hex');
const SESSION_HOURS = 12;

// ─── SIMPLE JSON DATABASE ─────────────────────────────────────────────────
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) {}
  return {
    users: [],
    jobs: {},
    catalog: {},
    inventory: {},
    auditLog: [],
    sessions: {}
  };
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let DB = loadDB();

// Seed admin account if no users exist
if (DB.users.length === 0) {
  const adminPass = hashPassword('admin123');
  DB.users.push({
    id: 'u1',
    username: 'admin',
    passwordHash: adminPass,
    role: 'admin',        // admin | stager | signout
    name: 'Administrator',
    active: true,
    createdAt: now()
  });
  saveDB(DB);
  console.log('✅ Default admin created — username: admin  password: admin123');
  console.log('   Change this password immediately in the Admin panel.');
}

// ─── AUTH HELPERS ─────────────────────────────────────────────────────────
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(plain, salt, 100000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(plain, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.pbkdf2Sync(plain, salt, 100000, 64, 'sha512').toString('hex');
  return check === hash;
}
function makeToken(userId) {
  const payload = { userId, exp: Date.now() + SESSION_HOURS * 3600 * 1000 };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
  return data + '.' + sig;
}
function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
  if (expected !== sig) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}
function now() {
  const n = new Date();
  return n.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})
    + ' ' + n.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',second:'2-digit',hour12:true});
}
function getUser(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  return DB.users.find(u => u.id === payload.userId && u.active) || null;
}
function requireAuth(res, user) {
  if (!user) { json(res, 401, { error: 'Not authenticated' }); return false; }
  return true;
}
function requireRole(res, user, ...roles) {
  if (!requireAuth(res, user)) return false;
  if (!roles.includes(user.role)) { json(res, 403, { error: 'Permission denied' }); return false; }
  return true;
}

// ─── HTTP HELPERS ─────────────────────────────────────────────────────────
function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  res.end(body);
}
function readBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch(e) { resolve({}); }
    });
  });
}
function serveFile(res, filePath, contentType) {
  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  } catch(e) {
    res.writeHead(404); res.end('Not found');
  }
}

// ─── ROUTES ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
    });
    return res.end();
  }

  // ── Static files ──
  if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    return serveFile(res, path.join(__dirname, 'public', 'index.html'), 'text/html');
  }
  if (method === 'GET' && pathname.startsWith('/public/')) {
    const safePath = path.join(__dirname, pathname);
    const ext = path.extname(safePath);
    const types = { '.html':'text/html','.js':'application/javascript','.css':'text/css','.png':'image/png' };
    return serveFile(res, safePath, types[ext] || 'application/octet-stream');
  }

  // ── Auth ──
  if (pathname === '/api/login' && method === 'POST') {
    const { username, password } = await readBody(req);
    const user = DB.users.find(u => u.username === username && u.active);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return json(res, 401, { error: 'Invalid username or password' });
    }
    const token = makeToken(user.id);
    return json(res, 200, { token, user: safeUser(user) });
  }

  if (pathname === '/api/me' && method === 'GET') {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated' });
    return json(res, 200, safeUser(user));
  }

  // ── Users (admin only) ──
  if (pathname === '/api/users' && method === 'GET') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin')) return;
    return json(res, 200, DB.users.map(safeUser));
  }

  if (pathname === '/api/users' && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin')) return;
    const { username, password, name, role } = await readBody(req);
    if (!username || !password || !name || !role) return json(res, 400, { error: 'username, password, name, role required' });
    if (!['admin','stager','signout'].includes(role)) return json(res, 400, { error: 'Invalid role' });
    if (DB.users.find(u => u.username === username)) return json(res, 400, { error: 'Username already exists' });
    const newUser = { id: 'u' + Date.now(), username, passwordHash: hashPassword(password), name, role, active: true, createdAt: now() };
    DB.users.push(newUser);
    saveDB(DB);
    return json(res, 201, safeUser(newUser));
  }

  const userEditMatch = pathname.match(/^\/api\/users\/([^/]+)$/);
  if (userEditMatch && method === 'PUT') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin')) return;
    const targetId = userEditMatch[1];
    const target = DB.users.find(u => u.id === targetId);
    if (!target) return json(res, 404, { error: 'User not found' });
    const body = await readBody(req);
    if (body.name !== undefined) target.name = body.name;
    if (body.role !== undefined && ['admin','stager','signout'].includes(body.role)) target.role = body.role;
    if (body.active !== undefined) target.active = !!body.active;
    if (body.password) target.passwordHash = hashPassword(body.password);
    saveDB(DB);
    return json(res, 200, safeUser(target));
  }

  if (userEditMatch && method === 'DELETE') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin')) return;
    const targetId = userEditMatch[1];
    if (targetId === user.id) return json(res, 400, { error: "Can't delete yourself" });
    DB.users = DB.users.filter(u => u.id !== targetId);
    saveDB(DB);
    return json(res, 200, { ok: true });
  }

  // ── Jobs ──
  if (pathname === '/api/jobs' && method === 'GET') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    return json(res, 200, Object.values(DB.jobs));
  }

  if (pathname === '/api/jobs' && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const { id } = await readBody(req);
    if (!id) return json(res, 400, { error: 'Job ID required' });
    if (DB.jobs[id]) return json(res, 400, { error: 'Job ID already exists' });
    const job = { id, parts: {}, created: now(), createdBy: user.name, active: true };
    DB.jobs[id] = job;
    saveDB(DB);
    return json(res, 201, job);
  }

  const jobMatch = pathname.match(/^\/api\/jobs\/([^/]+)$/);
  if (jobMatch && method === 'GET') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    const job = DB.jobs[jobMatch[1]];
    if (!job) return json(res, 404, { error: 'Job not found' });
    return json(res, 200, job);
  }

  // ── Job manifest (expected parts list) ──
  const manifestMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/manifest$/);

  // GET manifest
  if (manifestMatch && method === 'GET') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    const job = DB.jobs[manifestMatch[1]];
    if (!job) return json(res, 404, { error: 'Job not found' });
    if (!job.manifest) job.manifest = [];
    // Enrich with staged status from parts
    const enriched = job.manifest.map(m => {
      const staged = job.parts[m.partId];
      return {
        ...m,
        stagedStatus: staged ? staged.status : 'not_staged',
        stagedBy: staged?.stagedBy || null,
        stagedAt: staged?.stagedAt || null,
        signedOutBy: staged?.signedOutBy || null,
        signedOutAt: staged?.signedOutAt || null,
        over: staged?.over || false,
        takenQty: staged?.takenQty || 0,
      };
    });
    return json(res, 200, enriched);
  }

  // POST — add item to manifest
  if (manifestMatch && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const job = DB.jobs[manifestMatch[1]];
    if (!job) return json(res, 404, { error: 'Job not found' });
    if (!job.manifest) job.manifest = [];
    const { partId, name, expectedQty, notes } = await readBody(req);
    if (!partId) return json(res, 400, { error: 'partId required' });
    const cat = DB.catalog[partId];
    const partName = name || cat?.name || partId;
    const existing = job.manifest.find(m => m.partId === partId);
    if (existing) return json(res, 400, { error: 'Part already in manifest' });
    const item = { partId, name: partName, expectedQty: expectedQty || 1, notes: notes || '', addedBy: user.name, addedAt: now() };
    job.manifest.push(item);
    saveDB(DB);
    return json(res, 201, item);
  }

  // DELETE — remove item from manifest
  const manifestItemMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/manifest\/([^/]+)$/);
  if (manifestItemMatch && method === 'DELETE') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const job = DB.jobs[manifestItemMatch[1]];
    if (!job) return json(res, 404, { error: 'Job not found' });
    const partId = decodeURIComponent(manifestItemMatch[2]);
    job.manifest = (job.manifest || []).filter(m => m.partId !== partId);
    saveDB(DB);
    return json(res, 200, { ok: true });
  }

  // PUT — update manifest item qty/notes
  if (manifestItemMatch && method === 'PUT') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const job = DB.jobs[manifestItemMatch[1]];
    if (!job) return json(res, 404, { error: 'Job not found' });
    const partId = decodeURIComponent(manifestItemMatch[2]);
    const item = (job.manifest || []).find(m => m.partId === partId);
    if (!item) return json(res, 404, { error: 'Not in manifest' });
    const body = await readBody(req);
    if (body.expectedQty !== undefined) item.expectedQty = body.expectedQty;
    if (body.notes !== undefined) item.notes = body.notes;
    saveDB(DB);
    return json(res, 200, item);
  }

  // ── Parts on a job ──
  const jobPartsMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/parts$/);
  if (jobPartsMatch && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const jobId = jobPartsMatch[1];
    const job = DB.jobs[jobId];
    if (!job) return json(res, 404, { error: 'Job not found' });
    const { partId, name, assignedQty } = await readBody(req);
    if (!partId) return json(res, 400, { error: 'partId required' });
    if (job.parts[partId]) return json(res, 400, { error: 'Part already on this job' });
    const cat = DB.catalog[partId];
    const partName = name || cat?.name || partId;
    job.parts[partId] = { id: partId, name: partName, status: 'staged', stagedBy: user.name, stagedAt: now(), assignedQty: assignedQty || 1, takenQty: 0, over: false };
    if (DB.inventory[partId] && DB.inventory[partId].qty > 0) DB.inventory[partId].qty -= (assignedQty || 1);
    addAuditLog('in', jobId, partId, partName, user.name, 'qty: ' + (assignedQty || 1));
    saveDB(DB);
    return json(res, 201, job.parts[partId]);
  }

  // Stage part (stager or admin only)
  const stageMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/stage$/);
  if (stageMatch && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const [, jobId, partId] = stageMatch;
    const job = DB.jobs[jobId];
    if (!job) return json(res, 404, { error: 'Job not found' });
    if (!job.parts[partId]) return json(res, 404, { error: 'Part not assigned to this job. Parts must be assigned to a job before staging.' });
    const part = job.parts[partId];
    part.status = 'staged'; part.stagedBy = user.name; part.stagedAt = now();
    addAuditLog('staged', jobId, partId, part.name, user.name, '');
    saveDB(DB);
    return json(res, 200, part);
  }

  // Sign out part (signout, stager, or admin — but part MUST be on the job)
  const signoutMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/signout$/);
  if (signoutMatch && method === 'POST') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    const [, jobId, partId] = signoutMatch;
    const job = DB.jobs[jobId];
    if (!job) return json(res, 404, { error: 'Job not found' });
    // ENFORCE: part must exist on job
    if (!job.parts[partId]) return json(res, 403, { error: 'Part not assigned to this job. Cannot sign out unassigned parts.' });
    const body = await readBody(req);
    const qty = body.qty || 1;
    const part = job.parts[partId];
    part.status = 'picked'; part.signedOutBy = user.name; part.signedOutAt = now();
    part.takenQty = (part.takenQty || 0) + qty;
    const isOver = part.assignedQty && part.takenQty > part.assignedQty;
    if (isOver) { part.over = true; addAuditLog('over', jobId, partId, part.name, user.name, 'overage: '+part.takenQty+'/'+part.assignedQty); }
    else addAuditLog('out', jobId, partId, part.name, user.name, 'qty: '+qty);
    saveDB(DB);
    return json(res, 200, { part, over: isOver });
  }

  // Return part to inventory
  const returnMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/return$/);
  if (returnMatch && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const [, jobId, partId] = returnMatch;
    const job = DB.jobs[jobId];
    if (!job || !job.parts[partId]) return json(res, 404, { error: 'Not found' });
    const part = job.parts[partId];
    if (!DB.inventory[partId]) DB.inventory[partId] = { id: partId, name: part.name, qty: 0 };
    DB.inventory[partId].qty += part.assignedQty || 1;
    delete job.parts[partId];
    addAuditLog('return', jobId, partId, part.name, user.name, '');
    saveDB(DB);
    return json(res, 200, { ok: true });
  }

  // ── Catalog ──
  if (pathname === '/api/catalog' && method === 'GET') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    return json(res, 200, Object.values(DB.catalog));
  }

  if (pathname === '/api/catalog' && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const { barcode, name, part_number, category, description } = await readBody(req);
    if (!barcode || !name) return json(res, 400, { error: 'barcode and name required' });
    DB.catalog[barcode] = { barcode, name, part_number: part_number||'', category: category||'', description: description||'' };
    saveDB(DB);
    return json(res, 201, DB.catalog[barcode]);
  }

  const catMatch = pathname.match(/^\/api\/catalog\/([^/]+)$/);
  if (catMatch && method === 'DELETE') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin')) return;
    delete DB.catalog[catMatch[1]];
    saveDB(DB);
    return json(res, 200, { ok: true });
  }

  // ── Inventory ──
  if (pathname === '/api/inventory' && method === 'GET') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    return json(res, 200, Object.values(DB.inventory));
  }

  if (pathname === '/api/inventory' && method === 'POST') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin', 'stager')) return;
    const { id, name, qty } = await readBody(req);
    if (!id) return json(res, 400, { error: 'id required' });
    if (!DB.inventory[id]) DB.inventory[id] = { id, name: name||id, qty: 0 };
    DB.inventory[id].qty += qty || 1;
    saveDB(DB);
    return json(res, 200, DB.inventory[id]);
  }

  // ── Audit log ──
  if (pathname === '/api/log' && method === 'GET') {
    const user = getUser(req);
    if (!requireRole(res, user, 'admin')) return;
    return json(res, 200, DB.auditLog);
  }

  // ── Reports ──
  if (pathname === '/api/report' && method === 'GET') {
    const user = getUser(req);
    if (!requireAuth(res, user)) return;
    const filterJob = parsed.query.job || '';
    const jobs = Object.values(DB.jobs).filter(j => !filterJob || j.id.includes(filterJob));
    const staged = [], signedOut = [], overages = [];
    jobs.forEach(j => Object.values(j.parts).forEach(p => {
      const row = { job: j.id, ...p };
      if (p.status === 'staged') staged.push(row);
      else if (p.over) overages.push(row);
      else signedOut.push(row);
    }));
    return json(res, 200, { jobs: jobs.length, staged, signedOut, overages });
  }

  // 404
  json(res, 404, { error: 'Not found' });
});

function safeUser(u) {
  const { passwordHash, ...safe } = u;
  return safe;
}
function addAuditLog(type, jobId, partId, partName, user, extra) {
  DB.auditLog.unshift({ type, jobId, partId, partName, user, ts: now(), extra });
  if (DB.auditLog.length > 2000) DB.auditLog = DB.auditLog.slice(0, 2000);
}

server.listen(PORT, '0.0.0.0', () => {
  const isRailway = process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PUBLIC_DOMAIN;
  if (isRailway) {
    console.log(`\n🏭 Warehouse Tracker running on Railway`);
    console.log(`   Public URL: https://${process.env.RAILWAY_PUBLIC_DOMAIN || 'your-app.railway.app'}\n`);
  } else {
    console.log(`\n🏭 Warehouse Tracker running at http://localhost:${PORT}`);
    console.log(`   On same WiFi devices use your computer IP instead of localhost\n`);
  }
});
