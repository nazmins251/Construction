const express = require('express');
const { DatabaseSync } = require('node:sqlite'); // built into Node, no install needed
const crypto = require('crypto');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'data.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS app_users (
    username   TEXT PRIMARY KEY,
    pass_salt  TEXT NOT NULL,
    pass_hash  TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'admin',      -- 'admin' | 'readonly'
    name       TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    phone      TEXT NOT NULL DEFAULT '',
    photo      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS app_sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

const ALLOWED = ['labours', 'attendance', 'materials', 'incomes', 'expenses', 'advances', 'weeklyPays', 'monthlyPays', 'tasks'];
const OWNER = 'faiz';                       // primary admin, can manage profiles
const SESSION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ---------- password helpers ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const a = Buffer.from(crypto.scryptSync(password, salt, 64).toString('hex'));
  const b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- seed the primary admin on first run ----------
if (!db.prepare('SELECT 1 FROM app_users WHERE username = ?').get(OWNER)) {
  const { salt, hash } = hashPassword('12345');
  db.prepare('INSERT INTO app_users (username, pass_salt, pass_hash, role, name) VALUES (?, ?, ?, ?, ?)')
    .run(OWNER, salt, hash, 'admin', 'Faiz');
  console.log('Created default admin "faiz" with password 12345 (change it after logging in)');
}

function publicUser(u) {
  return {
    username: u.username,
    name: u.name || u.username,
    email: u.email || '',
    phone: u.phone || '',
    photo: u.photo || '',
    role: u.role,
    isOwner: u.username === OWNER
  };
}

// ---------- sessions ----------
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function createSession(res, username) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO app_sessions (token, username, expires_at) VALUES (?, ?, ?)')
    .run(token, username, Date.now() + SESSION_MS);
  res.setHeader('Set-Cookie',
    `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}`);
}

function auth(req, res, next) {
  const token = parseCookies(req).sid;
  if (token) {
    const s = db.prepare('SELECT username, expires_at FROM app_sessions WHERE token = ?').get(token);
    if (s && s.expires_at > Date.now()) {
      const u = db.prepare('SELECT * FROM app_users WHERE username = ?').get(s.username);
      if (u) { req.user = u; req.token = token; return next(); }
    }
    db.prepare('DELETE FROM app_sessions WHERE token = ?').run(token);
  }
  res.status(401).json({ error: 'Not signed in' });
}

// very small brute-force guard: 10 failed logins per 15 min per IP+username
const attempts = new Map();
function tooManyAttempts(key) {
  const a = attempts.get(key);
  return a && a.count >= 10 && Date.now() - a.first < 15 * 60 * 1000;
}
function noteFailure(key) {
  const a = attempts.get(key);
  if (!a || Date.now() - a.first > 15 * 60 * 1000) attempts.set(key, { count: 1, first: Date.now() });
  else a.count++;
}

const app = express();
app.use(express.json({ limit: '10mb' }));

// ---------- auth routes ----------
app.post('/api/login', (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const key = req.ip + '|' + username.toLowerCase();
  if (tooManyAttempts(key)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });

  const u = db.prepare('SELECT * FROM app_users WHERE username = ? COLLATE NOCASE').get(username);
  if (!u || !verifyPassword(password, u.pass_salt, u.pass_hash)) {
    noteFailure(key);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  attempts.delete(key);
  createSession(res, u.username);
  res.json({ user: publicUser(u) });
});

app.post('/api/logout', (req, res) => {
  const token = parseCookies(req).sid;
  if (token) db.prepare('DELETE FROM app_sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.put('/api/me', auth, (req, res) => {
  const b = req.body || {};
  const cur = req.user;
  const name = b.name !== undefined ? String(b.name).trim() : cur.name;
  const email = b.email !== undefined ? String(b.email).trim() : cur.email;
  const phone = b.phone !== undefined ? String(b.phone).trim() : cur.phone;
  const photo = b.photo !== undefined ? String(b.photo) : cur.photo;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  if (photo && !/^data:image\/(jpeg|png|webp);base64,/.test(photo)) {
    return res.status(400).json({ error: 'Invalid image' });
  }
  db.prepare('UPDATE app_users SET name = ?, email = ?, phone = ?, photo = ? WHERE username = ?')
    .run(name, email, phone, photo, cur.username);
  const u = db.prepare('SELECT * FROM app_users WHERE username = ?').get(cur.username);
  res.json({ user: publicUser(u) });
});

app.put('/api/me/password', auth, (req, res) => {
  const current = String((req.body && req.body.current) || '');
  const next = String((req.body && req.body.next) || '');
  if (!verifyPassword(current, req.user.pass_salt, req.user.pass_hash)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  if (next.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const { salt, hash } = hashPassword(next);
  db.prepare('UPDATE app_users SET pass_salt = ?, pass_hash = ? WHERE username = ?')
    .run(salt, hash, req.user.username);
  // sign out other sessions of this user
  db.prepare('DELETE FROM app_sessions WHERE username = ? AND token != ?').run(req.user.username, req.token);
  res.json({ ok: true });
});

// ---------- profile management (owner only) ----------
function ownerOnly(req, res, next) {
  if (req.user.username !== OWNER) return res.status(403).json({ error: 'Only the primary admin can do this' });
  next();
}

app.get('/api/users', auth, ownerOnly, (req, res) => {
  const users = db.prepare('SELECT username, name, role, created_at FROM app_users ORDER BY created_at').all();
  res.json({ users });
});

app.post('/api/users', auth, ownerOnly, (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const role = req.body && req.body.role;
  if (!/^[\w.-]{2,32}$/.test(username)) return res.status(400).json({ error: 'Username must be 2-32 letters, numbers, . _ -' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!['admin', 'readonly'].includes(role)) return res.status(400).json({ error: 'Invalid access level' });
  if (db.prepare('SELECT 1 FROM app_users WHERE username = ? COLLATE NOCASE').get(username)) {
    return res.status(400).json({ error: 'That username already exists' });
  }
  const { salt, hash } = hashPassword(password);
  db.prepare('INSERT INTO app_users (username, pass_salt, pass_hash, role, name) VALUES (?, ?, ?, ?, ?)')
    .run(username, salt, hash, role, username);
  res.json({ ok: true });
});

app.put('/api/users/:username', auth, ownerOnly, (req, res) => {
  const target = db.prepare('SELECT * FROM app_users WHERE username = ?').get(req.params.username);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.username === OWNER) return res.status(400).json({ error: 'The primary admin cannot be changed here' });
  const b = req.body || {};
  if (b.role !== undefined) {
    if (!['admin', 'readonly'].includes(b.role)) return res.status(400).json({ error: 'Invalid access level' });
    db.prepare('UPDATE app_users SET role = ? WHERE username = ?').run(b.role, target.username);
  }
  if (b.password) {
    if (String(b.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const { salt, hash } = hashPassword(String(b.password));
    db.prepare('UPDATE app_users SET pass_salt = ?, pass_hash = ? WHERE username = ?').run(salt, hash, target.username);
    db.prepare('DELETE FROM app_sessions WHERE username = ?').run(target.username); // force re-login
  }
  res.json({ ok: true });
});

app.delete('/api/users/:username', auth, ownerOnly, (req, res) => {
  if (req.params.username === OWNER) return res.status(400).json({ error: 'The primary admin cannot be deleted' });
  const r = db.prepare('DELETE FROM app_users WHERE username = ?').run(req.params.username);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM app_sessions WHERE username = ?').run(req.params.username);
  res.json({ ok: true });
});

// ---------- data ----------
app.get('/api/data', auth, (req, res) => {
  const out = {};
  db.prepare('SELECT key, value FROM store').all()
    .forEach(r => { out[r.key] = JSON.parse(r.value); });
  res.json(out);
});

app.put('/api/data/:key', auth, (req, res) => {
  if (req.user.role === 'readonly') return res.status(403).json({ error: 'Read-only access' });
  if (!ALLOWED.includes(req.params.key)) return res.status(400).json({ error: 'unknown key' });
  db.prepare(`INSERT INTO store (key, value) VALUES (?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
    .run(req.params.key, JSON.stringify(req.body));
  res.json({ ok: true });
});

// ---------- serve the app (only index.html and the images) ----------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get(/^\/[\w.-]+\.(jpg|jpeg|png|gif|webp|svg|ico)$/i, (req, res) =>
  res.sendFile(path.join(__dirname, req.path)));

// clean out expired sessions on startup
db.prepare('DELETE FROM app_sessions WHERE expires_at < ?').run(Date.now());

app.listen(3000, () => console.log('Open http://localhost:3000'));
