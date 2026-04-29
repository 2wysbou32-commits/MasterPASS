const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// R2 via API HTTP directe (pas de SDK — évite les problèmes SSL)
const crypto = require('crypto');
const https = require('https');
const { Resend } = require('resend');

// Email (Resend) — optionnel, fonctionne sans si RESEND_API_KEY non défini
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev';
const SITE_URL = process.env.SITE_URL || 'http://localhost:3000';

const app = express();
const PORT = process.env.PORT || 3000;

// ── Cloudflare R2 config (variables d'environnement) ─────────────────────────
const R2_ACCOUNT_ID    = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_KEY    = process.env.R2_SECRET_KEY;
const R2_BUCKET_NAME   = process.env.R2_BUCKET_NAME || 'masterpass';

let r2Enabled = false;
if (R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_KEY) {
  r2Enabled = true;
  console.log('✅ Cloudflare R2 activé — bucket:', R2_BUCKET_NAME);
} else {
  console.log('⚠️  R2 non configuré → stockage local (dev uniquement)');
}

// ── Helpers crypto ────────────────────────────────────────────────────────────
function hmac(key, data, encoding) {
  return crypto.createHmac('sha256', key).update(data).digest(encoding || undefined);
}
function hashSHA256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Encode chaque segment du path R2 séparément (conserve les /)
// C'est la SEULE méthode d'encodage utilisée partout dans ce fichier
function encodeR2Key(key) {
  return key.split('/').map(s => encodeURIComponent(s)).join('/');
}

// Ancien encodage (avant correction) : encodeURIComponent sur toute la clé, les / deviennent %2F
// Nécessaire pour lire les fichiers uploadés avec l'ancien code
function encodeR2KeyLegacy(key) {
  return encodeURIComponent(key);
}

// ── Signature AWS v4 — header Authorization (pour PUT/DELETE via serveur) ─────
function buildAuthHeader(method, key, contentType, bodyHash, date, region) {
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const datetime = date.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateShort = datetime.slice(0, 8);
  const scope = `${dateShort}/${region}/s3/aws4_request`;

  // Le canonical path doit utiliser les segments encodés séparément
  const canonicalPath = `/${R2_BUCKET_NAME}/${encodeR2Key(key)}`;

  const canonicalHeaders = `content-type:${contentType}\nhost:${host}\nx-amz-content-sha256:${bodyHash}\nx-amz-date:${datetime}\n`;
  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [method, canonicalPath, '', canonicalHeaders, signedHeaders, bodyHash].join('\n');

  const stringToSign = ['AWS4-HMAC-SHA256', datetime, scope, hashSHA256(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateShort), region), 's3'), 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');

  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    datetime,
    host,
    canonicalPath,
  };
}


// ── Paths ─────────────────────────────────────────────────────────────────────
const DATA_DIR    = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE   = path.join(DATA_DIR, 'db.json');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── DB ────────────────────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DATA_FILE)) return initDB();
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return initDB(); }
}
function saveDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function initDB() {
  const db = {
    nextId: 10,
    users: [{ id: 1, name: 'Administrateur Principal', login: 'admin', password: bcrypt.hashSync('admin123', 10), role: 'admin' }],
    folders: [],
    inviteCodes: [],
  };
  saveDB(db); return db;
}

// ── Reset tokens (en mémoire, valides 15 min) ────────────────────────────────
const resetTokens = {};

function generateToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// ── Codes d'invitation ────────────────────────────────────────────────────────
function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 12; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// ── Multer → mémoire (puis R2 ou disque) ─────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 * 1024 } });

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

const sessionsDir = path.join(__dirname, 'data', 'sessions');
if (!fs.existsSync(sessionsDir)) fs.mkdirSync(sessionsDir, { recursive: true });

app.use(session({
  store: new FileStore({
    path: sessionsDir,
    ttl: 28800,
    retries: 1,
    logFn: () => {},
  }),
  secret: process.env.SESSION_SECRET || 'masterpass-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 8 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
}));

const publicDir = fs.existsSync(path.join(__dirname, 'public'))
  ? path.join(__dirname, 'public')
  : __dirname;
app.use(express.static(publicDir));

// ── Auth guards ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  next();
}
// Admin principal uniquement (comptes, codes, stats)
function requireSuperAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé — admin principal requis' });
  next();
}

// Admin principal OU sous-admin (fichiers uniquement)
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user || (user.role !== 'admin' && user.role !== 'subadmin')) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  next();
}

// ── R2 helpers ────────────────────────────────────────────────────────────────
async function uploadToR2(key, buffer, contentType) {
  const ct = contentType || 'application/octet-stream';
  const bodyHash = hashSHA256(buffer);
  const date = new Date();
  const region = 'auto';
  const { authorization, datetime, host, canonicalPath } = buildAuthHeader('PUT', key, ct, bodyHash, date, region);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: host,
      port: 443,
      // Utiliser le même canonicalPath que la signature (segments encodés séparément)
      path: canonicalPath,
      method: 'PUT',
      rejectUnauthorized: false,
      secureProtocol: 'TLSv1_2_method',
      headers: {
        'Content-Type': ct,
        'Content-Length': buffer.length,
        'x-amz-content-sha256': bodyHash,
        'x-amz-date': datetime,
        'Authorization': authorization,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve();
        else reject(new Error(`R2 upload failed: ${res.statusCode} ${data}`));
      });
    });
    req.on('error', reject);
    req.write(buffer);
    req.end();
  });
}

async function deleteFromR2(key) {
  try {
    const bodyHash = hashSHA256('');
    const date = new Date();
    const { authorization, datetime, host, canonicalPath } = buildAuthHeader('DELETE', key, 'application/octet-stream', bodyHash, date, 'auto');
    await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: host,
        port: 443,
        path: canonicalPath,
        method: 'DELETE',
        rejectUnauthorized: false,
        secureProtocol: 'TLSv1_2_method',
        headers: {
          'Content-Type': 'application/octet-stream',
          'x-amz-content-sha256': bodyHash,
          'x-amz-date': datetime,
          'Authorization': authorization,
        },
      }, (res) => { res.on('data', ()=>{}); res.on('end', resolve); });
      req.on('error', reject);
      req.end();
    });
  } catch(e) { console.error('R2 delete error:', e.message); }
}

// Construit les headers de signature pour une requête GET R2
function buildR2GetHeaders(canonicalPath, host, region, amzDate, dateStamp, bodyHash) {
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${bodyHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = ['GET', canonicalPath, '', canonicalHeaders, signedHeaders, bodyHash].join('\n');
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, hashSHA256(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateStamp), region), 's3'), 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');
  return {
    'host': host,
    'x-amz-content-sha256': bodyHash,
    'x-amz-date': amzDate,
    'Authorization': `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

// Effectue une requête GET vers R2 avec un path donné
function r2GetRequest(host, canonicalPath, reqHeaders) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: host,
      port: 443,
      path: canonicalPath,
      method: 'GET',
      rejectUnauthorized: false,
      headers: reqHeaders,
    }, resolve);
    req.on('error', reject);
    req.end();
  });
}

// Proxy fichier depuis R2 — essaie le nouvel encodage puis l'ancien (legacy) si 404
async function proxyFileFromR2(key, res, inline, originalReq) {
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const bodyHash = hashSHA256('');

  // Les deux encodages possibles selon comment le fichier a été uploadé
  const pathNew    = `/${R2_BUCKET_NAME}/${encodeR2Key(key)}`;       // Nouveau : segments séparés
  const pathLegacy = `/${R2_BUCKET_NAME}/${encodeR2KeyLegacy(key)}`; // Ancien : tout encodé (les / = %2F)

  // Fonction qui construit les headers et envoie la requête
  async function tryPath(canonicalPath) {
    const extraRange = (originalReq && originalReq.headers && originalReq.headers.range)
      ? { 'Range': originalReq.headers.range } : {};
    const headers = { ...buildR2GetHeaders(canonicalPath, host, region, amzDate, dateStamp, bodyHash), ...extraRange };
    return r2GetRequest(host, canonicalPath, headers);
  }

  let r2res;
  try {
    r2res = await tryPath(pathNew);
    if (r2res.statusCode === 404) {
      // Fichier introuvable avec le nouvel encodage → essayer l'ancien
      console.log('[R2] 404 nouveau encodage, tentative legacy pour:', key);
      r2res.resume(); // vider la réponse 404
      r2res = await tryPath(pathLegacy);
    }
  } catch(e) {
    return Promise.reject(e);
  }

  return new Promise((resolve, reject) => {
    if (r2res.statusCode >= 400) {
      let errData = '';
      r2res.on('data', c => errData += c);
      r2res.on('end', () => reject(new Error(`R2 fetch failed: ${r2res.statusCode} ${errData}`)));
      return;
    }
    const ct = r2res.headers['content-type'] || 'application/octet-stream';
    const cl = r2res.headers['content-length'];
    const cr = r2res.headers['content-range'];
    const al = r2res.headers['accept-ranges'];
    res.status(r2res.statusCode);
    res.setHeader('Content-Type', ct);
    if (cl) res.setHeader('Content-Length', cl);
    if (cr) res.setHeader('Content-Range', cr);
    if (al) res.setHeader('Accept-Ranges', al);
    else res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Disposition', inline ? 'inline' : 'attachment');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    r2res.pipe(res);
    r2res.on('end', resolve);
  });
}

// URL signée pour streaming vidéo — essaie nouveau encodage, fallback legacy
function getSignedVideoUrl(r2Key, useLegacy) {
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]/g, '').replace(/\.\.\d{3}/, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const expires = 7200;
  const credential = `${R2_ACCESS_KEY_ID}/${dateStamp}/${region}/s3/aws4_request`;

  const encodedPath = useLegacy
    ? `/${R2_BUCKET_NAME}/${encodeR2KeyLegacy(r2Key)}`
    : `/${R2_BUCKET_NAME}/${encodeR2Key(r2Key)}`;

  const params = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', credential],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders', 'host'],
  ].sort((a, b) => encodeURIComponent(a[0]) < encodeURIComponent(b[0]) ? -1 : 1);

  const qs = params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');

  const canonicalReq = [
    'GET',
    encodedPath,
    qs,
    `host:${host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, hashSHA256(canonicalReq)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateStamp), region), 's3'), 'aws4_request');
  const sig = hmac(signingKey, toSign, 'hex');

  return `https://${host}${encodedPath}?${qs}&X-Amz-Signature=${sig}`;
}
// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  const user = loadDB().users.find(u => u.login === login);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect' });
  req.session.userId = user.id;
  req.session.save((err) => {
    if (err) console.log('[SESSION] Save error:', err);
    else console.log('[SESSION] Saved — sessionID:', req.sessionID, '— userId:', user.id);
  });
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role, email: user.email || '' });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Session invalide' });
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role, email: user.email || '' });
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireSuperAdmin, (req, res) => {
  res.json(loadDB().users.map(u => ({ id: u.id, name: u.name, login: u.login, role: u.role, email: u.email || '', mineure: u.mineure || '' })));
});
app.post('/api/users', requireSuperAdmin, (req, res) => {
  const { name, login, password, role } = req.body;
  if (!name || !login || !password || !['admin','subadmin','student'].includes(role))
    return res.status(400).json({ error: 'Données invalides' });
  const db = loadDB();
  if (db.users.find(u => u.login === login))
    return res.status(409).json({ error: 'Identifiant déjà utilisé' });
  const u = { id: db.nextId++, name, login, password: bcrypt.hashSync(password, 10), role };
  db.users.push(u); saveDB(db);
  res.json({ id: u.id, name, login, role });
});
app.delete('/api/users/:id', requireSuperAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.session.userId) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  const db = loadDB(); db.users = db.users.filter(u => u.id !== id); saveDB(db);
  res.json({ ok: true });
});

// ── FOLDERS ───────────────────────────────────────────────────────────────────
app.get('/api/folders', requireAuth, (req, res) => {
  const db = loadDB();
  res.json(db.folders.map(f => ({
    id: f.id, name: f.name, createdAt: f.createdAt,
    fileCount: (f.files||[]).length,
    totalSize: (f.files||[]).reduce((s,fi) => s+fi.size, 0),
  })));
});
app.post('/api/folders', requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom requis' });
  const db = loadDB();
  const folder = { id: db.nextId++, name: name.trim(), createdAt: new Date().toISOString().split('T')[0], files: [] };
  db.folders.push(folder); saveDB(db);
  res.json({ id: folder.id, name: folder.name, createdAt: folder.createdAt, fileCount: 0, totalSize: 0 });
});
app.delete('/api/folders/:id', requireAdmin, async (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.id));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  for (const file of (folder.files||[])) {
    if (r2Enabled && file.r2Key) await deleteFromR2(file.r2Key);
    else if (file.filename) { const p = path.join(UPLOADS_DIR, file.filename); if (fs.existsSync(p)) fs.unlinkSync(p); }
  }
  db.folders = db.folders.filter(f => f.id !== parseInt(req.params.id)); saveDB(db);
  res.json({ ok: true });
});

// ── SOUS-DOSSIERS ─────────────────────────────────────────────────────────────
app.post('/api/folders/:id/subfolders', requireAdmin, (req, res) => {
  const parentId = parseInt(req.params.id);
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom requis' });
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parentId);
  if (!parent) return res.status(404).json({ error: 'Dossier parent introuvable' });
  if (!parent.subfolders) parent.subfolders = [];
  const sub = { id: db.nextId++, name: name.trim(), createdAt: new Date().toISOString().split('T')[0], files: [] };
  parent.subfolders.push(sub);
  saveDB(db);
  res.json({ id: sub.id, name: sub.name, createdAt: sub.createdAt, fileCount: 0, totalSize: 0 });
});

app.get('/api/folders/:id/subfolders', requireAuth, (req, res) => {
  const parentId = parseInt(req.params.id);
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parentId);
  if (!parent) return res.status(404).json({ error: 'Dossier introuvable' });
  const subs = (parent.subfolders || []).map(s => ({
    id: s.id, name: s.name, createdAt: s.createdAt,
    fileCount: (s.files || []).length,
    totalSize: (s.files || []).reduce((a, f) => a + f.size, 0),
  }));
  res.json(subs);
});

app.delete('/api/folders/:parentId/subfolders/:subId', requireAdmin, async (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  if (!parent) return res.status(404).json({ error: 'Dossier introuvable' });
  const sub = (parent.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  if (!sub) return res.status(404).json({ error: 'Sous-dossier introuvable' });
  for (const file of (sub.files || [])) {
    if (r2Enabled && file.r2Key) await deleteFromR2(file.r2Key);
  }
  parent.subfolders = parent.subfolders.filter(s => s.id !== parseInt(req.params.subId));
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/folders/:parentId/subfolders/:subId/files', requireAuth, (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  if (!parent) return res.status(404).json({ error: 'Dossier introuvable' });
  const sub = (parent.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  if (!sub) return res.status(404).json({ error: 'Sous-dossier introuvable' });
  const requestingUser = db.users.find(u => u.id === req.session.userId);
  const isAdmin = requestingUser?.role === 'admin';
  const now = Date.now();
  res.json((sub.files || [])
    .filter(f => {
      if (f.pending) {
        const addedTime = new Date(f.addedAt).getTime();
        if (now - addedTime > 2 * 60 * 1000) { f.pending = false; saveDB(db); }
      }
      return isAdmin || !f.pending;
    })
    .map(f => ({ id: f.id, name: f.name, size: f.size, type: f.type, addedAt: f.addedAt, downloadable: f.downloadable !== false })));
});

app.post('/api/folders/:parentId/subfolders/:subId/files', requireAdmin, upload.array('files'), async (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  if (!parent) return res.status(404).json({ error: 'Dossier introuvable' });
  const sub = (parent.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  if (!sub) return res.status(404).json({ error: 'Sous-dossier introuvable' });
  if (!req.files?.length) return res.status(400).json({ error: 'Aucun fichier' });
  const added = [];
  for (const file of req.files) {
    const ext = path.extname(file.originalname).replace('.', '').toLowerCase();
    const type = getFileType(ext);
    const fileId = db.nextId++;
    let record;
    if (r2Enabled) {
      const r2Key = `files/${req.params.parentId}/sub${req.params.subId}/${fileId}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      await uploadToR2(r2Key, file.buffer, file.mimetype);
      record = { id: fileId, name: file.originalname, size: file.size, type, addedAt: new Date().toISOString().split('T')[0], r2Key, downloadable: true };
    } else {
      const filename = `${fileId}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      fs.writeFileSync(path.join(UPLOADS_DIR, filename), file.buffer);
      record = { id: fileId, name: file.originalname, size: file.size, type, addedAt: new Date().toISOString().split('T')[0], filename, downloadable: true };
    }
    sub.files.push(record);
    added.push({ id: record.id, name: record.name, size: record.size, type: record.type, addedAt: record.addedAt });
  }
  saveDB(db);
  res.json(added);
});

app.get('/api/folders/:parentId/subfolders/:subId/files/:fileId/download', requireAuth, async (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (parent?.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files || []).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (user?.role !== 'admin') {
    if (file.type === 'video') return res.status(403).json({ error: 'Les vidéos ne peuvent pas être téléchargées' });
    if (file.downloadable === false) return res.status(403).json({ error: 'Téléchargement non autorisé' });
  }
  if (r2Enabled && file.r2Key) { await proxyFileFromR2(file.r2Key, res, false, req); return; }
  if (file.filename) { const p = path.join(UPLOADS_DIR, file.filename); if (fs.existsSync(p)) return res.download(p, file.name); }
  res.status(500).json({ error: 'Erreur stockage' });
});

app.get('/api/folders/:parentId/subfolders/:subId/files/:fileId/preview', requireAuth, async (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (parent?.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files || []).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  if (r2Enabled && file.r2Key) { await proxyFileFromR2(file.r2Key, res, true, req); return; }
  if (file.filename) { const p = path.join(UPLOADS_DIR, file.filename); if (fs.existsSync(p)) return res.sendFile(p); }
  res.status(500).json({ error: 'Erreur stockage' });
});

app.delete('/api/folders/:parentId/subfolders/:subId/files/:fileId', requireAdmin, async (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (parent?.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files || []).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  if (r2Enabled && file.r2Key) await deleteFromR2(file.r2Key);
  sub.files = sub.files.filter(f => f.id !== parseInt(req.params.fileId));
  saveDB(db);
  res.json({ ok: true });
});

// ── STREAM VIDÉO ──────────────────────────────────────────────────────────────
app.get('/api/folders/:folderId/files/:fileId/stream', requireAuth, (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file || file.type !== 'video') return res.status(404).json({ error: 'Fichier introuvable' });
  if (!r2Enabled || !file.r2Key) {
    return res.json({ url: null, fallback: `/api/folders/${req.params.folderId}/files/${req.params.fileId}/preview` });
  }
  try {
    const signedUrl = getSignedVideoUrl(file.r2Key, false);
    const legacyUrl = getSignedVideoUrl(file.r2Key, true);
    console.log('[STREAM] URL générée pour:', file.r2Key);
    res.json({ url: signedUrl, urlLegacy: legacyUrl });
  } catch(e) {
    console.error('[STREAM] Erreur:', e.message);
    res.status(500).json({ error: 'Erreur génération URL' });
  }
});

app.get('/api/folders/:parentId/subfolders/:subId/files/:fileId/stream', requireAuth, (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (parent?.subfolders||[]).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file || file.type !== 'video') return res.status(404).json({ error: 'Fichier introuvable' });
  if (!r2Enabled || !file.r2Key) {
    return res.json({ url: null, fallback: `/api/folders/${req.params.parentId}/subfolders/${req.params.subId}/files/${req.params.fileId}/preview` });
  }
  try {
    const signedUrl = getSignedVideoUrl(file.r2Key, false);
    const legacyUrl = getSignedVideoUrl(file.r2Key, true);
    console.log('[STREAM] URL générée pour:', file.r2Key);
    res.json({ url: signedUrl, urlLegacy: legacyUrl });
  } catch(e) {
    console.error('[STREAM] Erreur:', e.message);
    res.status(500).json({ error: 'Erreur génération URL' });
  }
});

app.patch('/api/folders/:parentId/subfolders/:subId/files/:fileId/downloadable', requireAdmin, (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (parent?.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files || []).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  file.downloadable = !file.downloadable;
  saveDB(db);
  res.json({ id: file.id, downloadable: file.downloadable });
});

// ── FILES ─────────────────────────────────────────────────────────────────────
app.get('/api/folders/:id/files', requireAuth, (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.id));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const requestingUser = db.users.find(u => u.id === req.session.userId);
  const isAdmin = requestingUser?.role === 'admin';
  const now = Date.now();
  res.json((folder.files||[])
    .filter(f => {
      if (f.pending) {
        const addedTime = new Date(f.addedAt).getTime();
        if (now - addedTime > 2 * 60 * 1000) { f.pending = false; saveDB(db); }
      }
      return isAdmin || !f.pending;
    })
    .map(f => ({ id: f.id, name: f.name, size: f.size, type: f.type, addedAt: f.addedAt, downloadable: f.downloadable !== false })));
});

app.post('/api/folders/:id/files', requireAdmin, upload.array('files'), async (req, res) => {
  const folderId = parseInt(req.params.id);
  const db = loadDB();
  const folder = db.folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  if (!req.files?.length) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const added = [];
  for (const file of req.files) {
    const ext = path.extname(file.originalname).replace('.','').toLowerCase();
    const type = getFileType(ext);
    const fileId = db.nextId++;
    let record;

    if (r2Enabled) {
      const safeBase = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
      const r2Key = `files/${folderId}/${fileId}-${safeBase}`;
      await uploadToR2(r2Key, file.buffer, file.mimetype);
      record = { id: fileId, name: file.originalname, size: file.size, type, addedAt: new Date().toISOString().split('T')[0], r2Key, downloadable: true };
    } else {
      const filename = `${fileId}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      fs.writeFileSync(path.join(UPLOADS_DIR, filename), file.buffer);
      record = { id: fileId, name: file.originalname, size: file.size, type, addedAt: new Date().toISOString().split('T')[0], filename, downloadable: true };
    }
    folder.files.push(record);
    added.push({ id: record.id, name: record.name, size: record.size, type: record.type, addedAt: record.addedAt });
  }
  saveDB(db);
  res.json(added);
});

app.get('/api/folders/:folderId/files/:fileId/preview', requireAuth, async (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });

  if (r2Enabled && file.r2Key) {
    await proxyFileFromR2(file.r2Key, res, true, req);
    return;
  } else if (file.filename) {
    const p = path.join(UPLOADS_DIR, file.filename);
    if (!fs.existsSync(p)) return res.status(404).json({ error: 'Fichier manquant' });
    return res.sendFile(p);
  }
  res.status(500).json({ error: 'Erreur stockage' });
});

app.get('/api/folders/:folderId/files/:fileId/download', requireAuth, async (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  const requestingUser = db.users.find(u => u.id === req.session.userId);
  if (requestingUser?.role !== 'admin') {
    if (file.type === 'video') return res.status(403).json({ error: 'Les vidéos ne peuvent pas être téléchargées' });
    if (file.downloadable === false) return res.status(403).json({ error: "Téléchargement non autorisé par l'administrateur" });
  }

  if (r2Enabled && file.r2Key) {
    await proxyFileFromR2(file.r2Key, res, false, req);
    return;
  } else if (file.filename) {
    const p = path.join(UPLOADS_DIR, file.filename);
    if (!fs.existsSync(p)) return res.status(404).json({ error: 'Fichier manquant' });
    return res.download(p, file.name);
  }
  res.status(500).json({ error: 'Erreur de configuration stockage' });
});

app.patch('/api/folders/:folderId/files/:fileId/downloadable', requireAdmin, (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  file.downloadable = !file.downloadable;
  saveDB(db);
  res.json({ id: file.id, downloadable: file.downloadable });
});

app.delete('/api/folders/:folderId/files/:fileId', requireAdmin, async (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  if (r2Enabled && file.r2Key) await deleteFromR2(file.r2Key);
  else if (file.filename) { const p = path.join(UPLOADS_DIR, file.filename); if (fs.existsSync(p)) fs.unlinkSync(p); }
  folder.files = folder.files.filter(f => f.id !== parseInt(req.params.fileId));
  saveDB(db); res.json({ ok: true });
});

// ── MOT DE PASSE OUBLIÉ ───────────────────────────────────────────────────────
app.post('/api/forgot-password', async (req, res) => {
  const { login } = req.body;
  if (!login) return res.status(400).json({ error: 'Identifiant requis' });
  const db = loadDB();
  const user = db.users.find(u => u.login === login);
  if (!user || !user.email) {
    return res.json({ ok: true, message: 'Si ce compte existe et a un email, un lien a été envoyé.' });
  }
  const token = generateToken();
  resetTokens[token] = { userId: user.id, expires: Date.now() + 15 * 60 * 1000 };
  const resetLink = `${SITE_URL}?reset=${token}`;
  if (resend) {
    try {
      const emailResult = await resend.emails.send({
        from: FROM_EMAIL,
        to: user.email,
        subject: 'MasterPASS — Réinitialisation de mot de passe',
        html: `
          <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
            <h2 style="color:#004D61;margin-bottom:8px">Réinitialisation de mot de passe</h2>
            <p style="color:#3D6B6F;margin-bottom:24px">Bonjour ${user.name},<br><br>
            Tu as demandé à réinitialiser ton mot de passe MasterPASS.<br>
            Clique sur le bouton ci-dessous pour choisir un nouveau mot de passe.</p>
            <a href="${resetLink}" style="display:inline-block;background:linear-gradient(135deg,#0097A7,#006064);color:white;padding:14px 28px;border-radius:12px;text-decoration:none;font-weight:700;font-size:15px">
              Réinitialiser mon mot de passe
            </a>
            <p style="color:#9E9E9E;font-size:12px;margin-top:24px">
              Ce lien est valable 15 minutes.<br>
              Si tu n'es pas à l'origine de cette demande, ignore cet email.
            </p>
          </div>`,
      });
      console.log('[EMAIL] Envoyé, id:', emailResult?.id);
    } catch(e) { console.error('[EMAIL] Erreur:', e.message); }
  } else {
    console.log('RESET LINK:', resetLink);
  }
  res.json({ ok: true, resetLink: resetLink });
});

app.get('/api/reset-token/:token', (req, res) => {
  const entry = resetTokens[req.params.token];
  if (!entry || Date.now() > entry.expires) {
    return res.status(400).json({ error: 'Lien invalide ou expiré' });
  }
  const user = loadDB().users.find(u => u.id === entry.userId);
  res.json({ valid: true, name: user?.name || '' });
});

app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 6) {
    return res.status(400).json({ error: 'Données invalides (mot de passe min. 6 caractères)' });
  }
  const entry = resetTokens[token];
  if (!entry || Date.now() > entry.expires) {
    return res.status(400).json({ error: 'Lien invalide ou expiré' });
  }
  const db = loadDB();
  const user = db.users.find(u => u.id === entry.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.password = bcrypt.hashSync(password, 10);
  saveDB(db);
  delete resetTokens[token];
  res.json({ ok: true });
});

// ── RÉGLAGES UTILISATEUR ──────────────────────────────────────────────────────
app.patch('/api/users/:id/email', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  const requestingUser = loadDB().users.find(u => u.id === req.session.userId);
  if (requestingUser.id !== id && requestingUser.role !== 'admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  const { email } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.email = email;
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/users/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Données invalides (nouveau mot de passe min. 6 caractères)' });
  }
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  }
  user.password = bcrypt.hashSync(newPassword, 10);
  saveDB(db);
  res.json({ ok: true });
});

// ── PRESIGN — upload direct navigateur → R2 ───────────────────────────────────
app.post('/api/folders/:id/presign', requireAdmin, (req, res) => {
  const folderId = parseInt(req.params.id);
  const db = loadDB();
  const folder = db.folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });

  const { filename, contentType, size } = req.body;
  if (!filename || !contentType) return res.status(400).json({ error: 'Données manquantes' });

  const fileId = db.nextId++;
  const ext = filename.split('.').pop().toLowerCase();
  const safeBase = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const r2Key = `files/${folderId}/${fileId}-${safeBase}`;

  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const expires = 7200;
  const credential = `${R2_ACCESS_KEY_ID}/${dateStamp}/${region}/s3/aws4_request`;

  const qs = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', credential],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders', 'content-type;host'],
  ].sort((a, b) => a[0].localeCompare(b[0]));

  const canonicalQS = qs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const encodedR2Path = `/${R2_BUCKET_NAME}/${encodeR2Key(r2Key)}`;
  const canonicalRequest = [
    'PUT',
    encodedR2Path,
    canonicalQS,
    `content-type:${contentType}\nhost:${host}\n`,
    'content-type;host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, hashSHA256(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateStamp), region), 's3'), 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');
  const putUrl = `https://${host}${encodedR2Path}?${canonicalQS}&X-Amz-Signature=${signature}`;

  const type = getFileType(ext);
  const today = new Date().toISOString().split('T')[0];
  const record = { id: fileId, name: filename, size: size || 0, type, addedAt: today, r2Key, downloadable: true, pending: true };
  folder.files.push(record);
  db.nextId = fileId + 1;
  saveDB(db);

  res.json({ putUrl, fileId, r2Key });
});

app.post('/api/folders/:parentId/subfolders/:subId/presign', requireAdmin, (req, res) => {
  const parentId = parseInt(req.params.parentId);
  const subId    = parseInt(req.params.subId);
  const db       = loadDB();
  const parent   = db.folders.find(f => f.id === parentId);
  if (!parent) return res.status(404).json({ error: 'Dossier introuvable' });
  const sub = (parent.subfolders || []).find(s => s.id === subId);
  if (!sub) return res.status(404).json({ error: 'Sous-dossier introuvable' });

  const { filename, contentType, size } = req.body;
  if (!filename || !contentType) return res.status(400).json({ error: 'Données manquantes' });

  const fileId    = db.nextId++;
  const safeBase  = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const r2Key     = `files/${parentId}/sub${subId}/${fileId}-${safeBase}`;
  const ext       = filename.split('.').pop().toLowerCase();
  const host      = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const region    = 'auto';
  const date      = new Date();
  const amzDate   = date.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const expires   = 7200;
  const credential = `${R2_ACCESS_KEY_ID}/${dateStamp}/${region}/s3/aws4_request`;

  const qs = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', credential],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(expires)],
    ['X-Amz-SignedHeaders', 'content-type;host'],
  ].sort((a, b) => a[0].localeCompare(b[0]));

  const canonicalQS = qs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const encodedR2Path = `/${R2_BUCKET_NAME}/${encodeR2Key(r2Key)}`;
  const canonicalRequest = [
    'PUT',
    encodedR2Path,
    canonicalQS,
    `content-type:${contentType}\nhost:${host}\n`,
    'content-type;host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const scope      = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, hashSHA256(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateStamp), region), 's3'), 'aws4_request');
  const signature  = hmac(signingKey, stringToSign, 'hex');
  const putUrl     = `https://${host}${encodedR2Path}?${canonicalQS}&X-Amz-Signature=${signature}`;

  const type   = getFileType(ext);
  const today  = new Date().toISOString().split('T')[0];
  const record = { id: fileId, name: filename, size: size || 0, type, addedAt: today, r2Key, downloadable: true, pending: true };
  sub.files.push(record);
  db.nextId = fileId + 1;
  saveDB(db);

  res.json({ putUrl, fileId, r2Key });
});

app.post('/api/folders/:parentId/subfolders/:subId/files/:fileId/confirm', requireAdmin, (req, res) => {
  const db     = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  if (!parent) return res.status(404).json({ error: 'Dossier introuvable' });
  const sub  = (parent.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  if (!sub)  return res.status(404).json({ error: 'Sous-dossier introuvable' });
  const file = (sub.files || []).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  file.pending = false;
  if (req.body.size) file.size = req.body.size;
  saveDB(db);
  res.json({ id: file.id, name: file.name, size: file.size, type: file.type, addedAt: file.addedAt });
});

app.post('/api/folders/:folderId/files/:fileId/confirm', requireAdmin, (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = folder.files.find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  file.pending = false;
  if (req.body.size) file.size = req.body.size;
  saveDB(db);
  res.json({ id: file.id, name: file.name, size: file.size, type: file.type, addedAt: file.addedAt });
});

// ── CODES D'INVITATION ───────────────────────────────────────────────────────

// Générer N codes (admin)
app.post('/api/invite-codes/generate', requireSuperAdmin, (req, res) => {
  const count = Math.min(parseInt(req.body.count) || 1, 100);
  const db = loadDB();
  if (!db.inviteCodes) db.inviteCodes = [];
  const newCodes = [];
  for (let i = 0; i < count; i++) {
    let code;
    do { code = generateInviteCode(); } while (db.inviteCodes.find(c => c.code === code));
    const entry = { code, createdAt: new Date().toISOString(), usedAt: null, usedBy: null };
    db.inviteCodes.push(entry);
    newCodes.push(entry);
  }
  saveDB(db);
  res.json(newCodes);
});

// Lister tous les codes (admin)
app.get('/api/invite-codes', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  res.json((db.inviteCodes || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

// Supprimer un code (admin)
app.delete('/api/invite-codes/:code', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.inviteCodes) db.inviteCodes = [];
  db.inviteCodes = db.inviteCodes.filter(c => c.code !== req.params.code);
  saveDB(db);
  res.json({ ok: true });
});

// Supprimer tous les codes utilisés (admin)
app.delete('/api/invite-codes/used/all', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.inviteCodes) db.inviteCodes = [];
  const before = db.inviteCodes.length;
  db.inviteCodes = db.inviteCodes.filter(c => !c.usedAt);
  saveDB(db);
  res.json({ deleted: before - db.inviteCodes.length });
});

// Inscription étudiant via code d'invitation (public)
app.post('/api/register', (req, res) => {
  const { code, firstName, lastName, login, email, password, mineure } = req.body;
  if (!code || !firstName || !lastName || !login || !email || !password) {
    return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe minimum 6 caractères' });
  }
  const db = loadDB();
  if (!db.inviteCodes) db.inviteCodes = [];

  const entry = db.inviteCodes.find(c => c.code === code.toUpperCase().trim());
  if (!entry) return res.status(403).json({ error: "Code d'invitation invalide" });
  if (entry.usedAt) return res.status(409).json({ error: 'Ce code a déjà été utilisé' });

  // Si le login est déjà pris, ajouter un chiffre incrémental (jean.dupont.MP → jean.dupont2.MP)
  let finalLogin = login;
  if (db.users.find(u => u.login === finalLogin)) {
    let n = 2;
    while (db.users.find(u => u.login === `${login.replace(/\.MP$/, '')}.${n}.MP`)) n++;
    finalLogin = `${login.replace(/\.MP$/, '')}.${n}.MP`;
  }

  if (db.users.find(u => u.email === email))
    return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const newUser = {
    id: db.nextId++,
    name: `${firstName.trim()} ${lastName.trim()}`,
    login: finalLogin,
    email: email.trim(),
    password: bcrypt.hashSync(password, 10),
    role: 'student',
    mineure: mineure ? mineure.trim() : '',
    registeredAt: new Date().toISOString(),
  };
  db.users.push(newUser);

  // Consommer le code
  entry.usedAt = new Date().toISOString();
  entry.usedBy = newUser.login;
  saveDB(db);

  res.json({ ok: true, name: newUser.name, login: newUser.login });
});

// ── STATS ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  res.json({
    folders: db.folders.length,
    files: db.folders.reduce((s,f) => s+(f.files||[]).length, 0),
    students: db.users.filter(u => u.role==='student').length,
    totalSize: db.folders.reduce((s,f) => s+(f.files||[]).reduce((ss,fi) => ss+fi.size, 0), 0),
    storageMode: r2Enabled ? 'Cloudflare R2' : 'Local',
  });
});

// ── Helper ────────────────────────────────────────────────────────────────────
function getFileType(ext) {
  if (['pdf'].includes(ext)) return 'pdf';
  if (['doc','docx'].includes(ext)) return 'doc';
  if (['xls','xlsx','csv'].includes(ext)) return 'xls';
  if (['ppt','pptx'].includes(ext)) return 'ppt';
  if (['jpg','jpeg','png','gif','svg','webp'].includes(ext)) return 'img';
  if (['mp4','mov','avi','mkv','webm','m4v'].includes(ext)) return 'video';
  if (['mp3','wav','m4a'].includes(ext)) return 'audio';
  if (['zip','rar','7z','tar'].includes(ext)) return 'zip';
  return 'other';
}

app.get('*', (req, res) => {
  const indexPath = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
    ? path.join(__dirname, 'public', 'index.html')
    : path.join(__dirname, 'index.html');
  res.sendFile(indexPath);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅  MasterPASS → http://0.0.0.0:${PORT}`);
  console.log(`    Stockage : ${r2Enabled ? `R2 bucket «${R2_BUCKET_NAME}»` : 'Local'}\n`);
});
