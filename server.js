const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Cloudflare R2 config (variables d'environnement) ─────────────────────────
const R2_ACCOUNT_ID    = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_KEY    = process.env.R2_SECRET_KEY;
const R2_BUCKET_NAME   = process.env.R2_BUCKET_NAME || 'masterpass';

let r2Client = null;
let r2Enabled = false;

if (R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_KEY) {
  r2Client = new S3Client({
    region: 'auto',
    endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_KEY },
  });
  r2Enabled = true;
  console.log('✅ Cloudflare R2 activé — bucket:', R2_BUCKET_NAME);
} else {
  console.log('⚠️  R2 non configuré → stockage local (dev uniquement)');
}

// ── Paths ─────────────────────────────────────────────────────────────────────
const DATA_FILE   = path.join(__dirname, 'data', 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'data', 'uploads');
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
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
  };
  saveDB(db); return db;
}

// ── Multer → mémoire (puis R2 ou disque) ─────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Railway runs behind a proxy (HTTPS), so we need to trust it
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'masterpass-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 8 * 60 * 60 * 1000, // 8 heures
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
}));
// Serve static files from public/ if it exists, otherwise from root
const publicDir = fs.existsSync(path.join(__dirname, 'public'))
  ? path.join(__dirname, 'public')
  : __dirname;
app.use(express.static(publicDir));

// ── Auth guards ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  next();
}

// ── R2 helpers ────────────────────────────────────────────────────────────────
async function uploadToR2(key, buffer, contentType) {
  await r2Client.send(new PutObjectCommand({
    Bucket: R2_BUCKET_NAME, Key: key, Body: buffer,
    ContentType: contentType || 'application/octet-stream',
  }));
}
async function deleteFromR2(key) {
  try { await r2Client.send(new DeleteObjectCommand({ Bucket: R2_BUCKET_NAME, Key: key })); }
  catch (e) { console.error('R2 delete error:', e.message); }
}
async function getDownloadUrl(key, filename) {
  const cmd = new GetObjectCommand({
    Bucket: R2_BUCKET_NAME, Key: key,
    ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
  });
  return getSignedUrl(r2Client, cmd, { expiresIn: 3600 });
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  const user = loadDB().users.find(u => u.login === login);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect' });
  req.session.userId = user.id;
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Session invalide' });
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role });
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, (req, res) => {
  res.json(loadDB().users.map(u => ({ id: u.id, name: u.name, login: u.login, role: u.role })));
});
app.post('/api/users', requireAdmin, (req, res) => {
  const { name, login, password, role } = req.body;
  if (!name || !login || !password || !['admin','student'].includes(role))
    return res.status(400).json({ error: 'Données invalides' });
  const db = loadDB();
  if (db.users.find(u => u.login === login))
    return res.status(409).json({ error: 'Identifiant déjà utilisé' });
  const u = { id: db.nextId++, name, login, password: bcrypt.hashSync(password, 10), role };
  db.users.push(u); saveDB(db);
  res.json({ id: u.id, name, login, role });
});
app.delete('/api/users/:id', requireAdmin, (req, res) => {
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

// ── FILES ─────────────────────────────────────────────────────────────────────
app.get('/api/folders/:id/files', requireAuth, (req, res) => {
  const folder = loadDB().folders.find(f => f.id === parseInt(req.params.id));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  res.json((folder.files||[]).map(f => ({ id: f.id, name: f.name, size: f.size, type: f.type, addedAt: f.addedAt, downloadable: f.downloadable !== false })));
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

app.get('/api/folders/:folderId/files/:fileId/download', requireAuth, async (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  // Block download for students if not allowed
  const requestingUser = db.users.find(u => u.id === req.session.userId);
  if (requestingUser?.role !== 'admin' && file.downloadable === false) {
    return res.status(403).json({ error: 'Téléchargement non autorisé par l'administrateur' });
  }

  if (r2Enabled && file.r2Key) {
    const url = await getDownloadUrl(file.r2Key, file.name);
    return res.redirect(url);
  } else if (file.filename) {
    const p = path.join(UPLOADS_DIR, file.filename);
    if (!fs.existsSync(p)) return res.status(404).json({ error: 'Fichier manquant' });
    return res.download(p, file.name);
  }
  res.status(500).json({ error: 'Erreur de configuration stockage' });
});

// Toggle downloadable permission (admin only)
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

// ── STATS ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', requireAdmin, (req, res) => {
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
