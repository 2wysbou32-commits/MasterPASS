const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// R2 via AWS SDK v2 (plus compatible avec Node 22)
const AWS = require('aws-sdk');
const { Resend } = require('resend');

// Email (Resend) — optionnel, fonctionne sans si RESEND_API_KEY non défini
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@masterpass.app';
const SITE_URL = process.env.SITE_URL || 'http://localhost:3000';

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
  r2Client = new AWS.S3({
    endpoint: new AWS.Endpoint(`https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`),
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_KEY,
    region: 'auto',
    signatureVersion: 'v4',
    httpOptions: {
      agent: new (require('https').Agent)({ rejectUnauthorized: false }),
    },
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

// ── Reset tokens (en mémoire, valides 15 min) ────────────────────────────────
const resetTokens = {}; // { token: { userId, expires } }

function generateToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// ── Multer → mémoire (puis R2 ou disque) ─────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Railway runs behind a proxy (HTTPS), so we need to trust it
app.set('trust proxy', 1);

// Sessions stockées sur disque (persistent même si le serveur redémarre)
const sessionsDir = path.join(__dirname, 'data', 'sessions');
if (!fs.existsSync(sessionsDir)) fs.mkdirSync(sessionsDir, { recursive: true });

app.use(session({
  store: new FileStore({
    path: sessionsDir,
    ttl: 28800, // 8 heures en secondes
    retries: 1,
    logFn: () => {}, // Silence les logs de session
  }),
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
  await r2Client.upload({
    Bucket: R2_BUCKET_NAME,
    Key: key,
    Body: buffer,
    ContentType: contentType || 'application/octet-stream',
  }).promise();
}
async function deleteFromR2(key) {
  try {
    await r2Client.deleteObject({ Bucket: R2_BUCKET_NAME, Key: key }).promise();
  } catch (e) { console.error('R2 delete error:', e.message); }
}
async function getDownloadUrl(key, filename) {
  return r2Client.getSignedUrlPromise('getObject', {
    Bucket: R2_BUCKET_NAME,
    Key: key,
    Expires: 3600,
    ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
  });
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  const user = loadDB().users.find(u => u.login === login);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect' });
  req.session.userId = user.id;
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role, email: user.email || '' });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Session invalide' });
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role, email: user.email || '' });
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
    return res.status(403).json({ error: "Téléchargement non autorisé par l'administrateur" });
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

// ── MOT DE PASSE OUBLIÉ ──────────────────────────────────────────────────────

// Demande de réinitialisation
app.post('/api/forgot-password', async (req, res) => {
  const { login } = req.body;
  if (!login) return res.status(400).json({ error: 'Identifiant requis' });
  const db = loadDB();
  const user = db.users.find(u => u.login === login);
  // Toujours répondre OK pour ne pas divulguer si le compte existe
  if (!user || !user.email) {
    return res.json({ ok: true, message: 'Si ce compte existe et a un email, un lien a été envoyé.' });
  }
  // Générer token
  const token = generateToken();
  resetTokens[token] = { userId: user.id, expires: Date.now() + 15 * 60 * 1000 };
  const resetLink = `${SITE_URL}?reset=${token}`;
  // Envoyer email si Resend configuré
  if (resend) {
    try {
      await resend.emails.send({
        from: FROM_EMAIL,
        to: user.email,
        subject: 'MasterPASS — Réinitialisation de mot de passe',
        html: `
          <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
            <img src="${SITE_URL}/logo.png" style="width:60px;border-radius:12px;margin-bottom:20px" />
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
    } catch(e) { console.error('Email error:', e.message); }
  } else {
    // Sans Resend : afficher le lien dans les logs (dev)
    console.log('RESET LINK (dev):', resetLink);
  }
  res.json({ ok: true });
});

// Valider un token de reset
app.get('/api/reset-token/:token', (req, res) => {
  const entry = resetTokens[req.params.token];
  if (!entry || Date.now() > entry.expires) {
    return res.status(400).json({ error: 'Lien invalide ou expiré' });
  }
  const user = loadDB().users.find(u => u.id === entry.userId);
  res.json({ valid: true, name: user?.name || '' });
});

// Réinitialiser le mot de passe avec token
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

// Ajouter/mettre à jour l'email d'un utilisateur (lui-même ou admin)
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

// Changer son propre mot de passe (étudiant connecté)
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
