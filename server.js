const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const sharp = require('sharp');

// R2 via API HTTP directe (pas de SDK — évite les problèmes SSL)
const crypto = require('crypto');
const https = require('https');

// ── Notifications Push (Web Push) ─────────────────────────────────────────────
let webpush = null;
try {
  webpush = require('web-push');
  const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY || 'BPAm2u-DCWr3oUwEtnXoa2Yb3J1y2zxRigqtA5UadyOjy15CX_zdDqx7-cOseKC6VxAlfhVpkmmyT_TpORJ8JRM';
  const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || 'pvIDK_3p5Jvc1PJzYNV8ftfxk_vh-yVR4UJHu2p6sBs';
  webpush.setVapidDetails('mailto:masterpass.lille@gmail.com', VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('✅ Web Push activé');
} catch(e) {
  console.log('⚠️ Web Push non disponible (npm install web-push)');
}

async function sendPushToAll(title, body, url = '/', category = null, threadId = null, excludeUserId = null, excludeUserIds = []) {
  if (!webpush) return;
  const db = loadDB();
  const subs = db.pushSubscriptions || [];
  const payload = JSON.stringify({ title, body, url });
  console.log('[PUSH DEBUG] ===', subs.length, 'abonnement(s) — category:', category, '— threadId:', threadId);
  await Promise.allSettled(subs.map(async (sub) => {
    if (excludeUserId && String(sub.userId) === String(excludeUserId)) return;
    if (excludeUserIds.length && excludeUserIds.includes(String(sub.userId))) return;
    const user = db.users.find(u => String(u.id) === String(sub.userId));
    console.log('[PUSH DEBUG] sub.userId:', sub.userId, '— user:', user?.name || 'inconnu');
    if (category && user && user.notifPrefs && user.notifPrefs[category] === false) { console.log('[PUSH DEBUG] → BLOQUÉ (préférence', category, ')'); return; }
    if (threadId && user && (user.mutedThreads || []).includes(threadId)) { console.log('[PUSH DEBUG] → BLOQUÉ (sourdine thread', threadId, ')'); return; }
    console.log('[PUSH DEBUG] → envoi en cours pour', user?.name || sub.userId);
    try {
      await webpush.sendNotification(sub.subscription, payload);
    } catch(e) {
      console.log('[PUSH DEBUG] → erreur envoi:', e.statusCode, e.message);
      if (e.statusCode === 410) {
        // Subscription expirée — la supprimer
        db.pushSubscriptions = (db.pushSubscriptions||[]).filter(s => s.subscription.endpoint !== sub.subscription.endpoint);
        saveDB(db);
      }
    }
  }));
}

// ── Envoi push ciblé à un seul utilisateur ────────────────────────────────────
async function sendPushToUser(userId, title, body, url = '/') {
  if (!webpush) return;
  const db = loadDB();
  const subs = (db.pushSubscriptions || []).filter(s => String(s.userId) === String(userId));
  const payload = JSON.stringify({ title, body, url });
  await Promise.allSettled(subs.map(async (sub) => {
    try {
      await webpush.sendNotification(sub.subscription, payload);
    } catch(e) {
      if (e.statusCode === 410) {
        const db2 = loadDB();
        db2.pushSubscriptions = (db2.pushSubscriptions||[]).filter(s => s.subscription.endpoint !== sub.subscription.endpoint);
        saveDB(db2);
      }
    }
  }));
}

// ── Calcule le nombre de schémas à revoir pour un user ────────────────────────
function countDueSchemas(user, db) {
  const progress = user.revisionProgress || {};
  const now = new Date();
  let count = 0;
  for (const seance of (db.seances || [])) {
    for (const sc of (seance.schemas || [])) {
      const p = progress[sc.id];
      if (p && typeof p === 'object' && p.nextReview && new Date(p.nextReview) <= now) count++;
    }
  }
  return count;
}

// ── Cron : rappel quotidien de révision (8h00) ────────────────────────────────
async function runDailyReviewReminder() {
  const db = loadDB();
  for (const user of db.users) {
    if (user.role !== 'student') continue;
    if (user.notifPrefs && user.notifPrefs.revision === false) continue;
    const due = countDueSchemas(user, db);
    if (due > 0) {
      await sendPushToUser(user.id, 'Révision du jour 🔁', `Tu as ${due} schéma${due>1?'s':''} à revoir aujourd'hui`, '/revision');
    }
  }
  console.log('[CRON] Rappel de révision quotidien envoyé');
}

// ── Cron : résumé hebdomadaire (dimanche 17h) ─────────────────────────────────
async function runWeeklySummary() {
  const db = loadDB();
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const weekKey = new Date().toISOString().split('T')[0];
  if (!db.weeklySummaries) db.weeklySummaries = {};

  for (const user of db.users) {
    if (user.role !== 'student') continue;
    if (user.notifPrefs && user.notifPrefs.revision === false) continue;

    const progress = user.revisionProgress || {};
    const schemasRevised = [];

    for (const seance of (db.seances || [])) {
      for (const sc of (seance.schemas || [])) {
        const p = progress[sc.id];
        if (p && typeof p === 'object' && p.lastReview && new Date(p.lastReview) >= weekAgo) {
          schemasRevised.push({
            titre: sc.titre,
            seanceTitre: seance.titre,
            difficulty: p.difficulty || null,
            lastReview: p.lastReview
          });
        }
      }
    }

    db.weeklySummaries[user.id] = {
      weekKey,
      schemasRevised,
      generatedAt: new Date().toISOString()
    };

    if (schemasRevised.length > 0) {
      await sendPushToUser(user.id, 'Résumé de ta semaine 📊', 'Ton résumé de la semaine est disponible !', '/');
    } else {
      await sendPushToUser(user.id, 'Résumé de ta semaine 📊', 'Tu n\'as pas révisé cette semaine — c\'est le moment de s\'y remettre 💪', '/');
    }
  }

  saveDB(db);
  console.log('[CRON] Résumé hebdomadaire envoyé');
}

async function assignDailySchema() {
  const db = loadDB();
  if (!db.dailySchema) db.dailySchema = {};
  const today = new Date().toISOString().split('T')[0];
  const allSchemas = [];
  for (const seance of (db.seances || [])) {
    for (const sc of (seance.schemas || [])) {
      allSchemas.push({ id: sc.id, titre: sc.titre, seanceTitre: seance.titre, seanceId: seance.id });
    }
  }
  if (!allSchemas.length) return;
  for (const user of db.users) {
    if (user.role !== 'student') continue;
    const random = allSchemas[Math.floor(Math.random() * allSchemas.length)];
    db.dailySchema[user.id] = { schema: random, date: today, done: false };
    await sendPushToUser(user.id, 'Schéma du jour 🎲', `Aujourd'hui : "${random.titre}" — vas-y !`, '/');
  }
  saveDB(db);
  console.log('[CRON] Schéma du jour assigné');
}

// ── Scheduler simple (sans dépendance externe) ────────────────────────────────
let _lastDailyRun = null;
let _lastWeeklyRun = null;
function startCronScheduler() {
  setInterval(() => {
    const now = new Date();
    const dateKey = now.toISOString().split('T')[0];
    if (now.getHours() === 8 && now.getMinutes() === 0 && _lastDailyRun !== dateKey) {
      _lastDailyRun = dateKey;
      runDailyReviewReminder().catch(e => console.error('[CRON] Erreur rappel quotidien:', e.message));
    }
    if (now.getDay() === 0 && now.getHours() === 17 && now.getMinutes() === 0 && _lastWeeklyRun !== dateKey) {
      _lastWeeklyRun = dateKey;
      runWeeklySummary().catch(e => console.error('[CRON] Erreur résumé hebdomadaire:', e.message));
    }
  }, 60 * 1000);
  console.log('✅ Scheduler cron démarré (rappel 8h, résumé dimanche 17h)');
}

const SITE_URL = process.env.SITE_URL || 'http://localhost:3000';

// ── Cloudflare R2 config ──────────────────────────────────────────────────────
const R2_ACCOUNT_ID    = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_KEY    = process.env.R2_SECRET_KEY;
const R2_BUCKET_NAME   = process.env.R2_BUCKET_NAME || 'masterpass';

let r2Enabled = false;
if (R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_KEY) {
  r2Enabled = true;
  console.log('✅ Cloudflare R2 activé — bucket:', R2_BUCKET_NAME);
} else {
  console.log('⚠️  R2 non configuré → stockage local');
}

// ── Helpers crypto ────────────────────────────────────────────────────────────
function hmac(key, data, encoding) {
  return crypto.createHmac('sha256', key).update(data).digest(encoding || undefined);
}
function hashSHA256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Encode chaque segment du path R2 séparément (conserve les /)
function encodeR2Key(key) {
  return key.split('/').map(s => encodeURIComponent(s)).join('/');
}

// Ancien encodage (avant correction) : les / deviennent %2F
function encodeR2KeyLegacy(key) {
  return encodeURIComponent(key);
}

// Signature AWS v4 pour PUT/DELETE
function buildAuthHeader(method, key, contentType, bodyHash, date, region) {
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const datetime = date.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateShort = datetime.slice(0, 8);
  const scope = `${dateShort}/${region}/s3/aws4_request`;
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

const app = express();
const PORT = process.env.PORT || 3000;

// ── Paths ─────────────────────────────────────────────────────────────────────
const DATA_DIR    = process.env.DATA_DIR || require('path').join(__dirname, 'data');
const DATA_FILE   = require('path').join(DATA_DIR, 'db.json');
const UPLOADS_DIR = require('path').join(DATA_DIR, 'uploads');
if (!require('fs').existsSync(DATA_DIR)) require('fs').mkdirSync(DATA_DIR, { recursive: true });
if (!require('fs').existsSync(UPLOADS_DIR)) require('fs').mkdirSync(UPLOADS_DIR, { recursive: true });

// ── DB ────────────────────────────────────────────────────────────────────────
function migrateCommentsToThreads(db) {
  if (!db.comments || !Object.keys(db.comments).length) return;
  if (!db.threads) db.threads = {};
  let migrated = 0;
  Object.entries(db.comments).forEach(([fileId, comments]) => {
    if (!comments || !comments.length) return;
    if (!db.threads[fileId]) db.threads[fileId] = [];
    // Check if already migrated (avoid duplicates)
    if (db.threads[fileId].length > 0) return;
    // Group comments as a single thread per file
    const firstComment = comments[0];
    const thread = {
      id: db.nextId++,
      fileId: fileId,
      title: firstComment.message ? firstComment.message.substring(0, 80) : 'Discussion importée',
      createdBy: firstComment.userId,
      createdAt: firstComment.createdAt,
      resolved: false,
      replies: comments.slice(1).map(c => ({
        id: c.id, userId: c.userId, userName: c.userName,
        userRole: c.userRole, message: c.message || '',
        audio: c.audio || null, audioDuration: c.audioDuration || null,
        createdAt: c.createdAt
      }))
    };
    db.threads[fileId].push(thread);
    migrated++;
  });
  if (migrated > 0) {
    console.log('Migrated ' + migrated + ' comment threads to new thread system');
    saveDB(db);
  }
}

function loadDB() {
  if (!fs.existsSync(DATA_FILE)) return initDB();
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return initDB(); }
}
function saveDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function initDB() {
  const db = {
    nextId: 10,
    users: [{ id: 1, name: 'Kafil', login: 'kafil.admin.mp', password: require('bcryptjs').hashSync('Youlou007kafil2006', 10), role: 'admin' }],
    folders: [],
    inviteCodes: [],
    announcements: [],
    connectionLogs: [],
    tickets: [],
    settings: { defaultExpiresAt: null },
  };
  saveDB(db); return db;
}

// ── Registre des sessions actives (déconnexion simultanée) ──────────────────
// Stocké en DB pour survivre aux redémarrages
function getActiveSessions() {
  const db = loadDB();
  return db.activeSessions || {};
}
function setActiveSession(userId, sessionId) {
  const db = loadDB();
  if (!db.activeSessions) db.activeSessions = {};
  db.activeSessions[userId] = sessionId;
  saveDB(db);
}
function deleteActiveSession(userId) {
  const db = loadDB();
  if (db.activeSessions) delete db.activeSessions[userId];
  saveDB(db);
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
app.use(express.json({ limit: '50mb' }));

// PWA files
app.get('/manifest.json', (req, res) => res.sendFile(path.join(__dirname, 'manifest.json')));
app.get('/icon-192.png', (req, res) => res.sendFile(path.join(__dirname, 'icon-192.png')));
app.get('/icon-512.png', (req, res) => res.sendFile(path.join(__dirname, 'icon-512.png')));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
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
  if (req.session.userId) {
    const dbAuth = loadDB();
    const userAuth = dbAuth.users.find(u => u.id === req.session.userId);
    if (userAuth && userAuth.isDemo) return next(); // Plusieurs connexions simultanées autorisées en mode démo
  }
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  // Vérifier que c'est bien la session active (anti-partage de compte)
  const activeSessionId = getActiveSessions()[req.session.userId];
  if (activeSessionId && activeSessionId !== req.sessionID) {
    console.log('[SECURITY] Session expirée pour userId:', req.session.userId, '— double connexion détectée');
    // Marquer l'utilisateur comme ayant tenté une double connexion
    try {
      const dbSec = loadDB();
      const userSec = dbSec.users.find(u => u.id === req.session.userId);
      if (userSec) { userSec.doubleConnectionAt = new Date().toISOString(); saveDB(dbSec); }
    } catch(e) {}
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'SESSION_EXPIRED', message: 'Ton compte a été connecté depuis un autre appareil.' });
  }
  const dbExp = loadDB();
  const userExp = dbExp.users.find(u => u.id === req.session.userId);
  if (userExp && userExp.role === 'student') {
    const expiry = userExp.expiresAt || (dbExp.settings && dbExp.settings.defaultExpiresAt);
    if (expiry && new Date() >= new Date(expiry)) {
      return res.status(403).json({ error: 'ACCOUNT_EXPIRED' });
    }
  }
  next();
}
// Admin principal uniquement
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

function requireSuperAdminOnly(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Non authentifié' });
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès réservé à l\'administrateur principal' });
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
async function addWatermarkHeader(res, userId) {
  // Ajoute le nom de l'utilisateur dans les headers pour le filigrane frontend
  try {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (user) res.setHeader('X-User-Watermark', encodeURIComponent(user.name));
  } catch(e) {}
}

// Watermark info from session for PDF
function getWatermarkUser(req) {
  if (!req.session.userId) return null;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  return user ? `${user.name} (${user.login})` : null;
}

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
    res.setHeader('Cache-Control', 'private, no-store');
    // Filigrane : envoyer l'identité de l'utilisateur au client
    if (originalReq && originalReq.session && originalReq.session.userId) {
      const wUser = getWatermarkUser(originalReq);
      if (wUser) res.setHeader('X-Watermark-User', Buffer.from(wUser).toString('base64'));
    }
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
  const db = loadDB();
  // Connexion par identifiant OU par email
  const user = db.users.find(u => u.login === login || (u.email && u.email === login));
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect' });
  req.session.userId = user.id;
  const prevSession = getActiveSessions()[user.id];
  req.session.save((err) => {
    if (err) console.log('[SESSION] Save error:', err);
    else {
      console.log('[SESSION] Saved — sessionID:', req.sessionID, '— userId:', user.id);
      setActiveSession(user.id, req.sessionID);
    }
  });

  // Log de connexion
  const dbLog = loadDB();
  if (!dbLog.connectionLogs) dbLog.connectionLogs = [];
  dbLog.connectionLogs.unshift({
    userId: user.id,
    login: user.login,
    name: user.name,
    ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'inconnue',
    ua: (req.headers['user-agent'] || '').substring(0, 120),
    at: new Date().toISOString(),
    replaced: !!prevSession,
  });
  const sevenDaysAgo1 = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
dbLog.connectionLogs = dbLog.connectionLogs.filter(l => (l.at || l.date) > sevenDaysAgo1);
  saveDB(dbLog);
  console.log('[SESSION] Session active enregistrée pour userId:', user.id);
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role, email: user.email || '', registeredAt: user.registeredAt || '', notifPrefs: user.notifPrefs || { announcements: true, discussions: true, files: true, revision: true }, mutedThreads: user.mutedThreads || [] });
});

app.post('/api/demo-login', (req, res) => {
  const db = loadDB();
  let demoUser = db.users.find(u => u.isDemo);
  if (!demoUser) {
    demoUser = {
      id: db.nextId++,
      name: 'Démo',
      login: '_demo_test_',
      password: bcrypt.hashSync(Math.random().toString(36), 10),
      role: 'student',
      isDemo: true,
      registeredAt: new Date().toISOString(),
      notifPrefs: { announcements: true, discussions: true, files: true, revision: true },
      mutedThreads: [],
      revisionProgress: {},
    };
    db.users.push(demoUser);
  }
  db.tickets = (db.tickets || []).filter(t => t.studentId !== demoUser.id);
  demoUser.revisionProgress = {};
  demoUser.mutedThreads = [];
  const todayStr = new Date().toISOString().split('T')[0];
  const allSchemasDemo = [];
  for (const seance of (db.seances || [])) {
    for (const sc of (seance.schemas || [])) {
      allSchemasDemo.push({ id: sc.id, titre: sc.titre, seanceTitre: seance.titre, seanceId: seance.id });
    }
  }
  if (!db.dailySchema) db.dailySchema = {};
  if (!db.weeklySummaries) db.weeklySummaries = {};
  if (allSchemasDemo.length) {
    const pick = allSchemasDemo[Math.floor(Math.random() * allSchemasDemo.length)];
    db.dailySchema[demoUser.id] = { schema: pick, date: todayStr, done: false };
    const shuffled = [...allSchemasDemo].sort(() => Math.random() - 0.5).slice(0, Math.min(3, allSchemasDemo.length));
    db.weeklySummaries[demoUser.id] = {
      weekKey: todayStr,
      schemasRevised: shuffled.map((s, i) => ({
        titre: s.titre,
        seanceTitre: s.seanceTitre,
        difficulty: ['facile', 'moyen', 'difficile'][i % 3],
        lastReview: new Date(Date.now() - (i + 1) * 24 * 60 * 60 * 1000).toISOString(),
      })),
      generatedAt: new Date().toISOString(),
    };
  }
  saveDB(db);
  req.session.userId = demoUser.id;
  req.session.save((err) => { if (err) console.log('[SESSION] Save error (demo):', err); });
  res.json({ id: demoUser.id, name: demoUser.name, login: demoUser.login, role: demoUser.role, email: '', registeredAt: demoUser.registeredAt, notifPrefs: demoUser.notifPrefs, mutedThreads: demoUser.mutedThreads, isDemo: true });
});

app.post('/api/logout', (req, res) => {
  if (req.session.userId && getActiveSessions()[req.session.userId] === req.sessionID) {
    deleteActiveSession(req.session.userId);
  }
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Session invalide' });
  res.json({ id: user.id, name: user.name, login: user.login, role: user.role, email: user.email || '', avatar: user.avatar || null, notifPrefs: user.notifPrefs || { announcements: true, discussions: true, files: true, revision: true }, mutedThreads: user.mutedThreads || [] });
});

app.patch('/api/me/notif-prefs', requireAuth, (req, res) => {
  const { announcements, discussions, files, revision } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.notifPrefs = {
    announcements: announcements !== false,
    discussions: discussions !== false,
    files: files !== false,
    revision: revision !== false
  };
  saveDB(db);
  res.json({ notifPrefs: user.notifPrefs });
});

app.post('/api/threads/:fileId/:threadId/mute', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!user.mutedThreads) user.mutedThreads = [];
  const tid = parseInt(req.params.threadId);
  const idx = user.mutedThreads.indexOf(tid);
  let muted;
  if (idx >= 0) { user.mutedThreads.splice(idx, 1); muted = false; }
  else { user.mutedThreads.push(tid); muted = true; }
  saveDB(db);
  res.json({ muted });
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  const activeSess = db.activeSessions || {};
  res.json(db.users.map(u => ({
    id: u.id, name: u.name, login: u.login, role: u.role,
    email: u.email || '', mineure: u.mineure || '', discord: u.discord || '',
    doubleConnection: !!u.doubleConnectionAt, expiresAt: u.expiresAt || null
  })));
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
  const db = loadDB();
  const user = db.users.find(u => u.id === id);
  db.users = db.users.filter(u => u.id !== id);
  // Supprimer aussi le code d'invitation lié à ce compte
  if (user && db.inviteCodes) {
    db.inviteCodes = db.inviteCodes.filter(c => c.usedBy !== user.login && c.usedBy !== user.id);
  }
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/settings', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.settings) { db.settings = { defaultExpiresAt: null }; saveDB(db); }
  res.json(db.settings);
});
app.patch('/api/settings', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.settings) db.settings = {};
  if (req.body.defaultExpiresAt !== undefined) db.settings.defaultExpiresAt = req.body.defaultExpiresAt;
  saveDB(db);
  res.json(db.settings);
});
app.patch('/api/users/:id/expires', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => String(u.id) === String(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
  user.expiresAt = req.body.expiresAt || null;
  saveDB(db);
  res.json({ ok: true });
});
// ── FOLDERS ───────────────────────────
app.get('/api/folders', requireAuth, (req, res) => {
  const db = loadDB();
  res.json(db.folders.map(f => ({
    id: f.id, name: f.name, createdAt: f.createdAt,
    fileCount: (f.files||[]).length,
    totalSize: (f.files||[]).reduce((s,fi) => s+fi.size, 0),
    files: (f.files||[]).map(fi => ({ id: fi.id, name: fi.name, type: fi.type, size: fi.size, addedAt: fi.addedAt, views: fi.views||0, downloadable: fi.downloadable })),
    subfolders: (f.subfolders||[]).map(s => ({
      id: s.id, name: s.name,
      fileCount: (s.files||[]).length,
      files: (s.files||[]).map(fi => ({ id: fi.id, name: fi.name, type: fi.type, size: fi.size, addedAt: fi.addedAt, views: fi.views||0, downloadable: fi.downloadable }))
    }))
  })));
});

app.get('/api/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  const db = loadDB();
  const results = [];
  db.folders.forEach(f => {
    (f.files || []).forEach(fi => {
      if (fi.name.toLowerCase().includes(q)) {
        results.push({ file: { id: fi.id, name: fi.name, type: fi.type, size: fi.size, addedAt: fi.addedAt, downloadable: fi.downloadable }, folderName: f.name, folderId: f.id });
      }
    });
    (f.subfolders || []).forEach(s => {
      (s.files || []).forEach(fi => {
        if (fi.name.toLowerCase().includes(q)) {
          results.push({ file: { id: fi.id, name: fi.name, type: fi.type, size: fi.size, addedAt: fi.addedAt, downloadable: fi.downloadable }, folderName: f.name + ' / ' + s.name, folderId: f.id, subId: s.id });
        }
      });
    });
  });
  res.json(results);
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
// ── RÉVISION : DOSSIERS ──────────────────────────────────────────────────────
app.get('/api/revision/dossiers', requireAuth, (req, res) => {
  const db = loadDB();
  const dossiers = db.dossiers || [];
  const seances = db.seances || [];
  res.json(dossiers.map(d => ({
    id: d.id, titre: d.titre,
    seanceCount: seances.filter(s => s.dossierId === d.id).length
  })));
});
app.post('/api/revision/dossiers', requireSuperAdmin, (req, res) => {
  const { titre } = req.body;
  if (!titre?.trim()) return res.status(400).json({ error: 'Titre requis' });
  const db = loadDB();
  if (!db.dossiers) db.dossiers = [];
  const dossier = { id: db.nextId++, titre: titre.trim(), createdAt: new Date().toISOString().split('T')[0] };
  db.dossiers.push(dossier); saveDB(db);
  res.json({ id: dossier.id, titre: dossier.titre, seanceCount: 0 });
});
app.delete('/api/revision/dossiers/:id', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.dossiers) db.dossiers = [];
  db.dossiers = db.dossiers.filter(d => d.id !== parseInt(req.params.id));
  saveDB(db);
  res.json({ ok: true });
});

app.patch('/api/revision/dossiers/:id', requireSuperAdmin, (req, res) => {
  const { titre } = req.body;
  if (!titre?.trim()) return res.status(400).json({ error: 'Titre requis' });
  const db = loadDB();
  const dossier = (db.dossiers||[]).find(d => d.id === parseInt(req.params.id));
  if (!dossier) return res.status(404).json({ error: 'Dossier introuvable' });
  dossier.titre = titre.trim();
  saveDB(db);
  res.json({ id: dossier.id, titre: dossier.titre });
});

// ── RÉVISION : SÉANCES ───────────────────────────────────────────────────────
app.get('/api/revision/seances', requireAuth, (req, res) => {
  const db = loadDB();
  const seances = db.seances || [];
  const dossierId = req.query.dossierId ? parseInt(req.query.dossierId) : null;
  const filtered = dossierId ? seances.filter(s => s.dossierId === dossierId) : seances;
  res.json(filtered.map(s => ({
    id: s.id, titre: s.titre, createdAt: s.createdAt,
    schemaCount: (s.schemas||[]).length
  })));
});
app.post('/api/revision/seances', requireSuperAdmin, (req, res) => {
  const { titre, dossierId } = req.body;
  if (!titre?.trim()) return res.status(400).json({ error: 'Titre requis' });
  if (!dossierId) return res.status(400).json({ error: 'Dossier requis' });
  const db = loadDB();
  if (!db.seances) db.seances = [];
  const seance = { id: db.nextId++, titre: titre.trim(), dossierId: parseInt(dossierId), createdAt: new Date().toISOString().split('T')[0], schemas: [] };
  db.seances.push(seance); saveDB(db);
  res.json({ id: seance.id, titre: seance.titre, createdAt: seance.createdAt, schemaCount: 0 });
});
app.delete('/api/revision/seances/:id', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.seances) db.seances = [];
  db.seances = db.seances.filter(s => s.id !== parseInt(req.params.id));
  saveDB(db);
  res.json({ ok: true });
});

app.patch('/api/revision/seances/:id', requireSuperAdmin, (req, res) => {
  const { titre } = req.body;
  if (!titre?.trim()) return res.status(400).json({ error: 'Titre requis' });
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  seance.titre = titre.trim();
  saveDB(db);
  res.json({ id: seance.id, titre: seance.titre });
});

app.get('/api/revision/seances/:id/schemas', requireAuth, (req, res) => {
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  const progress = (user && user.revisionProgress) || {};
  res.json((seance.schemas||[]).map(sc => {
    const p = progress[sc.id];
    const isObj = p && typeof p === 'object';
    return {
      id: sc.id, titre: sc.titre,
      derniereRevision: isObj ? p.lastReview : (p || null),
      nextReview: isObj ? p.nextReview : null
    };
  }));
});

app.post('/api/revision/seances/:id/schemas', requireSuperAdmin, upload.single('image'), async (req, res) => {
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  if (!req.file) return res.status(400).json({ error: 'Image requise' });
  const { titre, reperes } = req.body;
  if (!titre?.trim()) return res.status(400).json({ error: 'Titre requis' });
  let parsedReperes;
  try { parsedReperes = JSON.parse(reperes); } catch { return res.status(400).json({ error: 'JSON des repères invalide' }); }
  if (!Array.isArray(parsedReperes) || !parsedReperes.length) return res.status(400).json({ error: 'Aucun repère trouvé dans le JSON' });
  for (const r of parsedReperes) {
    if (!r.id || !r.label || typeof r.x !== 'number' || typeof r.y !== 'number' || r.x < 0 || r.x > 100 || r.y < 0 || r.y > 100) {
      return res.status(400).json({ error: 'Repère invalide : ' + JSON.stringify(r) });
    }
  }
  if (!seance.schemas) seance.schemas = [];
  const schemaId = db.nextId++;
  let imageRecord;
  if (r2Enabled) {
    const r2Key = `revision/${seance.id}/${schemaId}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    await uploadToR2(r2Key, req.file.buffer, req.file.mimetype);
    imageRecord = { r2Key };
  } else {
    const filename = `revision-${schemaId}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    fs.writeFileSync(path.join(UPLOADS_DIR, filename), req.file.buffer);
    imageRecord = { filename };
  }
  const schema = { id: schemaId, titre: titre.trim(), reperes: parsedReperes, addedAt: new Date().toISOString().split('T')[0], ...imageRecord };
  seance.schemas.push(schema);
  saveDB(db);
  res.json({ id: schema.id, titre: schema.titre });
});

app.patch('/api/revision/seances/:id/schemas/:schemaId', requireSuperAdmin, (req, res) => {
  const { titre } = req.body;
  if (!titre?.trim()) return res.status(400).json({ error: 'Titre requis' });
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  const schema = (seance.schemas||[]).find(sc => sc.id === parseInt(req.params.schemaId));
  if (!schema) return res.status(404).json({ error: 'Schéma introuvable' });
  schema.titre = titre.trim();
  saveDB(db);
  res.json({ id: schema.id, titre: schema.titre });
});
app.delete('/api/revision/seances/:id/schemas/:schemaId', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  seance.schemas = (seance.schemas||[]).filter(sc => sc.id !== parseInt(req.params.schemaId));
  saveDB(db);
  res.json({ ok: true });
});
app.post('/api/revision/seances/:id/schemas/:schemaId/vu', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!user.revisionProgress) user.revisionProgress = {};
  const existing = user.revisionProgress[req.params.schemaId];
  // Garde l'objet SM-2 existant s'il existe, sinon simple marqueur de date (rétrocompatibilité)
  if (existing && typeof existing === 'object') {
    existing.lastSeen = new Date().toISOString();
  } else {
    user.revisionProgress[req.params.schemaId] = new Date().toISOString();
  }
  saveDB(db);
  res.json({ ok: true });
});

// Notation de difficulté après les 3 modes - algorithme SM-2 simplifié
app.post('/api/revision/seances/:id/schemas/:schemaId/note', requireAuth, (req, res) => {
  const { difficulty } = req.body; // 'difficile' | 'moyen' | 'facile'
  if (!['difficile', 'moyen', 'facile'].includes(difficulty)) {
    return res.status(400).json({ error: 'Difficulté invalide' });
  }
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  const schema = (seance.schemas||[]).find(sc => sc.id === parseInt(req.params.schemaId));
  if (!schema) return res.status(404).json({ error: 'Schéma introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!user.revisionProgress) user.revisionProgress = {};

  const prev = user.revisionProgress[req.params.schemaId];
  let easeFactor = (prev && typeof prev === 'object' && prev.easeFactor) ? prev.easeFactor : 2.5;
  let interval = (prev && typeof prev === 'object' && prev.interval) ? prev.interval : 0;
  let repetitions = (prev && typeof prev === 'object' && prev.repetitions) ? prev.repetitions : 0;

  const qualityMap = { difficile: 2, moyen: 3, facile: 5 };
  const quality = qualityMap[difficulty];

  if (quality < 3) {
    repetitions = 0;
    interval = 1;
  } else {
    repetitions += 1;
    if (repetitions === 1) interval = 1;
    else if (repetitions === 2) interval = 6;
    else interval = Math.round(interval * easeFactor);
    easeFactor = Math.max(1.3, easeFactor + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02)));
  }

  const now = new Date();
  const nextReview = new Date(now.getTime() + interval * 24 * 60 * 60 * 1000);

  user.revisionProgress[req.params.schemaId] = {
    lastReview: now.toISOString(),
    nextReview: nextReview.toISOString(),
    easeFactor, interval, repetitions, difficulty
  };
  saveDB(db);
  res.json({ ok: true, nextReview: nextReview.toISOString(), interval });
});

// Liste des schémas à revoir aujourd'hui ou en retard
app.get('/api/revision/due', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const progress = user.revisionProgress || {};
  const now = new Date();
  const due = [];
  for (const seance of (db.seances || [])) {
    for (const sc of (seance.schemas || [])) {
      const p = progress[sc.id];
      if (p && typeof p === 'object' && p.nextReview) {
        if (new Date(p.nextReview) <= now) {
          due.push({
            id: sc.id, titre: sc.titre, seanceId: seance.id, seanceTitre: seance.titre,
            dossierId: seance.dossierId, nextReview: p.nextReview
          });
        }
      }
    }
  }
  due.sort((a, b) => new Date(a.nextReview) - new Date(b.nextReview));
  res.json(due);
});

// Résumé hebdomadaire de l'étudiant connecté
app.get('/api/weekly-summary', requireAuth, (req, res) => {
  const db = loadDB();
  const summaries = db.weeklySummaries || {};
  const summary = summaries[req.session.userId] || null;
  res.json(summary);
});

// Schéma du jour
app.get('/api/daily-schema', requireAuth, (req, res) => {
  const db = loadDB();
  const entry = (db.dailySchema || {})[req.session.userId] || null;
  res.json(entry);
});

app.post('/api/daily-schema/done', requireAuth, (req, res) => {
  const db = loadDB();
  if (!db.dailySchema) db.dailySchema = {};
  const entry = db.dailySchema[req.session.userId];
  if (entry) { entry.done = true; entry.difficulty = req.body.difficulty || null; }
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/test-daily', requireAuth, async (req, res) => {
  await assignDailySchema();
  res.json({ ok: true });
});

app.get('/api/revision/seances/:id/schemas/:schemaId/image', requireAuth, async (req, res) => {
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  const schema = (seance.schemas||[]).find(sc => sc.id === parseInt(req.params.schemaId));
  if (!schema) return res.status(404).json({ error: 'Schéma introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (user?.role !== 'admin' && user?.role !== 'subadmin') {
    try {
      let imgBuffer;
      if (r2Enabled && schema.r2Key) { imgBuffer = await fetchFromR2ToBuffer(schema.r2Key); }
      else if (schema.filename) { imgBuffer = fs.readFileSync(path.join(UPLOADS_DIR, schema.filename)); }
      if (imgBuffer) {
        const userName = user?.login || user?.name || 'Inconnu';
        const watermarked = await addImageWatermark(imgBuffer, userName);
        res.setHeader('Content-Type', 'image/png');
        return res.send(watermarked);
      }
    } catch(e) { console.error('Watermark image révision:', e.message); }
  }
  if (r2Enabled && schema.r2Key) { await proxyFileFromR2(schema.r2Key, res, true, req); return; }
  if (schema.filename) { res.sendFile(path.join(UPLOADS_DIR, schema.filename)); return; }
  res.status(404).json({ error: 'Image introuvable' });
});
app.get('/api/revision/seances/:id/schemas/:schemaId', requireAuth, (req, res) => {
  const db = loadDB();
  const seance = (db.seances||[]).find(s => s.id === parseInt(req.params.id));
  if (!seance) return res.status(404).json({ error: 'Séance introuvable' });
  const schema = (seance.schemas||[]).find(sc => sc.id === parseInt(req.params.schemaId));
  if (!schema) return res.status(404).json({ error: 'Schéma introuvable' });
  res.json({ id: schema.id, titre: schema.titre, reperes: schema.reperes });
});
// ── SOUS-DOSSIERS ─────────────────────────────────────────────────────────────
app.post('/api/folders/:id/subfolders', requireSuperAdminOnly, (req, res) => {
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
    .map(f => ({ id: f.id, name: f.name, size: f.size, type: f.type, addedAt: f.addedAt, downloadable: f.downloadable !== false, views: f.views || 0 })));
});

app.post('/api/folders/:parentId/subfolders/:subId/files', requireSuperAdminOnly, upload.array('files'), async (req, res) => {
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
  if (added.length > 0) {
    const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
    const sub2 = (parent?.subfolders||[]).find(s => s.id === parseInt(req.params.subId));
    const folderName = sub2 ? `${parent?.name} › ${sub2.name}` : 'Sous-dossier';
  }
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
  const isPDF1 = (file.name && file.name.toLowerCase().endsWith('.pdf')) || file.type === 'pdf';
  if (isPDF1 && user?.role !== 'admin' && user?.role !== 'subadmin') {
    try {
      let pdfBuffer;
      if (r2Enabled && file.r2Key) { pdfBuffer = await fetchFromR2ToBuffer(file.r2Key); }
      else if (file.filename) { pdfBuffer = fs.readFileSync(path.join(UPLOADS_DIR, file.filename)); }
      if (pdfBuffer) {
        const userName = user?.login || user?.name || 'Inconnu';
        const watermarked = await addWatermark(pdfBuffer, userName);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${file.name}.pdf"`);
        return res.send(Buffer.from(watermarked));
      }
    } catch(e) { console.error('Watermark download subfolder:', e.message); }
  }
  if (r2Enabled && file.r2Key) { await proxyFileFromR2(file.r2Key, res, false, req); return; }
  if (file.filename) { const p = path.join(UPLOADS_DIR, file.filename); if (fs.existsSync(p)) return res.download(p, file.name); }
  res.status(500).json({ error: 'Erreur stockage' });
});
async function fetchFromR2ToBuffer(key) {
  const host = `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const bodyHash = hashSHA256('');
  const pathNew    = `/${R2_BUCKET_NAME}/${encodeR2Key(key)}`;
  const pathLegacy = `/${R2_BUCKET_NAME}/${encodeR2KeyLegacy(key)}`;
  async function tryFetch(canonicalPath) {
    const headers = buildR2GetHeaders(canonicalPath, host, region, amzDate, dateStamp, bodyHash);
    const r2res = await r2GetRequest(host, canonicalPath, headers);
    if (r2res.statusCode === 404) { r2res.resume(); return null; }
    if (r2res.statusCode >= 400) { r2res.resume(); throw new Error(`R2 fetch error: ${r2res.statusCode}`); }
    return new Promise((resolve, reject) => {
      const chunks = [];
      r2res.on('data', c => chunks.push(c));
      r2res.on('end', () => resolve(Buffer.concat(chunks)));
      r2res.on('error', reject);
    });
  }
  let buf = await tryFetch(pathNew);
  if (!buf) buf = await tryFetch(pathLegacy);
  return buf;
}
async function addWatermark(pdfBuffer, userName) {
  try {
    const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const pages = pdfDoc.getPages();
    const watermarkText = `${userName} — MasterPASS`;
    for (const page of pages) {
      const { width } = page.getSize();
      page.drawText(watermarkText, {
        x: width / 2 - (watermarkText.length * 3.2),
        y: 18, size: 10, font,
        color: rgb(0.35, 0.35, 0.35),
        opacity: 0.85,
      });
    }
    return await pdfDoc.save();
  } catch(e) {
    console.error('Watermark error:', e.message);
    return pdfBuffer;
  }
}
async function addImageWatermark(imageBuffer, userName) {
  try {
    const image = sharp(imageBuffer);
    const metadata = await image.metadata();
    const width = metadata.width || 800;
    const height = metadata.height || 600;
    const watermarkText = `${userName} — MasterPASS`;
    const fontSize = Math.max(12, Math.round(width / 45));
    const svg = `<svg width="${width}" height="${height}"><text x="${width/2}" y="${height-14}" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-weight="600" font-size="${fontSize}" fill="rgba(90,90,90,0.55)">${escapeXml(watermarkText)}</text></svg>`;
    return await image.composite([{ input: Buffer.from(svg), top: 0, left: 0 }]).png().toBuffer();
  } catch (e) {
    console.error('Watermark image error:', e.message);
    return imageBuffer;
  }
}
function escapeXml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

app.get('/api/folders/:parentId/subfolders/:subId/files/:fileId/preview', requireAuth, async (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (parent?.subfolders || []).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files || []).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  // Incrémenter le compteur de vues
  file.views = (file.views || 0) + 1;
  saveDB(db);
  const _reqUser1 = db.users.find(u => u.id === req.session.userId);
  const _isPDF1 = (file.name && file.name.toLowerCase().endsWith('.pdf')) || file.type === 'pdf';
  console.log('[WM-SUB] user:', _reqUser1?.login, '| role:', _reqUser1?.role, '| isPDF:', _isPDF1, '| file:', file.name);
  if (_isPDF1 && _reqUser1?.role !== 'admin' && _reqUser1?.role !== 'subadmin') {
    const userName = _reqUser1?.login || _reqUser1?.name || 'Inconnu';
    try {
      let pdfBuffer;
      console.log('[WATERMARK] r2Enabled:', r2Enabled, '| r2Key:', file.r2Key);
      if (r2Enabled && file.r2Key) {
        pdfBuffer = await fetchFromR2ToBuffer(file.r2Key);
        console.log('[WATERMARK] pdfBuffer size:', pdfBuffer ? pdfBuffer.length : 'NULL');
      } else if (file.filename) {
        pdfBuffer = fs.readFileSync(path.join(UPLOADS_DIR, file.filename));
        console.log('[WATERMARK] local file size:', pdfBuffer.length);
      }
      if (pdfBuffer) {
        const watermarked = await addWatermark(pdfBuffer, userName);
        console.log('[WATERMARK] watermarked size:', watermarked ? watermarked.length : 'NULL');
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline');
        return res.send(Buffer.from(watermarked));
      } else {
        console.log('[WATERMARK] pdfBuffer est null, pas de watermark');
      }
    } catch(e) { console.error('[WATERMARK] Erreur:', e.message, e.stack); }
  }
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
    .map(f => ({ id: f.id, name: f.name, size: f.size, type: f.type, addedAt: f.addedAt, downloadable: f.downloadable !== false, views: f.views || 0 })));
});

app.post('/api/folders/:id/files', requireSuperAdminOnly, upload.array('files'), async (req, res) => {
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
  // Envoyer notification push pour les nouveaux fichiers
  if (added.length > 0) {
    const folderName = db.folders.find(f=>f.id===parseInt(req.params.folderId))?.name || 'MasterPASS';
    const fileNames = added.map(f=>f.name).join(', ');
    sendPushToAll(
      `📁 Nouveau fichier dans ${folderName}`,
      added.length === 1 ? added[0].name : `${added.length} nouveaux fichiers`,
      '/', 'files'
    ).catch(()=>{});
  }
  res.json(added);
});

app.get('/api/folders/:folderId/files/:fileId/preview', requireAuth, async (req, res) => {
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  const file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  // Incrémenter le compteur de vues
  file.views = (file.views || 0) + 1;
  saveDB(db);
  const _reqUser2 = db.users.find(u => u.id === req.session.userId);
  const _isPDF2 = (file.name && file.name.toLowerCase().endsWith('.pdf')) || file.type === 'pdf';
  console.log('[WM-ROOT] user:', _reqUser2?.login, '| role:', _reqUser2?.role, '| isPDF:', _isPDF2, '| file:', file.name);
  if (_isPDF2 && _reqUser2?.role !== 'admin' && _reqUser2?.role !== 'subadmin') {
    const userName = _reqUser2?.login || _reqUser2?.name || 'Inconnu';
    try {
      let pdfBuffer;
      if (r2Enabled && file.r2Key) {
        pdfBuffer = await fetchFromR2ToBuffer(file.r2Key);
      } else if (file.filename) {
        pdfBuffer = fs.readFileSync(path.join(UPLOADS_DIR, file.filename));
      }
      if (pdfBuffer) {
        const watermarked = await addWatermark(pdfBuffer, userName);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline');
        return res.send(Buffer.from(watermarked));
      }
    } catch(e) { console.error('Watermark error folder:', e.message); }
  }
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

  const isPDF2 = (file.name && file.name.toLowerCase().endsWith('.pdf')) || file.type === 'pdf';
  if (isPDF2 && requestingUser?.role !== 'admin' && requestingUser?.role !== 'subadmin') {
    try {
      let pdfBuffer;
      if (r2Enabled && file.r2Key) { pdfBuffer = await fetchFromR2ToBuffer(file.r2Key); }
      else if (file.filename) { pdfBuffer = fs.readFileSync(path.join(UPLOADS_DIR, file.filename)); }
      if (pdfBuffer) {
        const userName = requestingUser?.login || requestingUser?.name || 'Inconnu';
        const watermarked = await addWatermark(pdfBuffer, userName);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${file.name}.pdf"`);
        return res.send(Buffer.from(watermarked));
      }
    } catch(e) { console.error('Watermark download folder:', e.message); }
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
  // Search in root files first, then subfolders
  let file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) {
    for (const sub of (folder.subfolders||[])) {
      file = (sub.files||[]).find(f => f.id === parseInt(req.params.fileId));
      if (file) break;
    }
  }
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
  console.log('RESET LINK:', resetLink);
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
app.post('/api/folders/:id/presign', requireSuperAdminOnly, (req, res) => {
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

app.post('/api/folders/:parentId/subfolders/:subId/presign', requireSuperAdminOnly, (req, res) => {
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

// ── CLEAR DOUBLE CONNECTION FLAG ─────────────────────────────────────────────
app.delete('/api/users/:id/double-connection', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  delete user.doubleConnectionAt;
  saveDB(db);
  res.json({ ok: true });
});

// ── NOTIFICATIONS PUSH ───────────────────────────────────────────────────────
// Clé publique VAPID pour le client
app.get('/api/push/vapid-key', requireAuth, (req, res) => {
  const key = process.env.VAPID_PUBLIC_KEY || 'BPAm2u-DCWr3oUwEtnXoa2Yb3J1y2zxRigqtA5UadyOjy15CX_zdDqx7-cOseKC6VxAlfhVpkmmyT_TpORJ8JRM';
  res.json({ key });
});

// S'abonner aux notifications
app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const { subscription } = req.body;
  if (!subscription) return res.status(400).json({ error: 'Subscription manquante' });
  const db = loadDB();
  if (!db.pushSubscriptions) db.pushSubscriptions = [];
  const idx = db.pushSubscriptions.findIndex(s => s.subscription.endpoint === subscription.endpoint);
  if (idx >= 0) {
    // Réassocier cet appareil au compte actuellement connecté
    db.pushSubscriptions[idx].userId = req.session.userId;
  } else {
    db.pushSubscriptions.push({ userId: req.session.userId, subscription });
  }
  saveDB(db);
  res.json({ ok: true });
});
// Se désabonner
app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body;
  const db = loadDB();
  db.pushSubscriptions = (db.pushSubscriptions||[]).filter(s => s.subscription.endpoint !== endpoint);
  saveDB(db);
  res.json({ ok: true });
});

// ── TICKETS DE SUPPORT ───────────────────────────────────────────────────────
// Un ticket = conversation privée étudiant <-> admin/subadmin

// Étudiant : liste de MES tickets
app.get('/api/tickets/mine', requireAuth, (req, res) => {
  const db = loadDB();
  if (!db.tickets) db.tickets = [];
  const mine = db.tickets
    .filter(t => String(t.studentId) === String(req.session.userId))
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json({ tickets: mine });
});

// Étudiant : ouvrir un nouveau ticket
app.post('/api/tickets', requireAuth, (req, res) => {
  const { subject, message, image, audio, audioDuration } = req.body;
  if (!subject || !subject.trim() || ((!message || !message.trim()) && !image && !audio)) {
    return res.status(400).json({ error: 'Sujet et message requis' });
  }
  const db = loadDB();
  if (!db.tickets) db.tickets = [];
  const user = db.users.find(u => u.id === req.session.userId);
  if (user.isDemo) return res.status(403).json({ error: 'Fonctionnalité désactivée en mode démo' });
  const now = new Date().toISOString();
  const ticket = {
    id: db.nextId++,
    studentId: user.id,
    studentName: user.name,
    subject: subject.trim(),
    status: 'open',
    messages: [{
      id: 1,
      authorId: user.id,
      authorName: user.name,
      authorRole: user.role,
      text: (message || '').trim(),
      image: image || null,
      audio: audio || null,
      audioDuration: audioDuration || null,
      createdAt: now,
    }],
    unreadForAdmin: true,
    unreadForStudent: false,
    createdAt: now,
    updatedAt: now,
  };
  db.tickets.push(ticket);
  saveDB(db);
  // Notifier tous les admins/subadmins
  const admins = db.users.filter(u => u.role === 'admin' || u.role === 'subadmin');
  admins.forEach(a => sendPushToUser(a.id, 'Nouveau ticket 🎫', `${user.name} : ${subject.trim()}`, '/'));
  res.json({ ticket });
});

// Admin/Subadmin : liste de TOUS les tickets
app.get('/api/tickets', requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.tickets) db.tickets = [];
  const all = [...db.tickets].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json({ tickets: all });
});

// Voir le détail d'un ticket (étudiant propriétaire OU admin/subadmin)
app.get('/api/tickets/:id', requireAuth, (req, res) => {
  const db = loadDB();
  if (!db.tickets) db.tickets = [];
  const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
  if (!ticket) return res.status(404).json({ error: 'Ticket introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  const isOwner = String(ticket.studentId) === String(req.session.userId);
  const isAdmin = user.role === 'admin' || user.role === 'subadmin';
  if (!isOwner && !isAdmin) return res.status(403).json({ error: 'Accès refusé' });
  // Marquer comme lu selon qui consulte
  if (isAdmin) ticket.unreadForAdmin = false; else ticket.unreadForStudent = false;
  saveDB(db);
  res.json({ ticket });
});

// Répondre à un ticket (étudiant propriétaire OU admin/subadmin)
app.post('/api/tickets/:id/reply', requireAuth, (req, res) => {
  const { text, image, audio, audioDuration } = req.body;
  if ((!text || !text.trim()) && !image && !audio) return res.status(400).json({ error: 'Message vide' });
  const db = loadDB();
  if (!db.tickets) db.tickets = [];
  const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
  if (!ticket) return res.status(404).json({ error: 'Ticket introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (user.isDemo) return res.status(403).json({ error: 'Fonctionnalité désactivée en mode démo' });
  const isOwner = String(ticket.studentId) === String(req.session.userId);
  const isAdmin = user.role === 'admin' || user.role === 'subadmin';
  if (!isOwner && !isAdmin) return res.status(403).json({ error: 'Accès refusé' });
  if (ticket.status === 'closed') return res.status(400).json({ error: 'Ce ticket est fermé' });

  const now = new Date().toISOString();
  ticket.messages.push({
    id: ticket.messages.length + 1,
    authorId: user.id,
    authorName: user.name,
    authorRole: user.role,
    text: (text || '').trim(),
    image: image || null,
    audio: audio || null,
    audioDuration: audioDuration || null,
    createdAt: now,
  });
  ticket.updatedAt = now;
  if (isAdmin) {
    ticket.unreadForStudent = true;
    ticket.unreadForAdmin = false;
  } else {
    ticket.unreadForAdmin = true;
    ticket.unreadForStudent = false;
  }
  saveDB(db);

  if (isAdmin) {
    const preview = (text && text.trim()) ? text.trim().slice(0, 80) : (audio ? '🎤 Message vocal' : (image ? '📷 Image' : ''));
    sendPushToUser(ticket.studentId, 'Réponse à ton ticket 🎫', preview, '/');
  } else {
    const admins = db.users.filter(u => u.role === 'admin' || u.role === 'subadmin');
    admins.forEach(a => sendPushToUser(a.id, 'Nouveau message — ticket', `${user.name} : ${preview}`, '/'));
  }
  res.json({ ticket });
});

// Admin/Subadmin : fermer un ticket
app.post('/api/tickets/:id/close', requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.tickets) db.tickets = [];
  const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
  if (!ticket) return res.status(404).json({ error: 'Ticket introuvable' });
  ticket.status = 'closed';
  ticket.updatedAt = new Date().toISOString();
  saveDB(db);
  sendPushToUser(ticket.studentId, 'Ticket fermé', `Ton ticket "${ticket.subject}" a été résolu`, '/');
  res.json({ ticket });
});

// ── AVATAR ───────────────────────────────────────────────────────────────────
app.post('/api/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier' });
  // Accepter seulement les images
  if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Format invalide' });
  // Limiter à 2Mo
  if (req.file.size > 2 * 1024 * 1024) return res.status(400).json({ error: 'Image trop lourde (max 2Mo)' });

  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  // Stocker en base64 dans la DB (simple, pas besoin de R2 pour les avatars)
  const base64 = req.file.buffer.toString('base64');
  const dataUrl = `data:${req.file.mimetype};base64,${base64}`;
  user.avatar = dataUrl;
  saveDB(db);
  res.json({ avatar: dataUrl });
});

app.get('/api/avatar/:userId', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === parseInt(req.params.userId));
  if (!user || !user.avatar) return res.status(404).json({ error: "Pas d'avatar" });
  res.json({ avatar: user.avatar });
});

// Inclure l'avatar dans /me
// ── DÉPLACER UN DOSSIER ──────────────────────────────────────────────────────
app.post('/api/folders/:folderId/move', requireAdmin, (req, res) => {
  const { toFolderId } = req.body;
  const db = loadDB();
  const folderId = parseInt(req.params.folderId);
  const targetId = parseInt(toFolderId);
  
  if (folderId === targetId) return res.status(400).json({ error: 'Impossible de déplacer un dossier dans lui-même' });
  
  // Find the folder to move
  const folderIdx = db.folders.findIndex(f => f.id === folderId);
  if (folderIdx === -1) return res.status(404).json({ error: 'Dossier introuvable' });
  const folder = db.folders[folderIdx];
  
  // Find the target folder
  const targetFolder = db.folders.find(f => f.id === targetId);
  if (!targetFolder) return res.status(404).json({ error: 'Dossier cible introuvable' });
  
  // Deep copy folder to preserve all content before splicing
  const folderCopy = JSON.parse(JSON.stringify(folder));
  db.folders.splice(folderIdx, 1);
  if (!targetFolder.subfolders) targetFolder.subfolders = [];
  targetFolder.subfolders.push(folderCopy);
  saveDB(db);
  res.json({ ok: true });
});

// Extraire un sous-dossier vers la racine
app.post('/api/folders/:parentId/subfolders/:subId/extract', requireAdmin, (req, res) => {
  const db = loadDB();
  const parent = db.folders.find(f => f.id === parseInt(req.params.parentId));
  if (!parent) return res.status(404).json({ error: 'Dossier parent introuvable' });
  const subIdx = (parent.subfolders||[]).findIndex(s => s.id === parseInt(req.params.subId));
  if (subIdx === -1) return res.status(404).json({ error: 'Sous-dossier introuvable' });
  const subCopy = JSON.parse(JSON.stringify(parent.subfolders[subIdx]));
  parent.subfolders.splice(subIdx, 1);
  db.folders.push(subCopy);
  saveDB(db);
  res.json({ ok: true });
});

// ── DÉPLACER UN FICHIER ──────────────────────────────────────────────────────
app.post('/api/files/:fileId/move', requireAdmin, (req, res) => {
  const { fromFolderId, fromSubId, toFolderId, toSubId } = req.body;
  const db = loadDB();
  
  // Find source file - search in root and subfolders
  const fromFolder = db.folders.find(f => f.id === parseInt(fromFolderId));
  if (!fromFolder) return res.status(404).json({ error: 'Dossier source introuvable' });
  let sourceList, file;
  if (fromSubId) {
    const sub = (fromFolder.subfolders||[]).find(s => s.id === parseInt(fromSubId));
    sourceList = sub?.files;
  } else {
    // Try root files first
    sourceList = fromFolder.files;
    // If file not found in root, search subfolders
    const fileInRoot = (fromFolder.files||[]).find(f => f.id === parseInt(req.params.fileId));
    if (!fileInRoot) {
      for (const sub of (fromFolder.subfolders||[])) {
        const f = (sub.files||[]).find(f => f.id === parseInt(req.params.fileId));
        if (f) { sourceList = sub.files; break; }
      }
    }
  }
  if (!sourceList) return res.status(404).json({ error: 'Source introuvable' });
  const fileIdx = sourceList.findIndex(f => f.id === parseInt(req.params.fileId));
  if (fileIdx === -1) return res.status(404).json({ error: 'Fichier introuvable' });
  file = sourceList[fileIdx];
  
  // Find destination
  let destList;
  if (toSubId) {
    const folder = db.folders.find(f => f.id === parseInt(toFolderId));
    const sub = (folder?.subfolders||[]).find(s => s.id === parseInt(toSubId));
    destList = sub?.files;
  } else {
    const folder = db.folders.find(f => f.id === parseInt(toFolderId));
    destList = folder?.files;
  }
  if (!destList) return res.status(404).json({ error: 'Destination introuvable' });
  
  // Move
  sourceList.splice(fileIdx, 1);
  destList.push(file);
  saveDB(db);
  res.json({ ok: true });
});

// ── RENOMMER UN FICHIER ──────────────────────────────────────────────────────
app.patch('/api/folders/:folderId/files/:fileId/rename', requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom invalide' });
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.folderId));
  if (!folder) return res.status(404).json({ error: 'Dossier introuvable' });
  // Search in root files
  let file = (folder.files||[]).find(f => f.id === parseInt(req.params.fileId));
  // If not found, search in subfolders
  if (!file) {
    for (const sub of (folder.subfolders||[])) {
      file = (sub.files||[]).find(f => f.id === parseInt(req.params.fileId));
      if (file) break;
    }
  }
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  file.name = name.trim();
  saveDB(db);
  res.json({ ok: true, name: file.name });
});

app.patch('/api/folders/:parentId/subfolders/:subId/files/:fileId/rename', requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom invalide' });
  const db = loadDB();
  const folder = db.folders.find(f => f.id === parseInt(req.params.parentId));
  const sub = (folder?.subfolders||[]).find(s => s.id === parseInt(req.params.subId));
  const file = (sub?.files||[]).find(f => f.id === parseInt(req.params.fileId));
  if (!file) return res.status(404).json({ error: 'Fichier introuvable' });
  file.name = name.trim();
  saveDB(db);
  res.json({ ok: true, name: file.name });
});

// ── RÉORGANISER LES DOSSIERS ──────────────────────────────────────────────────
app.patch('/api/folders/reorder', requireAdmin, (req, res) => {
  const { order } = req.body; // array of folder ids in new order
  if (!Array.isArray(order)) return res.status(400).json({ error: 'Order invalide' });
  const db = loadDB();
  const reordered = [];
  order.forEach(id => {
    const f = db.folders.find(f => f.id === parseInt(id));
    if (f) reordered.push(f);
  });
  // Add any folders not in the order array
  db.folders.forEach(f => { if (!order.includes(f.id) && !order.includes(String(f.id))) reordered.push(f); });
  db.folders = reordered;
  saveDB(db);
  res.json({ ok: true });
});

// ── FILS DE DISCUSSION (THREADS) ────────────────────────────────────────────
// Structure: db.threads = { fileId: [ { id, title, createdBy, createdAt, replies: [...] } ] }

// GET all threads for a file
app.get('/api/threads/all', requireAuth, (req, res) => {
  const db = loadDB();
  const threads = db.threads;
  if (!threads || typeof threads !== 'object') return res.json([]);

  // Build flat file map
  const fileMap = {};
  (db.folders||[]).forEach(folder => {
    (folder.files||[]).forEach(f => {
      fileMap[String(f.id)] = { name: f.name, folder: folder.name };
    });
    (folder.subfolders||[]).forEach(sub => {
      (sub.files||[]).forEach(f => {
        fileMap[String(f.id)] = { name: f.name, folder: folder.name + ' / ' + sub.name };
      });
    });
  });

  const result = [];
  const keys = Object.keys(threads);
  keys.forEach(fileId => {
    const fileThreads = threads[fileId];
    if (!Array.isArray(fileThreads) || !fileThreads.length) return;
    const info = fileMap[String(fileId)] || { name: 'Fichier #' + fileId, folder: '' };
    fileThreads.forEach(t => {
      if (!t || !t.id) return;
      result.push({
        fileId: String(fileId),
        fileName: info.name,
        folderName: info.folder,
        threadId: t.id,
        title: t.title || 'Sans titre',
        resolved: t.resolved || false,
        createdAt: t.createdAt,
        createdBy: t.createdBy,
        replyCount: (t.replies||[]).length,
        lastActivity: (t.replies&&t.replies.length) ? t.replies[t.replies.length-1].createdAt : t.createdAt
      });
    });
  });

  result.sort((a,b) => new Date(b.lastActivity) - new Date(a.lastActivity));
  res.json(result);
});

// Unread threads count
app.get('/api/threads/:fileId', requireAuth, (req, res) => {
  const db = loadDB();
  if (!db.threads) db.threads = {};
  const threads = (db.threads[req.params.fileId] || []).map(t => {
    const creator = db.users.find(u => u.id === t.createdBy);
    return {
      ...t,
      creatorName: creator?.name || 'Inconnu',
      creatorAvatar: creator?.avatar || null,
      creatorRole: creator?.role || 'student',
      replyCount: (t.replies || []).length,
      lastReplyAt: t.replies?.length ? t.replies[t.replies.length-1].createdAt : t.createdAt
    };
  });
  res.json(threads);
});

app.post('/api/threads/upload-image', requireAuth, (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    try {
      const file = req.file;
      if (!file) return res.status(400).json({ error: 'Aucun fichier' });
      const ext = path.extname(file.originalname).toLowerCase();
      if (!['.jpg','.jpeg','.png','.gif','.webp'].includes(ext))
        return res.status(400).json({ error: 'Format non supporté' });
      if (file.size > 10 * 1024 * 1024) return res.status(400).json({ error: 'Image trop lourde (max 10 Mo)' });
      if (r2Enabled) {
        const r2Key = `discussion-images/${Date.now()}${ext}`;
        await uploadToR2(r2Key, file.buffer, file.mimetype);
        const url = `/api/threads/image/${r2Key}`;
        res.json({ url, r2Key });
      } else {
        const filename = `disc-${Date.now()}${ext}`;
        const dest = path.join(UPLOADS_DIR, filename);
        require('fs').writeFileSync(dest, file.buffer);
        const url = `/api/threads/image-local/${filename}`;
        res.json({ url, r2Key: null });
      }
    } catch(e) {
      console.error('[upload-image]', e.message);
      res.status(500).json({ error: e.message });
    }
  });
});

app.get('/api/threads/image-local/:filename', requireAuth, (req, res) => {
  const filename = req.params.filename;
  if (!filename || !filename.startsWith('disc-')) return res.status(404).end();
  const filePath = path.join(UPLOADS_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.get('/api/threads/image/*', requireAuth, async (req, res) => {
  try {
    const r2Key = req.params[0];
    if (!r2Key || !r2Key.startsWith('discussion-images/')) return res.status(404).end();
    await proxyFileFromR2(r2Key, res, true, req);
  } catch(e) {
    res.status(500).end();
  }
});

// CREATE a thread
app.post('/api/threads/:fileId', requireAuth, (req, res) => {
  const { title } = req.body;
  if (!title?.trim()) return res.status(400).json({ error: 'Titre requis' });
  const db = loadDB();
  if (!db.threads) db.threads = {};
  if (!db.threads[req.params.fileId]) db.threads[req.params.fileId] = [];
  const user = db.users.find(u => u.id === req.session.userId);
  if (user.isDemo) return res.status(403).json({ error: 'Fonctionnalité désactivée en mode démo' });
  const thread = {
    id: db.nextId++,
    fileId: req.params.fileId,
    title: title.trim(),
    createdBy: user.id,
    createdAt: new Date().toISOString(),
    replies: [],
    resolved: false
  };
  db.threads[req.params.fileId].push(thread);
  // Notif admin
  if (user.role !== 'admin') {
    if (!db.adminUnreadDiscussions) db.adminUnreadDiscussions = 0;
    db.adminUnreadDiscussions++;
    sendPushToAll('💬 Nouvelle question — MasterPASS', user.name + ': ' + title.trim().substring(0, 80), '/', 'discussions', thread.id).catch(()=>{});
  }
  saveDB(db);
  res.json(thread);
});

// DELETE a thread (admin or creator)
app.delete('/api/threads/:fileId/:threadId', requireAuth, (req, res) => {
  const db = loadDB();
  const threads = db.threads?.[req.params.fileId] || [];
  const thread = threads.find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (thread.createdBy !== req.session.userId && user?.role !== 'admin')
    return res.status(403).json({ error: 'Accès refusé' });
  db.threads[req.params.fileId] = threads.filter(t => t.id !== parseInt(req.params.threadId));
  saveDB(db);
  res.json({ ok: true });
});

// MARK thread as resolved (admin only)
app.patch('/api/threads/:fileId/:threadId/resolve', requireAdmin, (req, res) => {
  const db = loadDB();
  const thread = (db.threads?.[req.params.fileId] || []).find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  thread.resolved = !thread.resolved;
  saveDB(db);
  res.json({ ok: true, resolved: thread.resolved });
});

// GET replies for a thread
app.get('/api/threads/:fileId/:threadId/replies', requireAuth, (req, res) => {
  const db = loadDB();
  const thread = (db.threads?.[req.params.fileId] || []).find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  const replies = (thread.replies || []).map(r => {
    const user = db.users.find(u => u.id === r.userId);
    return { ...r, userAvatar: user?.avatar || null };
  });
  // Participants du fil + tous les admins/subadmins (pour le menu @mention)
  const participantIds = new Set([thread.userId, ...( thread.replies||[]).map(r => r.userId)]);
  const mentionables = db.users
    .filter(u => participantIds.has(u.id) || u.role === 'admin' || u.role === 'subadmin')
    .map(u => ({ id: u.id, name: u.name, role: u.role }));
  res.json({ thread: { id: thread.id, title: thread.title, resolved: thread.resolved }, replies, mentionables });
});

// POST a reply to a thread
app.post('/api/threads/:fileId/:threadId/replies', requireAuth, (req, res) => {
  console.log('[reply] body keys:', Object.keys(req.body), 'replyToName:', req.body.replyToName);
  const { message, audio, audioDuration, replyToId, replyToName, replyToPreview, imageUrl, r2Key } = req.body;
  if (!message?.trim() && !audio && !imageUrl) return res.status(400).json({ error: 'Message vide' });
  const db = loadDB();
  const thread = (db.threads?.[req.params.fileId] || []).find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (user.isDemo) return res.status(403).json({ error: 'Fonctionnalité désactivée en mode démo' });
  const reply = {
    id: db.nextId++,
    userId: user.id,
    userName: user.name,
    userRole: user.role,
    message: message?.trim() || '',
    audio: audio || null,
    audioDuration: audioDuration || null,
    replyToId: replyToId || null,
    replyToName: replyToName || null,
    replyToPreview: replyToPreview || null,
    createdAt: new Date().toISOString(),
    imageUrl: imageUrl || null,
    r2Key: r2Key || null
  };
  if (!thread.replies) thread.replies = [];
  thread.replies.push(reply);
  if (user.role !== 'admin') {
    if (!db.adminUnreadDiscussions) db.adminUnreadDiscussions = 0;
    db.adminUnreadDiscussions++;
    const mentionedIds = message ? (message.match(/@\[([^\]]+)\]/g)||[]).map(function(m){
      const n = m.slice(2,-1).trim();
      const u2 = db.users.find(function(u){return u.name.toLowerCase()===n.toLowerCase();});
      return u2 ? String(u2.id) : null;
    }).filter(Boolean) : [];
    sendPushToAll('💬 Réponse — ' + thread.title.substring(0,40), user.name + ': ' + (message ? message.substring(0,60) : imageUrl ? '🖼️ Image' : audio ? '🎤 Vocal' : '…'), '/', 'discussions', thread.id, user.id, mentionedIds).catch(()=>{});
    // Notifier les personnes @mentionnées directement
    if (message) {
      const mentionMatches = message.match(/@\[([^\]]+)\]/g) || [];
      mentionMatches.forEach(function(m) {
        const mentionedName = m.slice(2, -1).trim();
        const mentionedUser = db.users.find(u => u.name.toLowerCase() === mentionedName.toLowerCase());
        if (mentionedUser && mentionedUser.id !== user.id) {
          // Respecter le réglage "Mentions @" de l'utilisateur mentionné
          if (mentionedUser.notifPrefs?.mentions === false) return;
          // Envoyer à TOUS les appareils de la personne mentionnée, indépendamment des préfs discussions
          const mentionSubs = (db.pushSubscriptions||[]).filter(s => String(s.userId) === String(mentionedUser.id));
          mentionSubs.forEach(function(sub) {
            webpush.sendNotification(sub.subscription, JSON.stringify({
              title: '📣 ' + user.name + ' vous a mentionné',
              body: message.substring(0, 80),
              url: '/'
            })).catch(()=>{});
          });
        }
      });
    }
  }
  saveDB(db);
  res.json(reply);
});

// EDIT a reply
app.patch('/api/threads/:fileId/:threadId/replies/:replyId', requireAuth, (req, res) => {
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Message vide' });
  const db = loadDB();
  const thread = (db.threads?.[req.params.fileId]||[]).find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  const reply = (thread.replies||[]).find(r => r.id === parseInt(req.params.replyId));
  if (!reply) return res.status(404).json({ error: 'Réponse introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (reply.userId !== req.session.userId && user?.role !== 'admin')
    return res.status(403).json({ error: 'Accès refusé' });
  reply.message = message.trim();
  reply.editedAt = new Date().toISOString();
  saveDB(db);
  res.json({ ok: true });
});

// REACT to a reply
app.post('/api/threads/:fileId/:threadId/replies/:replyId/react', requireAuth, (req, res) => {
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Emoji manquant' });
  const db = loadDB();
  const thread = (db.threads?.[req.params.fileId]||[]).find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  const reply = (thread.replies||[]).find(r => r.id === parseInt(req.params.replyId));
  if (!reply) return res.status(404).json({ error: 'Réponse introuvable' });
  if (!reply.reactions) reply.reactions = {};
  if (!reply.reactions[emoji]) reply.reactions[emoji] = [];
  const uid = req.session.userId;
  const idx = reply.reactions[emoji].indexOf(uid);
  if (idx !== -1) reply.reactions[emoji].splice(idx, 1);
  else reply.reactions[emoji].push(uid);
  if (!reply.reactions[emoji].length) delete reply.reactions[emoji];
  saveDB(db);
  res.json({ reactions: reply.reactions });
});

// DELETE a reply
app.delete('/api/threads/:fileId/:threadId/replies/:replyId', requireAuth, async (req, res) => {
  const db = loadDB();
  const thread = (db.threads?.[req.params.fileId] || []).find(t => t.id === parseInt(req.params.threadId));
  if (!thread) return res.status(404).json({ error: 'Fil introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  const reply = (thread.replies||[]).find(r => r.id === parseInt(req.params.replyId));
  if (!reply) return res.status(404).json({ error: 'Réponse introuvable' });
  if (reply.userId !== req.session.userId && user?.role !== 'admin')
    return res.status(403).json({ error: 'Accès refusé' });
  if (r2Enabled && reply.r2Key) await deleteFromR2(reply.r2Key).catch(() => {});
  thread.replies = thread.replies.filter(r => r.id !== parseInt(req.params.replyId));
  saveDB(db);
  res.json({ ok: true });
});

// MIGRATION manuelle comments → threads (appeler une fois)
app.post('/api/admin/migrate-threads', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (!db.comments || !Object.keys(db.comments).length) {
    return res.json({ ok: true, migrated: 0, message: 'Pas de comments à migrer' });
  }
  if (!db.threads) db.threads = {};
  let migrated = 0;
  Object.entries(db.comments).forEach(([fileId, comments]) => {
    if (!comments || !comments.length) return;
    if (!db.threads[fileId]) db.threads[fileId] = [];
    comments.forEach((c, idx) => {
      // Chaque commentaire devient un fil séparé
      const thread = {
        id: db.nextId++,
        fileId,
        title: (c.message || 'Message vocal').substring(0, 80),
        createdBy: c.userId,
        createdAt: c.createdAt,
        resolved: false,
        replies: []
      };
      db.threads[fileId].push(thread);
      migrated++;
    });
  });
  saveDB(db);
  res.json({ ok: true, migrated, threadsKeys: Object.keys(db.threads) });
});

// GET all threads across all files (for notification center)
app.post('/api/threads/unread', requireAuth, (req, res) => {
  const { fileIds, lastSeen } = req.body;
  if (!Array.isArray(fileIds)) return res.status(400).json({ error: 'fileIds requis' });
  const db = loadDB();
  if (!db.threads) return res.json({});
  const result = {};
  fileIds.filter(id => id && id !== 'undefined' && id !== 'null').forEach(fileId => {
    const threads = db.threads[String(fileId)] || [];
    const lastSeenAt = lastSeen?.[fileId] ? new Date(lastSeen[fileId]) : null;
    if (!lastSeenAt) {
      // Jamais vu : compter tous les fils + toutes les réponses
      result[fileId] = threads.reduce((acc, t) => acc + 1 + (t.replies||[]).length, 0);
    } else {
      // Compter les nouveaux fils + nouvelles réponses depuis lastSeen
      let count = 0;
      threads.forEach(t => {
        if (new Date(t.createdAt) > lastSeenAt) count++;
        else count += (t.replies||[]).filter(r => new Date(r.createdAt) > lastSeenAt).length;
      });
      result[fileId] = count;
    }
  });
  res.json(result);
});

// POST a comment
app.post('/api/comments/:fileId', requireAuth, (req, res) => {
  const { message, replyTo, audio, audioDuration } = req.body;
  if (!message?.trim() && !audio) return res.status(400).json({ error: 'Message vide' });
  const db = loadDB();
  if (!db.comments) db.comments = {};
  if (!db.comments[req.params.fileId]) db.comments[req.params.fileId] = [];
  const user = db.users.find(u => u.id === req.session.userId);
  const comment = {
    id: db.nextId++,
    fileId: req.params.fileId,
    userId: user.id,
    userName: user.name,
    userRole: user.role,
    userAvatar: user.avatar || null,
    message: message?.trim() || '',
    audio: audio || null,
    audioDuration: audioDuration || null,
    replyToId: req.body.replyToId || null,
    replyToName: req.body.replyToName || null,
    replyToPreview: req.body.replyToPreview || null,
    replyTo: replyTo || null,
    createdAt: new Date().toISOString(),
  };
  db.comments[req.params.fileId].push(comment);

  // Notifier l'admin si c'est un étudiant qui commente
  if (user.role !== 'admin') {
    if (!db.adminUnreadDiscussions) db.adminUnreadDiscussions = 0;
    db.adminUnreadDiscussions++;
    sendPushToAll('💬 Nouvelle question — MasterPASS', user.name + (message?.trim() ? ': ' + message.trim().substring(0, 60) : (audio ? ' a envoyé un vocal' : ' a envoyé une image')), '/', 'discussions').catch(()=>{});
    if (!db.adminNotifications) db.adminNotifications = [];
    db.adminNotifications.unshift({
      id: db.nextId++,
      type: 'comment',
      fileId: req.params.fileId,
      userName: user.name,
      message: message.trim().substring(0, 100),
      at: new Date().toISOString(),
      read: false,
    });
    if (db.adminNotifications.length > 50) db.adminNotifications = db.adminNotifications.slice(0, 50);
  }

  saveDB(db);
  res.json(comment);
});

// GET unread comments count for multiple files
app.post('/api/comments/unread', requireAuth, (req, res) => {
  const { fileIds, lastSeen } = req.body; // lastSeen: { fileId: timestamp }
  const db = loadDB();
  if (!db.comments) return res.json({});
  const result = {};
  (fileIds || []).forEach(fileId => {
    const comments = db.comments[fileId] || [];
    const lastSeenAt = lastSeen?.[fileId] ? new Date(lastSeen[fileId]) : null;
    result[fileId] = lastSeenAt
      ? comments.filter(c => new Date(c.createdAt) > lastSeenAt).length
      : comments.length;
  });
  res.json(result);
});

// Admin notifications
app.get('/api/admin/notifications', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.adminNotifications || []);
});
app.post('/api/admin/notifications/read', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  if (db.adminNotifications) db.adminNotifications.forEach(n => n.read = true);
  saveDB(db);
  res.json({ ok: true });
});

// EDIT a comment
app.patch('/api/comments/:fileId/:commentId', requireAuth, (req, res) => {
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Message vide' });
  const db = loadDB();
  const comments = db.comments?.[req.params.fileId] || [];
  const comment = comments.find(c => c.id === parseInt(req.params.commentId));
  if (!comment) return res.status(404).json({ error: 'Commentaire introuvable' });
  if (comment.userId !== req.session.userId && db.users.find(u=>u.id===req.session.userId)?.role !== 'admin')
    return res.status(403).json({ error: 'Accès refusé' });
  comment.message = message.trim();
  comment.editedAt = new Date().toISOString();
  saveDB(db);
  res.json({ ok: true });
});

// ADD/REMOVE reaction
app.post('/api/comments/:fileId/:commentId/react', requireAuth, (req, res) => {
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Emoji manquant' });
  const db = loadDB();
  const comment = (db.comments?.[req.params.fileId] || []).find(c => c.id === parseInt(req.params.commentId));
  if (!comment) return res.status(404).json({ error: 'Introuvable' });
  if (!comment.reactions) comment.reactions = {};
  if (!comment.reactions[emoji]) comment.reactions[emoji] = [];
  const userId = req.session.userId;
  const idx = comment.reactions[emoji].indexOf(userId);
  if (idx !== -1) comment.reactions[emoji].splice(idx, 1);
  else comment.reactions[emoji].push(userId);
  if (!comment.reactions[emoji].length) delete comment.reactions[emoji];
  saveDB(db);
  res.json({ reactions: comment.reactions });
});

// DELETE a comment (admin or own comment)
app.delete('/api/comments/:fileId/:commentId', requireAuth, (req, res) => {
  const db = loadDB();
  if (!db.comments?.[req.params.fileId]) return res.status(404).json({ error: 'Introuvable' });
  const user = db.users.find(u => u.id === req.session.userId);
  const comment = db.comments[req.params.fileId].find(c => c.id === parseInt(req.params.commentId));
  if (!comment) return res.status(404).json({ error: 'Commentaire introuvable' });
  if (comment.userId !== req.session.userId && user.role !== 'admin')
    return res.status(403).json({ error: 'Accès refusé' });
  db.comments[req.params.fileId] = db.comments[req.params.fileId].filter(c => c.id !== parseInt(req.params.commentId));
  saveDB(db);
  res.json({ ok: true });
});

// Badge discussions non lues (admin)
app.get('/api/comments/admin-unread', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  res.json({ count: db.adminUnreadDiscussions || 0 });
});
app.post('/api/comments/admin-unread/reset', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  db.adminUnreadDiscussions = 0;
  saveDB(db);
  res.json({ ok: true });
});

// ── LOGS DE CONNEXION ────────────────────────────────────────────────────────
app.get('/api/connection-logs', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.connectionLogs || []);
});

// ── ANNONCES ─────────────────────────────────────────────────────────────────

// Créer une annonce (admin)
app.post('/api/announcements', requireAdmin, (req, res) => {
  const { title, message, color } = req.body;
  if (!title?.trim() || !message?.trim()) return res.status(400).json({ error: 'Titre et message requis' });
  const db = loadDB();
  if (!db.announcements) db.announcements = [];
  const ann = {
    id: db.nextId++,
    title: title.trim(),
    message: message.trim(),
    color: color || 'info',
    createdAt: new Date().toISOString(),
  };
  db.announcements.unshift(ann); // Plus récent en premier
  saveDB(db);
  sendPushToAll('📢 ' + ann.title, ann.message.substring(0, 80), '/', 'announcements').catch(()=>{});
  res.json(ann);
});
// Lister toutes les annonces
app.post('/api/announcements/:id/react', requireAuth, (req, res) => {
  const db = loadDB();
  const ann = (db.announcements || []).find(a => a.id === parseInt(req.params.id));
  if (!ann) return res.status(404).json({ error: 'Annonce introuvable' });
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Emoji requis' });
  const uid = req.session.userId;
  if (!ann.reactions) ann.reactions = {};
  if (!ann.reactions[emoji]) ann.reactions[emoji] = [];
  const idx = ann.reactions[emoji].indexOf(uid);
  if (idx !== -1) ann.reactions[emoji].splice(idx, 1);
  else ann.reactions[emoji].push(uid);
  if (!ann.reactions[emoji].length) delete ann.reactions[emoji];
  saveDB(db);
  res.json({ reactions: ann.reactions });
});
app.get('/api/announcements', requireAuth, (req, res) => {
  const db = loadDB();
  res.json(db.announcements || []);
});

// Supprimer une annonce (admin)
app.delete('/api/announcements/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.announcements) db.announcements = [];
  db.announcements = db.announcements.filter(a => a.id !== parseInt(req.params.id));
  saveDB(db);
  res.json({ ok: true });
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
  const { code, firstName, lastName, login, email, password, mineure, discord } = req.body;
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
    discord: discord ? discord.trim() : '',
    registeredAt: new Date().toISOString(),
  };
  db.users.push(newUser);

  // Consommer le code
  entry.usedAt = new Date().toISOString();
  entry.usedBy = newUser.login;
  saveDB(db);

  res.json({ ok: true, name: newUser.name, login: newUser.login });
});

// ── CLEAR DOUBLE CONNECTION FLAG ─────────────────────────────────────────────
app.get('/api/stats', requireSuperAdmin, (req, res) => {
  const db = loadDB();
  res.json({
    folders: db.folders.length,
    files: db.folders.reduce((s,f) => s+(f.files||[]).length, 0),
    students: db.users.filter(u => u.role==='student').length,
    totalSize: db.folders.reduce((s,f) => {
      const rootSize = (f.files||[]).reduce((ss,fi) => ss+fi.size, 0);
      const subSize = (f.subfolders||[]).reduce((ss,sub) => ss+(sub.files||[]).reduce((sss,fi) => sss+fi.size, 0), 0);
      return s + rootSize + subSize;
    }, 0),
    files: db.folders.reduce((s,f) => s+(f.files||[]).length+(f.subfolders||[]).reduce((ss,sub) => ss+(sub.files||[]).length, 0), 0),
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

// Servir le service worker
app.get('/sw.js', (req, res) => {
  const swPath = path.join(__dirname, 'sw.js');
  if (fs.existsSync(swPath)) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Service-Worker-Allowed', '/');
    res.sendFile(swPath);
  } else {
    res.status(404).send('// sw.js not found');
  }
});

app.get('*', (req, res) => {
  const indexPath = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
    ? path.join(__dirname, 'public', 'index.html')
    : path.join(__dirname, 'index.html');
  res.sendFile(indexPath);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅  MasterPASS → http://0.0.0.0:${PORT}`);
  startCronScheduler();
  // Migrate old comments to threads (once at startup)
  try {
    const db = loadDB();
    let migrated = 0;
    if (db.comments && Object.keys(db.comments).length) {
      if (!db.threads) db.threads = {};
      Object.entries(db.comments).forEach(([fileId, comments]) => {
        if (!comments || !comments.length) return;
        if (db.threads[fileId] && db.threads[fileId].length > 0) return;
        if (!db.threads[fileId]) db.threads[fileId] = [];
        const first = comments[0];
        db.threads[fileId].push({
          id: db.nextId++,
          fileId, title: (first.message||'Discussion importée').substring(0, 80),
          createdBy: first.userId, createdAt: first.createdAt,
          resolved: false,
          replies: comments.slice(1).map(c => ({
            id: c.id, userId: c.userId, userName: c.userName,
            userRole: c.userRole||'student', message: c.message||'',
            audio: c.audio||null, audioDuration: c.audioDuration||null,
            createdAt: c.createdAt
          }))
        });
        migrated++;
      });
      if (migrated > 0) { saveDB(db); console.log('✅ Migrated', migrated, 'discussions'); }
    }
  } catch(e) { console.error('Migration error:', e.message); }
  console.log(`    Stockage : ${r2Enabled ? `R2 bucket «${R2_BUCKET_NAME}»` : 'Local'}\n`);
});
