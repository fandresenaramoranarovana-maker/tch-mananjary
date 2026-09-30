import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const PUBLIC_ACCESS_CODE = process.env.PUBLIC_ACCESS_CODE;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!PUBLIC_ACCESS_CODE) throw new Error('PUBLIC_ACCESS_CODE must be set in .env');
if (!ADMIN_PASSWORD) throw new Error('ADMIN_PASSWORD must be set in .env');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');

const root = __dirname;
const dataDir = path.join(root, 'data');
const imageDir = path.join(root, 'storage', 'images');
const videoDir = path.join(root, 'storage', 'videos');
for (const dir of [dataDir, imageDir, videoDir]) fs.mkdirSync(dir, { recursive: true });

const db = new Database(path.join(dataDir, 'tch.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS films (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  duration TEXT DEFAULT '',
  rating TEXT DEFAULT '',
  description TEXT DEFAULT '',
  poster TEXT DEFAULT '',
  video_filename TEXT DEFAULT '',
  trailer_filename TEXT DEFAULT '',
  is_paid INTEGER NOT NULL DEFAULT 0,
  price INTEGER,
  published INTEGER NOT NULL DEFAULT 0,
  featured INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Vidéos',
  description TEXT DEFAULT '',
  thumbnail TEXT DEFAULT '',
  filename TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Images',
  description TEXT DEFAULT '',
  filename TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  pseudo TEXT DEFAULT '',
  role TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  photo TEXT DEFAULT '',
  birth_date TEXT DEFAULT '',
  city TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  social_json TEXT DEFAULT '{}',
  published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  pseudo TEXT DEFAULT '',
  photo TEXT DEFAULT '',
  birth_date TEXT DEFAULT '',
  city TEXT DEFAULT '',
  role TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  social TEXT DEFAULT '',
  personal_link TEXT DEFAULT '',
  message TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS upcoming (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  poster TEXT DEFAULT '',
  release_label TEXT DEFAULT '',
  published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  film_id INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  provider TEXT DEFAULT 'manual',
  reference TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  confirmed_at TEXT,
  FOREIGN KEY (film_id) REFERENCES films(id)
);
`);

const adminExists = db.prepare('SELECT id FROM admins WHERE username = ?').get(ADMIN_USERNAME);
if (!adminExists) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(ADMIN_USERNAME, hash);
}

const seedFilm = db.prepare('SELECT id FROM films WHERE title = ?').get('LONG TIME');
if (!seedFilm) {
  db.prepare(`INSERT INTO films (title,duration,rating,description,poster,is_paid,price,published,featured)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(
    'LONG TIME', '2H', '-10 ANS',
    'Une production T.CH présentée comme une histoire de suspense, action, drame et révélation.',
    '/assets/long-time-poster.png', 1, null, 1, 1
  );
}
const seedUpcoming = db.prepare('SELECT id FROM upcoming WHERE title = ?').get('LONG TIME');
if (!seedUpcoming) {
  db.prepare(`INSERT INTO upcoming (title,description,poster,release_label,published) VALUES (?,?,?,?,?)`).run(
    'LONG TIME', 'Film principal T.CH. Bande-annonce disponible séparément; film complet protégé après confirmation de paiement.', '/assets/long-time-poster.png', 'À venir', 1
  );
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
const Store = SQLiteStoreFactory(session);
app.use(session({
  store: new Store({ db: 'sessions.db', dir: dataDir }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const publicAccessLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });

const imageStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, imageDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname).toLowerCase()}`)
});
const videoStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, videoDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname).toLowerCase()}`)
});
const imageUpload = multer({
  storage: imageStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
});
const videoUpload = multer({
  storage: videoStorage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, /^video\/(mp4|webm|quicktime)$/.test(file.mimetype))
});

function requirePublicAccess(req, res, next) {
  if (req.session.publicAccess) return next();
  return res.status(401).json({ error: 'PUBLIC_ACCESS_REQUIRED' });
}
function requireAdmin(req, res, next) {
  if (req.session.adminId) return next();
  return res.status(401).json({ error: 'ADMIN_REQUIRED' });
}
function safeUnlink(filePath) {
  try { if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch {}
}
function parseBool(v) { return v === true || v === 'true' || v === 1 || v === '1'; }
function parseSocial(v) {
  if (!v) return {};
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch { return {}; }
}

app.post('/api/access', publicAccessLimiter, (req, res) => {
  const code = String(req.body?.code || '');
  if (code !== PUBLIC_ACCESS_CODE) return res.status(401).json({ error: 'Code incorrect. Veuillez réessayer.' });
  req.session.publicAccess = true;
  res.json({ ok: true });
});
app.get('/api/session', (req, res) => res.json({ publicAccess: !!req.session.publicAccess, admin: !!req.session.adminId }));
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(String(username || ''));
  if (!admin || !bcrypt.compareSync(String(password || ''), admin.password_hash)) return res.status(401).json({ error: 'Identifiants incorrects.' });
  req.session.adminId = admin.id;
  res.json({ ok: true });
});
app.post('/api/admin/logout', requireAdmin, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.post('/api/admin/password', requireAdmin, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.session.adminId);
  if (!admin || !bcrypt.compareSync(String(currentPassword || ''), admin.password_hash)) return res.status(401).json({ error: 'Mot de passe actuel incorrect.' });
  if (String(newPassword || '').length < 10) return res.status(400).json({ error: 'Le nouveau mot de passe doit contenir au moins 10 caractères.' });
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(String(newPassword), 12), admin.id);
  res.json({ ok: true });
});

app.get('/api/films', requirePublicAccess, (_req, res) => {
  const rows = db.prepare('SELECT id,title,duration,rating,description,poster,is_paid,price,published,featured FROM films WHERE published = 1 ORDER BY featured DESC, id DESC').all();
  res.json(rows);
});
app.get('/api/films/:id', requirePublicAccess, (req, res) => {
  const film = db.prepare('SELECT id,title,duration,rating,description,poster,is_paid,price,published,featured FROM films WHERE id = ? AND published = 1').get(req.params.id);
  if (!film) return res.status(404).json({ error: 'Film introuvable.' });
  const hasPurchase = db.prepare("SELECT id FROM purchases WHERE film_id = ? AND session_id = ? AND status = 'confirmed' LIMIT 1").get(film.id, req.sessionID);
  res.json({ ...film, unlocked: !film.is_paid || !!hasPurchase });
});
app.get('/api/videos', requirePublicAccess, (_req, res) => {
  const rows = db.prepare('SELECT id,title,category,description,thumbnail,published,created_at FROM videos WHERE published = 1 ORDER BY id DESC').all();
  res.json(rows);
});
app.get('/api/images', requirePublicAccess, (_req, res) => {
  const rows = db.prepare('SELECT id,title,category,description,filename,published FROM images WHERE published = 1 ORDER BY id DESC').all();
  res.json(rows);
});
app.get('/api/members', requirePublicAccess, (_req, res) => {
  const rows = db.prepare('SELECT id,name,pseudo,role,bio,photo,birth_date,city,phone,email,social_json,published FROM members WHERE published = 1 ORDER BY id DESC').all();
  res.json(rows.map(x => ({ ...x, social: parseSocial(x.social_json) })));
});
app.get('/api/upcoming', requirePublicAccess, (_req, res) => res.json(db.prepare('SELECT id,title,description,poster,release_label FROM upcoming WHERE published = 1 ORDER BY id DESC').all()));

app.post('/api/applications', requirePublicAccess, imageUpload.single('photo'), (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.role || !b.city) return res.status(400).json({ error: 'Nom, ville et rôle/talent sont obligatoires.' });
  const photo = req.file ? `/media/images/${req.file.filename}` : '';
  db.prepare(`INSERT INTO applications (name,pseudo,photo,birth_date,city,role,phone,email,social,personal_link,message)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(b.name,b.pseudo || '',photo,b.birth_date || '',b.city,b.role,b.phone || '',b.email || '',b.social || '',b.personal_link || '',b.message || '');
  res.status(201).json({ ok: true });
});

app.post('/api/purchases', requirePublicAccess, (req, res) => {
  const film = db.prepare('SELECT * FROM films WHERE id = ? AND published = 1').get(req.body?.filmId);
  if (!film) return res.status(404).json({ error: 'Film introuvable.' });
  if (!film.is_paid) return res.json({ ok: true, unlocked: true });
  const reference = `TCH-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const result = db.prepare('INSERT INTO purchases (film_id,session_id,status,provider,reference) VALUES (?,?,?,?,?)').run(film.id, req.sessionID, 'pending', 'manual', reference);
  res.status(201).json({ ok: true, purchaseId: result.lastInsertRowid, reference, status: 'pending', message: 'Demande de paiement créée. Un paiement réel doit être confirmé par un prestataire connecté ou par l’administrateur.' });
});

app.get('/api/media/video/:id', requirePublicAccess, (req, res) => {
  const film = db.prepare('SELECT * FROM films WHERE id = ? AND published = 1').get(req.params.id);
  if (!film || !film.video_filename) return res.status(404).json({ error: 'Vidéo indisponible.' });
  const unlocked = !film.is_paid || !!db.prepare("SELECT id FROM purchases WHERE film_id = ? AND session_id = ? AND status = 'confirmed' LIMIT 1").get(film.id, req.sessionID);
  if (!unlocked) return res.status(403).json({ error: 'Paiement requis.' });
  const file = path.join(videoDir, path.basename(film.video_filename));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Fichier vidéo introuvable.' });
  res.sendFile(file);
});

app.get('/api/media/trailer/:id', requirePublicAccess, (req, res) => {
  const film = db.prepare('SELECT * FROM films WHERE id = ? AND published = 1').get(req.params.id);
  if (!film || !film.trailer_filename) return res.status(404).json({ error: 'Bande-annonce indisponible.' });
  const file = path.join(videoDir, path.basename(film.trailer_filename));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Fichier bande-annonce introuvable.' });
  res.sendFile(file);
});

app.get('/api/media/video-public/:id', requirePublicAccess, (req, res) => {
  const video = db.prepare('SELECT * FROM videos WHERE id = ? AND published = 1').get(req.params.id);
  if (!video) return res.status(404).json({ error: 'Vidéo introuvable.' });
  const file = path.join(videoDir, path.basename(video.filename));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Fichier vidéo introuvable.' });
  res.sendFile(file);
});

app.use('/media/images', express.static(imageDir, { maxAge: '7d', index: false }));
app.use('/assets', express.static(path.join(root, 'public', 'assets'), { maxAge: '7d' }));

app.post('/api/contact', requirePublicAccess, (req, res) => {
  const { name, email, subject, message } = req.body || {};
  if (!name || !email || !subject || !message) return res.status(400).json({ error: 'Tous les champs sont obligatoires.' });
  db.prepare('INSERT INTO messages (name,email,subject,message) VALUES (?,?,?,?)').run(String(name).slice(0,120),String(email).slice(0,180),String(subject).slice(0,180),String(message).slice(0,5000));
  res.status(201).json({ ok: true });
});

app.get('/api/admin/data', requireAdmin, (_req, res) => {
  res.json({
    films: db.prepare('SELECT * FROM films ORDER BY id DESC').all(),
    videos: db.prepare('SELECT id,title,category,description,thumbnail,filename,published,created_at FROM videos ORDER BY id DESC').all(),
    images: db.prepare('SELECT * FROM images ORDER BY id DESC').all(),
    members: db.prepare('SELECT * FROM members ORDER BY id DESC').all().map(x => ({...x, social: parseSocial(x.social_json)})),
    applications: db.prepare('SELECT * FROM applications ORDER BY id DESC').all(),
    upcoming: db.prepare('SELECT * FROM upcoming ORDER BY id DESC').all(),
    purchases: db.prepare('SELECT p.*, f.title AS film_title FROM purchases p JOIN films f ON f.id = p.film_id ORDER BY p.id DESC').all(),
    messages: db.prepare('SELECT * FROM messages ORDER BY id DESC').all()
  });
});

app.post('/api/admin/films', requireAdmin, videoUpload.single('video'), (req, res) => {
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Titre obligatoire.' });
  const video = req.file ? req.file.filename : '';
  const trailer = b.trailer_filename || '';
  const poster = b.poster || '/assets/long-time-poster.png';
  const result = db.prepare(`INSERT INTO films (title,duration,rating,description,poster,video_filename,trailer_filename,is_paid,price,published,featured,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`).run(b.title,b.duration || '',b.rating || '',b.description || '',poster,video,trailer,parseBool(b.is_paid) ? 1 : 0,b.price ? Number(b.price) : null,parseBool(b.published) ? 1 : 0,parseBool(b.featured) ? 1 : 0);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.put('/api/admin/films/:id', requireAdmin, videoUpload.single('video'), (req, res) => {
  const old = db.prepare('SELECT * FROM films WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Film introuvable.' });
  const b = req.body || {};
  const newVideo = req.file ? req.file.filename : old.video_filename;
  const trailer = b.trailer_filename || old.trailer_filename;
  if (req.file && old.video_filename) safeUnlink(path.join(videoDir, path.basename(old.video_filename)));
  db.prepare(`UPDATE films SET title=?,duration=?,rating=?,description=?,poster=?,video_filename=?,trailer_filename=?,is_paid=?,price=?,published=?,featured=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(
    b.title || old.title,b.duration ?? old.duration,b.rating ?? old.rating,b.description ?? old.description,b.poster || old.poster,newVideo,trailer,parseBool(b.is_paid) ? 1 : 0,b.price ? Number(b.price) : null,parseBool(b.published) ? 1 : 0,parseBool(b.featured) ? 1 : 0,old.id);
  res.json({ ok: true });
});
app.delete('/api/admin/films/:id', requireAdmin, (req, res) => {
  const old = db.prepare('SELECT * FROM films WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Film introuvable.' });
  if (old.video_filename) safeUnlink(path.join(videoDir, path.basename(old.video_filename)));
  db.prepare('DELETE FROM films WHERE id = ?').run(old.id);
  res.json({ ok: true });
});

app.post('/api/admin/videos', requireAdmin, videoUpload.single('video'), (req, res) => {
  if (!req.file || !req.body?.title) return res.status(400).json({ error: 'Titre et vidéo obligatoires.' });
  const result = db.prepare('INSERT INTO videos (title,category,description,thumbnail,filename,published) VALUES (?,?,?,?,?,?)').run(req.body.title,req.body.category || 'Vidéos',req.body.description || '',req.body.thumbnail || '',req.file.filename,parseBool(req.body.published) ? 1 : 0);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.put('/api/admin/videos/:id', requireAdmin, videoUpload.single('video'), (req, res) => {
  const old = db.prepare('SELECT * FROM videos WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Vidéo introuvable.' });
  const filename = req.file ? req.file.filename : old.filename;
  if (req.file) safeUnlink(path.join(videoDir, path.basename(old.filename)));
  db.prepare('UPDATE videos SET title=?,category=?,description=?,thumbnail=?,filename=?,published=? WHERE id=?').run(req.body.title || old.title,req.body.category || old.category,req.body.description ?? old.description,req.body.thumbnail ?? old.thumbnail,filename,parseBool(req.body.published) ? 1 : 0,old.id);
  res.json({ ok: true });
});
app.delete('/api/admin/videos/:id', requireAdmin, (req, res) => {
  const old = db.prepare('SELECT * FROM videos WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Vidéo introuvable.' });
  safeUnlink(path.join(videoDir, path.basename(old.filename)));
  db.prepare('DELETE FROM videos WHERE id = ?').run(old.id);
  res.json({ ok: true });
});

app.post('/api/admin/images', requireAdmin, imageUpload.single('image'), (req, res) => {
  if (!req.file || !req.body?.title) return res.status(400).json({ error: 'Titre et image obligatoires.' });
  const result = db.prepare('INSERT INTO images (title,category,description,filename,published) VALUES (?,?,?,?,?)').run(req.body.title,req.body.category || 'Images',req.body.description || '',`/media/images/${req.file.filename}`,parseBool(req.body.published) ? 1 : 0);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.delete('/api/admin/images/:id', requireAdmin, (req, res) => {
  const old = db.prepare('SELECT * FROM images WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Image introuvable.' });
  safeUnlink(path.join(imageDir, path.basename(old.filename)));
  db.prepare('DELETE FROM images WHERE id = ?').run(old.id);
  res.json({ ok: true });
});

app.post('/api/admin/members', requireAdmin, imageUpload.single('photo'), (req, res) => {
  const b = req.body || {};
  if (!b.name) return res.status(400).json({ error: 'Nom obligatoire.' });
  const photo = req.file ? `/media/images/${req.file.filename}` : (b.photo || '');
  const social = parseSocial(b.social || '{}');
  const result = db.prepare(`INSERT INTO members (name,pseudo,role,bio,photo,birth_date,city,phone,email,social_json,published) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(b.name,b.pseudo || '',b.role || '',b.bio || '',photo,b.birth_date || '',b.city || '',b.phone || '',b.email || '',JSON.stringify(social),parseBool(b.published) ? 1 : 0);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.put('/api/admin/members/:id', requireAdmin, imageUpload.single('photo'), (req, res) => {
  const old = db.prepare('SELECT * FROM members WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Membre introuvable.' });
  const b = req.body || {};
  const photo = req.file ? `/media/images/${req.file.filename}` : (b.photo || old.photo);
  if (req.file && old.photo) safeUnlink(path.join(imageDir, path.basename(old.photo)));
  db.prepare(`UPDATE members SET name=?,pseudo=?,role=?,bio=?,photo=?,birth_date=?,city=?,phone=?,email=?,social_json=?,published=? WHERE id=?`).run(b.name || old.name,b.pseudo ?? old.pseudo,b.role ?? old.role,b.bio ?? old.bio,photo,b.birth_date ?? old.birth_date,b.city ?? old.city,b.phone ?? old.phone,b.email ?? old.email,JSON.stringify(parseSocial(b.social || old.social_json)),parseBool(b.published) ? 1 : 0,old.id);
  res.json({ ok: true });
});
app.delete('/api/admin/members/:id', requireAdmin, (req, res) => {
  const old = db.prepare('SELECT * FROM members WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Membre introuvable.' });
  if (old.photo) safeUnlink(path.join(imageDir, path.basename(old.photo)));
  db.prepare('DELETE FROM members WHERE id = ?').run(old.id);
  res.json({ ok: true });
});

app.post('/api/admin/applications/:id/accept', requireAdmin, (req, res) => {
  const a = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'Candidature introuvable.' });
  const social = a.social ? { social: a.social } : {};
  db.prepare(`INSERT INTO members (name,pseudo,role,bio,photo,birth_date,city,phone,email,social_json,published) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(a.name,a.pseudo,a.role,a.message,a.photo,a.birth_date,a.city,a.phone,a.email,JSON.stringify(social),1);
  db.prepare("UPDATE applications SET status='accepted' WHERE id=?").run(a.id);
  res.json({ ok: true });
});
app.post('/api/admin/applications/:id/reject', requireAdmin, (req, res) => {
  const result = db.prepare("UPDATE applications SET status='rejected' WHERE id=?").run(req.params.id);
  res.json({ ok: result.changes > 0 });
});

app.post('/api/admin/upcoming', requireAdmin, imageUpload.single('posterFile'), (req, res) => {
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Titre obligatoire.' });
  const poster = req.file ? `/media/images/${req.file.filename}` : (b.poster || '/assets/long-time-poster.png');
  const result = db.prepare('INSERT INTO upcoming (title,description,poster,release_label,published) VALUES (?,?,?,?,?)').run(b.title,b.description || '',poster,b.release_label || '',parseBool(b.published) ? 1 : 0);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.put('/api/admin/upcoming/:id', requireAdmin, imageUpload.single('posterFile'), (req, res) => {
  const old = db.prepare('SELECT * FROM upcoming WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Projet introuvable.' });
  const poster = req.file ? `/media/images/${req.file.filename}` : (req.body.poster || old.poster);
  if (req.file && old.poster) safeUnlink(path.join(imageDir, path.basename(old.poster)));
  db.prepare('UPDATE upcoming SET title=?,description=?,poster=?,release_label=?,published=? WHERE id=?').run(req.body.title || old.title,req.body.description ?? old.description,poster,req.body.release_label ?? old.release_label,parseBool(req.body.published) ? 1 : 0,old.id);
  res.json({ ok: true });
});
app.delete('/api/admin/upcoming/:id', requireAdmin, (req, res) => {
  const old = db.prepare('SELECT * FROM upcoming WHERE id = ?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Projet introuvable.' });
  if (old.poster) safeUnlink(path.join(imageDir, path.basename(old.poster)));
  db.prepare('DELETE FROM upcoming WHERE id=?').run(old.id);
  res.json({ ok: true });
});

app.post('/api/admin/purchases/:id/confirm', requireAdmin, (req, res) => {
  const result = db.prepare("UPDATE purchases SET status='confirmed', confirmed_at=CURRENT_TIMESTAMP WHERE id=?").run(req.params.id);
  res.json({ ok: result.changes > 0 });
});
app.post('/api/admin/purchases/:id/reject', requireAdmin, (req, res) => {
  const result = db.prepare("UPDATE purchases SET status='rejected' WHERE id=?").run(req.params.id);
  res.json({ ok: result.changes > 0 });
});

app.get('/admin.html', (_req, res) => res.sendFile(path.join(root, 'public', 'admin.html')));
app.use(express.static(path.join(root, 'public')));
app.get('/{*splat}', (_req, res) => res.sendFile(path.join(root, 'public', 'index.html')));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(400).json({ error: 'Requête invalide ou fichier non accepté.' });
});

app.listen(PORT, () => console.log(`T.CH MANANJARY running on http://localhost:${PORT}`));
