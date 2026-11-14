// Labcare V1 — serveur unique (Express + SQLite).
// Sert le frontend et l'API. Construit à partir du PRD final Labcare (11 nov. 2026).
// Usage interne uniquement — aucun accès patient, aucun contenu médical affiché.
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const dbModule = require('./db');
const logger = require('./lib/logger');
const { isProd } = require('./lib/config');
const { signSessionToken, verifySessionToken, hashTokenId, DESKTOP_TTL_MS, MOBILE_TTL_MS } = require('./lib/jwt');

const PORT = process.env.PORT || 3000;

// --- Référentiel PRD ---
const STEPS = [
  { n: 1, label: 'RDV pris', role: 'secretariat' },
  { n: 2, label: 'RDV confirmé', role: 'secretariat' },
  { n: 3, label: 'Accueilli', role: 'preleveur' },
  { n: 4, label: 'Prélevé', role: 'preleveur' },
  { n: 5, label: 'Envoyé au labo', role: 'transport' },
  { n: 6, label: 'Résultat reçu', role: 'laboratoire' },
  { n: 7, label: 'Validé par le médecin', role: 'medecin' },
  { n: 8, label: 'Remis au patient', role: 'secretariat' },
];
const ROLES = {
  secretariat: 'Secrétariat / Accueil',
  preleveur: 'Préleveur',
  transport: 'Préleveur / Transport',
  laboratoire: 'Laboratoire',
  medecin: 'Médecin',
  admin: 'Administrateur',
};
// Comptes de test (DÉVELOPPEMENT UNIQUEMENT) : ils n'existent que si la
// base a été remplie par seed() (hors production). La liste est exposée au
// frontend par /api/test-accounts, jamais en production.
const TEST_ACCOUNTS = [
  { name: 'Secrétariat Labcare', email: 'secretariat@labcare-test.ci', pass: 'Labcare2026Secret', roles: 'Secrétariat / Accueil' },
  { name: 'Awa Diallo', email: 'preleveuse@labcare-test.ci', pass: 'Labcare2026Prelev', roles: 'Préleveur' },
  { name: 'Jean Dupont', email: 'transport@labcare-test.ci', pass: 'Labcare2026Transp', roles: 'Préleveur + Transport' },
  { name: 'Marie Koné', email: 'labo@labcare-test.ci', pass: 'Labcare2026Labo12', roles: 'Laboratoire' },
  { name: 'Dr Aya Kouassi', email: 'medecin@labcare-test.ci', pass: 'Labcare2026Medecin', roles: 'Médecin (2FA)' },
  { name: 'Hervé Admin', email: 'admin@labcare-test.ci', pass: 'Labcare2026Admin1', roles: 'Administrateur (2FA)' },
  { name: "Paul N'Guessan", email: 'preleveur2@labcare-test.ci', pass: 'Labcare2026Prelev2', roles: 'Préleveur' },
];
// Suites des exceptions — proposition du PRD §8.1 (à valider, appliquée ici).
const EXCEPTIONS = {
  annule: { label: 'RDV annulé par le patient', resumeStep: null, notify: ['secretariat'], closes: true },
  absent: { label: 'Patient absent à domicile', resumeStep: 1, notify: ['secretariat'] },
  prelevement_impossible: { label: 'Prélèvement impossible', resumeStep: 1, notify: ['secretariat'] },
  echantillon: { label: 'Échantillon à refaire / non conforme', resumeStep: 4, notify: ['preleveur', 'secretariat'] },
  resultat_retard: { label: 'Résultat en retard', resumeStep: 6, notify: ['laboratoire', 'secretariat'] },
};
const LOCKOUT_AFTER = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

let db;

function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 10 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}
// Empreinte d'un jeton d'activation ou de réinitialisation : on ne stocke
// jamais le jeton en clair en base, seulement son sha256 (comme pour les
// sessions, dont le jti est haché dans lib/jwt.js). La comparaison se fait
// sur le hash, jamais sur le clair.
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}
// Faux hash bcrypt, généré une fois au démarrage : pour un e-mail inconnu,
// on compare quand même le mot de passe contre lui, pour que le temps de
// réponse soit comparable à celui d'un vrai compte (anti-énumération).
const FAKE_PASSWORD_HASH = bcrypt.hashSync(randomToken(), 10);
// Révoque toutes les sessions d'un compte (après un changement de mot de
// passe, par exemple) : les jetons existants ne fonctionnent plus, même si
// leur signature reste valide, car leur ligne a disparu du registre.
function revokeSessions(userId) {
  db.run('DELETE FROM sessions WHERE user_id = ?', [userId]);
}
// Purge des sessions expirées et des codes 2FA expirés ou déjà utilisés :
// les tables ne grossissent pas indéfiniment.
function purgeExpired() {
  if (!db) return;
  const now = Date.now();
  db.run('DELETE FROM sessions WHERE expires_at < ?', [now]);
  db.run('DELETE FROM two_factor_codes WHERE expires_at < ? OR used = 1', [now]);
}
// Validation des champs de dossier : une date doit être une vraie date
// calendaire (2026-02-30 est rejetée), une heure doit être HH:MM.
function isValidDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}
function isValidTime(s) {
  return typeof s === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
}
function isMobile(req) {
  return /mobile|android|iphone|ipad/i.test(req.get('user-agent') || '');
}
function publicUser(u) {
  if (!u) return null;
  const { password_hash, activation_token, reset_token, ...rest } = u;
  // `roles` arrive soit en texte JSON (ligne de base), soit déjà en
  // tableau (req.user, déjà traité par db.parseRoles dans le middleware).
  return { ...rest, roles: Array.isArray(u.roles) ? u.roles : JSON.parse(u.roles || '[]') };
}
function logAuth(userId, email, event, success, detail) {
  db.run('INSERT INTO auth_logs (user_id, email, event, success, detail, created_at) VALUES (?,?,?,?,?,?)',
    [userId, email, event, success ? 1 : 0, detail || null, Date.now()]);
}
function notifyRoles(roles, dossierId, message) {
  const users = db.all("SELECT * FROM users WHERE status = 'active'");
  const now = Date.now();
  for (const u of users) {
    const r = JSON.parse(u.roles || '[]');
    if (r.some((x) => roles.includes(x))) {
      db.run('INSERT INTO notifications (user_id, dossier_id, message, created_at) VALUES (?,?,?,?)',
        [u.id, dossierId, message, now]);
    }
  }
}
function addHistory(dossierId, user, action, fromStep, toStep, exception, note) {
  db.run(
    'INSERT INTO dossier_history (dossier_id, user_id, user_name, action, from_step, to_step, exception, note, created_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [dossierId, user ? user.id : null, user ? user.name : null, action, fromStep, toStep, exception || null, note || null, Date.now()]
  );
}
// Crée une session JWT : le jeton est signé (HS256) et sa ligne est
// inscrite dans le registre `sessions` (token_hash = sha256 du jti).
// Durée nominale : 30 min sur bureau, 7 jours sur mobile (PRD §5).
// Appelée uniquement après mot de passe correct (sans 2FA), ou après
// code 2FA correct — jamais avant la 2FA quand elle est requise.
function createSession(user, req) {
  const mobile = isMobile(req);
  const { token, jti, expiresAt } = signSessionToken(user.id, mobile);
  const now = Date.now();
  db.run('INSERT INTO sessions (user_id, token_hash, is_mobile, created_at, expires_at, last_seen) VALUES (?,?,?,?,?,?)',
    [user.id, hashTokenId(jti), mobile ? 1 : 0, now, expiresAt, now]);
  return { token, expires: expiresAt, mobile };
}
function setSessionCookie(res, session) {
  res.cookie('labcare_session', session.token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/',
    maxAge: session.expires - Date.now(),
  });
}
function dossierWithNames(row) {
  if (!row) return null;
  const assigned = row.assigned_to ? db.get('SELECT id, name FROM users WHERE id = ?', [row.assigned_to]) : null;
  return { ...row, blocked: !!row.blocked, assigned_name: assigned ? assigned.name : null };
}
function activeAdminCount(exceptId) {
  const users = db.all("SELECT * FROM users WHERE status = 'active'");
  return users.filter((u) => JSON.parse(u.roles || '[]').includes('admin') && u.id !== exceptId).length;
}
// --- Mode maintenance ---
// Réglage stocké dans la table `settings`, clé 'maintenance' = '1' (active) ou '0' (inactive).
// Par défaut inactive. La maintenance ne supprime aucune donnée : elle ne fait que bloquer.
function getMaintenance() {
  try {
    const row = db.get("SELECT value FROM settings WHERE key = 'maintenance'");
    return row ? row.value === '1' : false;
  } catch (_) {
    return false;
  }
}
function setMaintenance(active) {
  db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance', ?)", [active ? '1' : '0']);
}
// Routes /api/* toujours accessibles pendant la maintenance (pour un non-admin) :
// /api/meta pour que le frontend connaisse l'état, /api/auth/me et /api/auth/logout
// pour que l'utilisateur puisse voir son état et se déconnecter.
const MAINTENANCE_EXEMPT = new Set(['/api/auth/me', '/api/auth/logout', '/api/meta']);
// Middleware de maintenance, placé après le middleware auth : il suppose
// req.user déjà rempli. Les Admins ne sont jamais bloqués (ils doivent
// pouvoir désactiver la maintenance). Les routes sans auth (connexion,
// 2FA, mot de passe oublié, activation) ne passent pas par ici et restent
// accessibles : un non-admin qui se connecte pendant la maintenance verra
// la page de maintenance après sa connexion.
function maintenanceGuard(req, res, next) {
  if (!getMaintenance()) return next();
  if (req.user.roles.includes('admin')) return next();
  if (MAINTENANCE_EXEMPT.has(req.path)) return next();
  return res.status(503).json({ error: 'Application en maintenance, revenez plus tard.', maintenance: true });
}

async function main() {
  db = await dbModule.init();
  // Purge au démarrage, puis toutes les heures (le minuteur ne retient pas
  // le processus à la sortie).
  purgeExpired();
  setInterval(purgeExpired, 60 * 60 * 1000).unref();

  const app = express();
  app.set('trust proxy', 1);
  // En-têtes de sécurité (helmet) + politique CSP. Les styles inline
  // (style="...") sont utilisés partout dans le frontend : ils restent
  // autorisés ; les scripts inline, eux, sont interdits (aucun n'existe).
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  }));
  app.use(express.json());
  app.use(cookieParser());
  app.use(express.static(path.join(__dirname, 'public')));

  // Limitation de débit sur les routes sensibles, EN PLUS du verrouillage
  // à 5 échecs (qui reste en place) : elle protège contre les essais
  // massifs venus d'une même adresse. Les limites sont larges pour ne pas
  // gêner l'équipe (5 personnes, éventuellement derrière une même adresse).
  // Render est derrière un proxy (trust proxy = 1) : la validation
  // trustProxy du limiteur est désactivée volontairement, l'adresse prise
  // en compte est celle que donne le proxy de confiance.
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false,
    validate: { trustProxy: false },
    message: { error: 'Trop de tentatives. Réessayez dans quelques minutes.' },
  });
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
    validate: { trustProxy: false },
    message: { error: 'Trop de tentatives de connexion. Réessayez dans quelques minutes.' },
  });
  const twofaLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
    validate: { trustProxy: false },
    message: { error: 'Trop de tentatives. Réessayez dans quelques minutes.' },
  });

  const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

  // --- Authentification (JWT) ---
  async function auth(req, res, next) {
    const token = req.cookies.labcare_session;
    if (!token) return res.status(401).json({ error: 'Non connecté.' });
    // 1. Signature du jeton (HS256) — un jeton forgé ou modifié est rejeté ici.
    const decoded = verifySessionToken(token);
    if (!decoded || !decoded.jti || typeof decoded.sub !== 'number') {
      return res.status(401).json({ error: 'Non connecté.' });
    }
    // 2. Ligne présente dans le registre `sessions` : la révocation
    //    (déconnexion, désactivation du compte) supprime la ligne, et le
    //    jeton ne fonctionne alors plus, même si sa signature est valide.
    const sess = db.get('SELECT * FROM sessions WHERE token_hash = ?', [hashTokenId(decoded.jti)]);
    if (!sess || sess.user_id !== decoded.sub) return res.status(401).json({ error: 'Non connecté.' });
    // 3. Ligne non expirée (c'est le registre qui fait foi : 30 min
    //    glissantes sur bureau, 7 jours fixes sur mobile).
    if (sess.expires_at < Date.now()) {
      db.run('DELETE FROM sessions WHERE id = ?', [sess.id]);
      return res.status(401).json({ error: 'Session expirée, reconnectez-vous.' });
    }
    const user = db.get('SELECT * FROM users WHERE id = ?', [sess.user_id]);
    if (!user || user.status !== 'active') {
      db.run('DELETE FROM sessions WHERE id = ?', [sess.id]);
      return res.status(401).json({ error: 'Non connecté.' });
    }
    // Session : 30 min d'inactivité sur ordinateur (glissante), 7 jours sur mobile (fixe).
    if (!sess.is_mobile) {
      const newExpires = Date.now() + DESKTOP_TTL_MS;
      db.run('UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id = ?', [Date.now(), newExpires, sess.id]);
      // Le cookie est rafraîchi avec la même valeur : sans cela, le
      // navigateur supprimerait le cookie 30 minutes après la connexion,
      // même si l'utilisateur est actif (le serveur seul prolongeait).
      setSessionCookie(res, { token, expires: newExpires });
    } else {
      db.run('UPDATE sessions SET last_seen = ? WHERE id = ?', [Date.now(), sess.id]);
    }
    req.user = db.parseRoles(user);
    req.session = sess;
    // Maintenance : après l'authentification, avant la route.
    return maintenanceGuard(req, res, next);
  }
  function requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user.roles.some((r) => roles.includes(r))) {
        return res.status(403).json({ error: 'Votre rôle ne permet pas cette action.' });
      }
      next();
    };
  }

  app.get('/api/health', (req, res) => res.json({ ok: true }));
  // Routes publiques (sans connexion) : la page de connexion en a besoin
  // avant même qu'un utilisateur soit connecté.
  // /api/public-meta dit au frontend si les comptes de test existent.
  // En production, ils n'existent jamais : la page de connexion n'affiche
  // alors aucun compte de test.
  app.get('/api/public-meta', (req, res) => res.json({ showTestAccounts: !isProd }));
  // Comptes de test : DÉVELOPPEMENT UNIQUEMENT. La table (e-mails + mots
  // de passe) n'est jamais exposée en production : la route répond 404.
  app.get('/api/test-accounts', (req, res) => {
    if (isProd) return res.status(404).json({ error: 'Route inconnue.' });
    res.json({ accounts: TEST_ACCOUNTS });
  });
  // Premier Administrateur (production) : utilisable uniquement tant
  // qu'aucun compte n'existe. Après la création du premier compte, la
  // route répond 404. C'est le seul moyen de créer un compte sans être
  // déjà Administrateur.
  app.post('/api/setup', asyncHandler(async (req, res) => {
    const count = db.get('SELECT COUNT(*) AS c FROM users').c;
    if (count > 0) return res.status(404).json({ error: 'Route inconnue.' });
    const { name, email, phone, password } = req.body;
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'Le nom complet est obligatoire.' });
    const em = String(email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ error: 'Adresse e-mail invalide.' });
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'Mot de passe invalide : 10 caractères minimum, avec des lettres et des chiffres.' });
    }
    const r = db.run(
      'INSERT INTO users (name, email, phone, roles, status, password_hash, created_at) VALUES (?,?,?,?,?,?,?)',
      [String(name).trim(), em, phone || null, JSON.stringify(['admin']), 'active', bcrypt.hashSync(password, 10), Date.now()]
    );
    logAuth(r.id, em, 'setup_admin_created', 1, 'Premier Administrateur créé au setup.');
    logger.info('setup_admin_created', { userId: r.id, email: em });
    res.status(201).json({ user: publicUser(db.get('SELECT * FROM users WHERE id = ?', [r.id])) });
  }));
  app.get('/api/meta', auth, (req, res) => res.json({ steps: STEPS, roles: ROLES, exceptions: EXCEPTIONS, maintenance: getMaintenance() }));

  // Mode maintenance (Admin uniquement).
  app.post('/api/admin/maintenance', auth, requireRole('admin'), (req, res) => {
    const active = req.body.active;
    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'Le champ « active » doit être vrai ou faux.' });
    }
    setMaintenance(active);
    logger.info('maintenance_changed', { userId: req.user.id, email: req.user.email, active });
    res.json({ maintenance: getMaintenance() });
  });

  app.post('/api/auth/login', loginLimiter, asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    const user = db.get('SELECT * FROM users WHERE email = ?', [email]);
    // Anti-énumération : pour un e-mail inconnu (ou un compte inactif /
    // sans mot de passe), on compare quand même le mot de passe contre un
    // faux hash, pour que le temps de réponse soit comparable à celui d'un
    // vrai compte. La réponse est ensuite la même erreur générique que pour
    // un mauvais mot de passe : rien ne révèle si le compte existe.
    if (!user || user.status !== 'active' || !user.password_hash) {
      bcrypt.compareSync(password, FAKE_PASSWORD_HASH);
      logAuth(user ? user.id : null, email, 'login', 0, 'Identifiants incorrects ou compte inactif.');
      logger.warn('login_failed', { email });
      return res.status(401).json({ error: 'E-mail ou mot de passe incorrect.' });
    }
    // Compte verrouillé : on compare quand même le mot de passe (temps de
    // réponse comparable) mais on ne renvoie jamais 423 : la réponse est la
    // même erreur générique. Le verrouillage reste actif côté serveur et
    // journalisé ; un Administrateur peut toujours déverrouiller le compte.
    const locked = user.locked_until && user.locked_until > Date.now();
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (locked || !ok) {
      if (locked) {
        logAuth(user.id, email, 'login', 0, 'Compte verrouillé.');
        logger.warn('login_failed', { userId: user.id, email, reason: 'compte verrouillé' });
      } else {
        const attempts = (user.failed_attempts || 0) + 1;
        const lockedUntil = attempts >= LOCKOUT_AFTER ? Date.now() + LOCKOUT_MS : null;
        db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?', [attempts, lockedUntil, user.id]);
        logAuth(user.id, email, 'login', 0, `Mot de passe incorrect (tentative ${attempts}).`);
        logger.warn('login_failed', { userId: user.id, email, attempts });
        if (lockedUntil) logger.warn('account_locked', { userId: user.id, email });
      }
      return res.status(401).json({ error: 'E-mail ou mot de passe incorrect.' });
    }
    db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
    const roles = JSON.parse(user.roles || '[]');
    // Double authentification obligatoire pour Admin et Médecin (PRD §5.2).
    if (roles.includes('admin') || roles.includes('medecin')) {
      const code = String(crypto.randomInt(100000, 1000000));
      db.run('DELETE FROM two_factor_codes WHERE user_id = ?', [user.id]);
      db.run('INSERT INTO two_factor_codes (user_id, code_hash, expires_at) VALUES (?,?,?)',
        [user.id, bcrypt.hashSync(code, 10), Date.now() + 10 * 60 * 1000]);
      logAuth(user.id, email, 'login_password_ok', 1, 'Mot de passe correct, code 2FA demandé.');
      logger.info('login_password_ok_2fa', { userId: user.id, email });
      // En production, le code n'est JAMAIS renvoyé dans la réponse : il
      // part par application d'authentification ou par SMS. En
      // développement, il s'affiche dans l'application (simulation,
      // version de test).
      if (isProd) return res.json({ needs2fa: true, email: user.email });
      return res.json({ needs2fa: true, email: user.email, demoCode: code });
    }
    const session = createSession(user, req);
    db.run('UPDATE users SET last_login = ? WHERE id = ?', [Date.now(), user.id]);
    logAuth(user.id, email, 'login', 1, 'Connexion réussie.');
    logger.info('login_success', { userId: user.id, email });
    setSessionCookie(res, session);
    res.json({ user: publicUser(user) });
  }));

  app.post('/api/auth/verify-2fa', twofaLimiter, asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const code = String(req.body.code || '').trim();
    const user = db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || user.status !== 'active') {
      logAuth(user ? user.id : null, email, 'login_2fa', 0, 'Code 2FA incorrect ou compte inactif.');
      logger.warn('login_2fa_failed', { email });
      return res.status(401).json({ error: 'Code incorrect ou expiré.' });
    }
    if (user.locked_until && user.locked_until > Date.now()) {
      logAuth(user.id, email, 'login_2fa', 0, 'Compte verrouillé.');
      logger.warn('login_2fa_failed', { userId: user.id, email, reason: 'compte verrouillé' });
      return res.status(401).json({ error: 'Code incorrect ou expiré.' });
    }
    const rec = db.get('SELECT * FROM two_factor_codes WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1', [user.id]);
    if (!rec || rec.expires_at < Date.now() || !bcrypt.compareSync(code, rec.code_hash)) {
      if (rec) {
        // Chaque échec est compté : après 5 essais ratés, le code est
        // invalidé — il faut se reconnecter pour en recevoir un nouveau.
        const attempts = (rec.attempts || 0) + 1;
        if (attempts >= 5) {
          db.run('UPDATE two_factor_codes SET attempts = ?, used = 1 WHERE id = ?', [attempts, rec.id]);
        } else {
          db.run('UPDATE two_factor_codes SET attempts = ? WHERE id = ?', [attempts, rec.id]);
        }
        logAuth(user.id, email, 'login_2fa', 0, `Code 2FA incorrect (tentative ${attempts}).`);
        logger.warn('login_2fa_failed', { userId: user.id, email, attempts });
      } else {
        logAuth(user.id, email, 'login_2fa', 0, 'Code 2FA incorrect ou expiré.');
        logger.warn('login_2fa_failed', { userId: user.id, email });
      }
      return res.status(401).json({ error: 'Code incorrect ou expiré.' });
    }
    db.run('UPDATE two_factor_codes SET used = 1 WHERE id = ?', [rec.id]);
    const session = createSession(user, req);
    db.run('UPDATE users SET last_login = ? WHERE id = ?', [Date.now(), user.id]);
    logAuth(user.id, email, 'login', 1, 'Connexion réussie (2FA).');
    logger.info('login_2fa_success', { userId: user.id, email });
    setSessionCookie(res, session);
    res.json({ user: publicUser(user) });
  }));

  app.post('/api/auth/logout', auth, (req, res) => {
    db.run('DELETE FROM sessions WHERE id = ?', [req.session.id]);
    logger.info('logout', { userId: req.user.id, email: req.user.email });
    res.clearCookie('labcare_session', { path: '/' });
    res.json({ ok: true });
  });

  app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

  app.post('/api/auth/forgot', authLimiter, asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const user = db.get('SELECT * FROM users WHERE email = ?', [email]);
    // Le message ne révèle jamais si l'adresse existe (PRD §5.2) :
    // la réponse est strictement identique que le compte existe ou non.
    // Le lien n'est jamais renvoyé ici, même en version de test.
    // En production, il part uniquement par e-mail ; en test, la
    // réinitialisation passe par l'Admin (POST /api/users/:id/reset-password).
    if (user && user.status === 'active') {
      const token = randomToken();
      // Le jeton est stocké haché (sha256), jamais en clair.
      db.run('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [hashToken(token), Date.now() + 60 * 60 * 1000, user.id]);
      logAuth(user.id, email, 'reset_requested', 1, 'Lien de réinitialisation demandé.');
      logger.info('password_reset_requested', { userId: user.id, email });
    }
    return res.json({ ok: true, message: 'Si cet e-mail existe, un lien de réinitialisation a été envoyé.' });
  }));

  app.post('/api/auth/reset', asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'Mot de passe invalide : 10 caractères minimum, avec des lettres et des chiffres.' });
    }
    const user = db.get('SELECT * FROM users WHERE reset_token = ?', [hashToken(String(token || ''))]);
    if (!user || !user.reset_expires || user.reset_expires < Date.now()) {
      return res.status(400).json({ error: 'Lien invalide ou expiré (1 heure, usage unique).' });
    }
    db.run('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL, failed_attempts = 0, locked_until = NULL WHERE id = ?',
      [bcrypt.hashSync(password, 10), user.id]);
    // Le mot de passe a changé : toutes les sessions existantes sont
    // révoquées (un jeton volé ne fonctionne plus).
    revokeSessions(user.id);
    logAuth(user.id, user.email, 'password_reset', 1, 'Mot de passe réinitialisé.');
    logger.info('password_reset', { userId: user.id, email: user.email });
    res.json({ ok: true, message: 'Mot de passe changé. Vous pouvez vous connecter.' });
  }));

  app.post('/api/auth/activate', asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'Mot de passe invalide : 10 caractères minimum, avec des lettres et des chiffres.' });
    }
    const user = db.get('SELECT * FROM users WHERE activation_token = ?', [hashToken(String(token || ''))]);
    if (!user || !user.activation_expires || user.activation_expires < Date.now()) {
      return res.status(400).json({ error: "Lien d'activation invalide ou expiré (48 heures). Demandez à un Administrateur de le renvoyer." });
    }
    db.run('UPDATE users SET password_hash = ?, activation_token = NULL, activation_expires = NULL WHERE id = ?',
      [bcrypt.hashSync(password, 10), user.id]);
    logAuth(user.id, user.email, 'activated', 1, 'Compte activé par le lien d’invitation.');
    logger.info('account_activated', { userId: user.id, email: user.email });
    res.json({ ok: true, message: 'Compte activé. Vous pouvez vous connecter.' });
  }));

  app.post('/api/auth/change-password', auth, asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = db.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user.password_hash || !bcrypt.compareSync(currentPassword || '', user.password_hash)) {
      return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });
    }
    if (!validPassword(newPassword)) {
      return res.status(400).json({ error: 'Nouveau mot de passe invalide : 10 caractères minimum, avec des lettres et des chiffres.' });
    }
    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 10), user.id]);
    // Le mot de passe a changé : toutes les sessions existantes sont
    // révoquées — l'utilisateur se reconnecte avec son nouveau mot de passe.
    revokeSessions(user.id);
    logAuth(user.id, user.email, 'password_change', 1, 'Mot de passe changé depuis le profil.');
    logger.info('password_changed', { userId: user.id, email: user.email });
    res.json({ ok: true, message: 'Mot de passe changé.' });
  }));

  // --- Dossiers ---
  app.get('/api/dossiers', auth, (req, res) => {
    const q = String(req.query.q || '').trim().toLowerCase();
    // Pagination : ?page= (défaut 1), ?limit= (défaut 10, maximum 50).
    let page = parseInt(req.query.page, 10);
    if (!Number.isFinite(page) || page < 1) page = 1;
    let limit = parseInt(req.query.limit, 10);
    if (!Number.isFinite(limit) || limit < 1) limit = 10;
    if (limit > 50) limit = 50;
    let rows = db.all('SELECT * FROM dossiers ORDER BY blocked DESC, rdv_date ASC, code ASC');
    // La recherche s'applique AVANT la pagination.
    if (q) {
      rows = rows.filter((d) => [d.code, d.client_name, d.company_name, d.phone].filter(Boolean).some((v) => String(v).toLowerCase().includes(q)));
    }
    const total = rows.length;
    const totalPages = Math.ceil(total / limit);
    const start = (page - 1) * limit;
    const pageRows = rows.slice(start, start + limit);
    res.json({ dossiers: pageRows.map(dossierWithNames), total, page, limit, totalPages });
  });

  app.get('/api/dossiers/:id', auth, (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    const history = db.all('SELECT * FROM dossier_history WHERE dossier_id = ? ORDER BY created_at ASC, id ASC', [d.id]);
    const step = STEPS.find((s) => s.n === d.step);
    const canAdvance = d.status === 'open' && !d.blocked && step && req.user.roles.includes(step.role);
    // Une exception ne peut être signalée que par le rôle de l'étape en
    // cours (même règle que l'avancement, PRD §5) : un intervenant ne
    // bloque pas un dossier qui n'est pas à son étape.
    const canSignalException = d.status === 'open' && !d.blocked && step && req.user.roles.includes(step.role);
    const exc = d.exception ? EXCEPTIONS[d.exception] : null;
    const canResume = d.status === 'open' && d.blocked && exc && !exc.closes && req.user.roles.some((r) => exc.notify.includes(r));
    const canClose = d.status === 'open' && d.blocked && req.user.roles.some((r) => ['secretariat', 'admin'].includes(r));
    const canEdit = req.user.roles.some((r) => ['secretariat', 'admin'].includes(r));
    res.json({ dossier: dossierWithNames(d), history, permissions: { canAdvance, canSignalException, canResume, canClose, canEdit } });
  });

  app.post('/api/dossiers', auth, requireRole('secretariat'), asyncHandler(async (req, res) => {
    const b = req.body;
    if (!['particulier', 'entreprise'].includes(b.type)) return res.status(400).json({ error: 'Type de client invalide.' });
    if (!b.rdv_date) return res.status(400).json({ error: 'La date du RDV est obligatoire.' });
    if (!isValidDate(b.rdv_date)) return res.status(400).json({ error: 'Date de RDV invalide (format attendu : AAAA-MM-JJ).' });
    if (b.rdv_time && !isValidTime(b.rdv_time)) return res.status(400).json({ error: 'Heure de RDV invalide (format attendu : HH:MM).' });
    if (b.effectif !== undefined && b.effectif !== '' && b.effectif !== null) {
      const n = Number(b.effectif);
      if (!Number.isInteger(n) || n < 0) return res.status(400).json({ error: 'Effectif prévu invalide : un nombre entier positif ou nul.' });
    }
    if (b.type === 'particulier' && !b.client_name) return res.status(400).json({ error: 'Le nom du client est obligatoire.' });
    if (b.type === 'entreprise' && !b.company_name) return res.status(400).json({ error: "Le nom de l'entreprise est obligatoire." });
    const maxRow = db.get('SELECT MAX(CAST(substr(code, 10) AS INTEGER)) AS m FROM dossiers');
    const num = (maxRow && maxRow.m ? maxRow.m : 161) + 1;
    // Le code porte l'année courante, pas une année figée.
    const code = `LAB-${new Date().getFullYear()}-${String(num).padStart(4, '0')}`;
    const assigned = b.assigned_to ? db.get('SELECT * FROM users WHERE id = ? AND status = ?', [b.assigned_to, 'active']) : null;
    const r = db.run(
      `INSERT INTO dossiers (code, type, rdv_date, rdv_time, step, status, client_name, phone, contact, address,
        company_name, hr_contact, formula, effectif, assigned_to, created_by, created_at)
       VALUES (?,?,?,?,1,'open',?,?,?,?,?,?,?,?,?,?,?)`,
      [code, b.type, b.rdv_date, b.rdv_time || null, b.client_name || null, b.phone || null, b.contact || null,
        b.address || null, b.company_name || null, b.hr_contact || null, b.formula || null,
        b.effectif ? Number(b.effectif) : null, assigned ? assigned.id : req.user.id, req.user.id, Date.now()]
    );
    addHistory(r.id, req.user, 'create', null, 1, null, 'Dossier créé (RDV pris).');
    logger.info('dossier_created', { userId: req.user.id, email: req.user.email, dossierCode: code });
    res.status(201).json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [r.id])) });
  }));

  app.post('/api/dossiers/:id/advance', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    if (d.status !== 'open') return res.status(400).json({ error: 'Ce dossier est clôturé.' });
    if (d.blocked) return res.status(400).json({ error: 'Ce dossier est bloqué. Reprenez-le ou clôturez-le d’abord.' });
    const step = STEPS.find((s) => s.n === d.step);
    if (!req.user.roles.includes(step.role)) {
      return res.status(403).json({ error: `Seul le rôle « ${ROLES[step.role]} » peut valider l'étape « ${step.label} ».` });
    }
    if (d.step >= 8) {
      db.run("UPDATE dossiers SET status = 'closed', closed_at = ?, close_reason = ? WHERE id = ?", [Date.now(), 'Remis au patient', d.id]);
      addHistory(d.id, req.user, 'close', 8, 8, null, 'Parcours terminé : résultat remis au patient.');
      logger.info('dossier_closed', { userId: req.user.id, email: req.user.email, dossierCode: d.code, fromStep: 8, toStep: 8 });
      return res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
    }
    const next = STEPS[d.step]; // step n+1 (index n)
    db.run('UPDATE dossiers SET step = ? WHERE id = ?', [d.step + 1, d.id]);
    addHistory(d.id, req.user, 'advance', d.step, d.step + 1, null, `Passage à « ${next.label} ».`);
    logger.info('dossier_advanced', { userId: req.user.id, email: req.user.email, dossierCode: d.code, fromStep: d.step, toStep: d.step + 1 });
    notifyRoles([next.role], d.id, `${d.code} est passé à « ${next.label} » — c'est à vous.`);
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  app.post('/api/dossiers/:id/exception', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    if (d.status !== 'open') return res.status(400).json({ error: 'Ce dossier est clôturé.' });
    if (d.blocked) return res.status(400).json({ error: 'Une exception est déjà signalée sur ce dossier.' });
    // Seul le rôle de l'étape en cours peut signaler une exception (même
    // règle que l'avancement, PRD §5) : un intervenant ne bloque pas un
    // dossier qui n'est pas à son étape.
    const step = STEPS.find((s) => s.n === d.step);
    if (!step || !req.user.roles.includes(step.role)) {
      return res.status(403).json({ error: `Seul le rôle « ${ROLES[step ? step.role : 'secretariat']} » peut signaler une exception à l'étape « ${step ? step.label : ''} ».` });
    }
    const type = req.body.type;
    const exc = EXCEPTIONS[type];
    if (!exc) return res.status(400).json({ error: 'Exception inconnue.' });
    const note = String(req.body.note || '').trim() || null;
    if (exc.closes) {
      db.run("UPDATE dossiers SET status = 'closed', exception = ?, blocked = 0, closed_at = ?, close_reason = ? WHERE id = ?",
        [type, Date.now(), exc.label, d.id]);
      addHistory(d.id, req.user, 'exception', d.step, d.step, type, note || exc.label);
      addHistory(d.id, req.user, 'close', d.step, d.step, type, 'Dossier clôturé : ' + exc.label);
      logger.warn('dossier_exception', { userId: req.user.id, email: req.user.email, dossierCode: d.code, exception: type });
      logger.info('dossier_closed', { userId: req.user.id, email: req.user.email, dossierCode: d.code, fromStep: d.step, toStep: d.step, reason: 'exception' });
      notifyRoles(exc.notify, d.id, `${d.code} : ${exc.label} — dossier clôturé.`);
    } else {
      db.run('UPDATE dossiers SET exception = ?, blocked = 1 WHERE id = ?', [type, d.id]);
      addHistory(d.id, req.user, 'exception', d.step, d.step, type, note || exc.label);
      logger.warn('dossier_exception', { userId: req.user.id, email: req.user.email, dossierCode: d.code, exception: type });
      notifyRoles(exc.notify, d.id, `${d.code} : ${exc.label} — dossier bloqué, action requise.`);
    }
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  app.post('/api/dossiers/:id/resume', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    if (!d.blocked || !d.exception) return res.status(400).json({ error: 'Ce dossier n’est pas bloqué.' });
    const exc = EXCEPTIONS[d.exception];
    if (!exc || exc.closes) return res.status(400).json({ error: 'Cette exception ne permet pas de reprise (dossier clôturé).' });
    if (!req.user.roles.some((r) => exc.notify.includes(r))) {
      return res.status(403).json({ error: 'Votre rôle ne permet pas de reprendre ce dossier.' });
    }
    const toStep = exc.resumeStep;
    db.run('UPDATE dossiers SET step = ?, exception = NULL, blocked = 0 WHERE id = ?', [toStep, d.id]);
    const label = STEPS.find((s) => s.n === toStep).label;
    addHistory(d.id, req.user, 'resume', d.step, toStep, d.exception, `Reprise du parcours à « ${label} » après : ${exc.label}.`);
    logger.info('dossier_resumed', { userId: req.user.id, email: req.user.email, dossierCode: d.code, fromStep: d.step, toStep, exception: d.exception });
    notifyRoles([STEPS.find((s) => s.n === toStep).role], d.id, `${d.code} a repris à « ${label} » — c'est à vous.`);
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  app.post('/api/dossiers/:id/close', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    if (d.status !== 'open' || !d.blocked) return res.status(400).json({ error: 'Seul un dossier bloqué peut être clôturé ici.' });
    if (!req.user.roles.some((r) => ['secretariat', 'admin'].includes(r))) {
      return res.status(403).json({ error: 'Seuls le Secrétariat ou un Administrateur peuvent clôturer un dossier bloqué.' });
    }
    const reason = String(req.body.reason || '').trim() || 'Clôturé depuis un dossier bloqué.';
    db.run("UPDATE dossiers SET status = 'closed', blocked = 0, closed_at = ?, close_reason = ? WHERE id = ?", [Date.now(), reason, d.id]);
    addHistory(d.id, req.user, 'close', d.step, d.step, d.exception, reason);
    logger.info('dossier_closed_blocked', { userId: req.user.id, email: req.user.email, dossierCode: d.code, exception: d.exception });
    // Notification à chaque changement de statut (PRD §7) : la clôture
    // d'un dossier bloqué alerte le Secrétariat / Accueil, comme l'annulation.
    notifyRoles(['secretariat'], d.id, `${d.code} : dossier bloqué clôturé — ${reason}`);
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  app.patch('/api/dossiers/:id', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    // Un dossier clôturé ne peut plus être modifié.
    if (d.status !== 'open') return res.status(400).json({ error: 'Ce dossier est clôturé, il ne peut plus être modifié.' });
    if (!req.user.roles.some((r) => ['secretariat', 'admin'].includes(r))) {
      return res.status(403).json({ error: 'Seuls le Secrétariat ou un Administrateur peuvent modifier un dossier.' });
    }
    const b = req.body;
    // Toute valeur non scalaire (objet, tableau) est rejetée : elle
    // provoquerait sinon une erreur 500 côté base.
    for (const [k, v] of Object.entries(b)) {
      if (v !== null && typeof v === 'object') {
        return res.status(400).json({ error: `Le champ « ${k} » doit être une valeur simple (texte ou nombre).` });
      }
    }
    const fields = {};
    const changes = [];
    const labels = {
      rdv_date: 'Date RDV', rdv_time: 'Heure RDV', client_name: 'Nom du client',
      phone: 'Téléphone', contact: 'Contact', address: 'Adresse',
      company_name: "Nom de l'entreprise", hr_contact: 'Contact RH',
      formula: 'Formule', effectif: 'Effectif prévu', assigned_to: 'Intervenant assigné',
    };
    const fmtVal = (v) => (v === null || v === undefined || v === '' ? '—' : String(v));
    for (const k of ['rdv_date', 'rdv_time', 'client_name', 'phone', 'contact', 'address', 'company_name', 'hr_contact', 'formula']) {
      if (b[k] !== undefined) {
        const v = b[k] === '' ? null : b[k];
        if (k === 'rdv_date' && v !== null && !isValidDate(v)) {
          return res.status(400).json({ error: 'Date de RDV invalide (format attendu : AAAA-MM-JJ).' });
        }
        if (k === 'rdv_time' && v !== null && !isValidTime(v)) {
          return res.status(400).json({ error: 'Heure de RDV invalide (format attendu : HH:MM).' });
        }
        fields[k] = v;
        if (String(d[k] ?? '') !== String(v ?? '')) changes.push(`${labels[k]} : ${fmtVal(d[k])} → ${fmtVal(v)}`);
      }
    }
    if (b.effectif !== undefined) {
      if (b.effectif === '' || b.effectif === null) {
        fields.effectif = null;
        if (d.effectif !== null) changes.push(`Effectif prévu : ${d.effectif} → —`);
      } else {
        const n = Number(b.effectif);
        if (!Number.isInteger(n) || n < 0) {
          return res.status(400).json({ error: 'Effectif prévu invalide : un nombre entier positif ou nul.' });
        }
        fields.effectif = n;
        if (d.effectif !== n) changes.push(`Effectif prévu : ${fmtVal(d.effectif)} → ${n}`);
      }
    }
    if (b.assigned_to !== undefined) {
      const assignedId = (b.assigned_to === '' || b.assigned_to === null) ? null : Number(b.assigned_to);
      if (b.assigned_to !== '' && b.assigned_to !== null && (!Number.isInteger(assignedId) || assignedId <= 0)) {
        return res.status(400).json({ error: 'Intervenant invalide.' });
      }
      const u = assignedId ? db.get('SELECT * FROM users WHERE id = ? AND status = ?', [assignedId, 'active']) : null;
      if (assignedId && !u) return res.status(400).json({ error: 'Intervenant introuvable ou désactivé.' });
      fields.assigned_to = assignedId;
      if ((d.assigned_to || null) !== (assignedId || null)) {
        const oldName = d.assigned_to ? (db.get('SELECT name FROM users WHERE id = ?', [d.assigned_to]) || {}).name : '—';
        changes.push(`Intervenant assigné : ${oldName || '—'} → ${u ? u.name : '—'}`);
      }
    }
    const keys = Object.keys(fields);
    if (keys.length) {
      db.run(`UPDATE dossiers SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, [...keys.map((k) => fields[k]), d.id]);
      // L'historique garde l'ancienne et la nouvelle valeur de chaque champ
      // modifié (audit) : « Effectif prévu : 12 → 15 ».
      addHistory(d.id, req.user, 'update', d.step, d.step, null, changes.length ? changes.join(' ; ') : 'Informations du dossier modifiées.');
      logger.info('dossier_updated', { userId: req.user.id, email: req.user.email, dossierCode: d.code });
    }
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  // --- Notifications ---
  app.get('/api/notifications', auth, (req, res) => {
    const list = db.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 50', [req.user.id]);
    const unread = db.get('SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0', [req.user.id]).c;
    res.json({ notifications: list, unread });
  });
  app.post('/api/notifications/read-all', auth, (req, res) => {
    db.run('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.user.id]);
    res.json({ ok: true });
  });

  // --- Administration (Utilisateurs) ---
  app.get('/api/users', auth, requireRole('admin'), (req, res) => {
    const users = db.all('SELECT * FROM users ORDER BY name ASC').map((u) => ({
      ...publicUser(u),
      locked: !!(u.locked_until && u.locked_until > Date.now()),
      hasPassword: !!u.password_hash,
    }));
    res.json({ users });
  });

  app.post('/api/users', auth, requireRole('admin'), asyncHandler(async (req, res) => {
    const { name, email, phone, roles } = req.body;
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'Le nom complet est obligatoire.' });
    const em = String(email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ error: 'Adresse e-mail invalide.' });
    if (!Array.isArray(roles) || roles.length === 0 || roles.some((r) => !ROLES[r])) {
      return res.status(400).json({ error: 'Choisissez au moins un rôle valide.' });
    }
    if (db.get('SELECT * FROM users WHERE email = ?', [em])) return res.status(400).json({ error: 'Un compte existe déjà avec cet e-mail.' });
    // Un seul Administrateur : refuser d'en créer un deuxième tant qu'un
    // Administrateur actif existe (le premier se crée par /api/setup).
    if (roles.includes('admin') && activeAdminCount() >= 1) {
      return res.status(400).json({ error: 'Un seul Administrateur est autorisé.' });
    }
    const token = randomToken();
    const r = db.run(
      'INSERT INTO users (name, email, phone, roles, status, password_hash, activation_token, activation_expires, created_at) VALUES (?,?,?,?,?,NULL,?,?,?)',
      [String(name).trim(), em, phone || null, JSON.stringify(roles), 'active', hashToken(token), Date.now() + 48 * 60 * 60 * 1000, Date.now()]
    );
    logAuth(req.user.id, req.user.email, 'user_created', 1, `Compte créé : ${em}.`);
    logger.info('account_created', { userId: req.user.id, email: req.user.email, newUserEmail: em });
    const activationUrl = `${req.protocol}://${req.get('host')}/#/activate?token=${token}`;
    // VERSION DE TEST : pas d'envoi d'e-mail, le lien s'affiche (simulation).
    res.status(201).json({ user: publicUser(db.get('SELECT * FROM users WHERE id = ?', [r.id])), activationUrl });
  }));

  app.patch('/api/users/:id', auth, requireRole('admin'), asyncHandler(async (req, res) => {
    const target = db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'Compte introuvable.' });
    const b = req.body;
    const targetRoles = JSON.parse(target.roles || '[]');
    if (b.status === 'disabled' && target.status !== 'disabled') {
      if (target.id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas désactiver votre propre compte.' });
      if (targetRoles.includes('admin') && activeAdminCount(target.id) < 1) {
        return res.status(400).json({ error: 'Impossible : il doit rester un Administrateur actif.' });
      }
      const open = db.get('SELECT COUNT(*) AS c FROM dossiers WHERE assigned_to = ? AND status = ?', [target.id, 'open']);
      if (open.c > 0 && !b.reassign_to) {
        return res.status(400).json({ error: `Ce compte a ${open.c} dossier(s) en cours. Réassignez-les d’abord (champ « Réassigner à »).`, openCount: open.c });
      }
      if (b.reassign_to) {
        const to = db.get('SELECT * FROM users WHERE id = ? AND status = ?', [b.reassign_to, 'active']);
        if (!to) return res.status(400).json({ error: 'Compte de réassignation introuvable ou désactivé.' });
        db.run('UPDATE dossiers SET assigned_to = ? WHERE assigned_to = ? AND status = ?', [to.id, target.id, 'open']);
      }
    }
    const updates = {};
    if (b.name !== undefined) updates.name = String(b.name).trim();
    if (b.phone !== undefined) updates.phone = b.phone || null;
    if (b.roles !== undefined) {
      if (!Array.isArray(b.roles) || b.roles.length === 0 || b.roles.some((r) => !ROLES[r])) {
        return res.status(400).json({ error: 'Choisissez au moins un rôle valide.' });
      }
      const newRoles = b.roles;
      // Un seul Administrateur : refuser d'ajouter le rôle à un autre compte
      // tant qu'un Administrateur actif existe.
      if (!targetRoles.includes('admin') && newRoles.includes('admin') && activeAdminCount(target.id) >= 1) {
        return res.status(400).json({ error: 'Un seul Administrateur est autorisé.' });
      }
      if (targetRoles.includes('admin') && !newRoles.includes('admin') && target.status !== 'disabled' && activeAdminCount(target.id) < 1) {
        return res.status(400).json({ error: 'Impossible : il doit rester un Administrateur actif.' });
      }
      updates.roles = JSON.stringify(newRoles);
    }
    if (b.status !== undefined) {
      if (!['active', 'disabled'].includes(b.status)) return res.status(400).json({ error: 'Statut invalide.' });
      updates.status = b.status;
      if (b.status === 'disabled') db.run('DELETE FROM sessions WHERE user_id = ?', [target.id]);
    }
    const keys = Object.keys(updates);
    if (keys.length) {
      db.run(`UPDATE users SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, [...keys.map((k) => updates[k]), target.id]);
      logAuth(req.user.id, req.user.email, 'user_updated', 1, `Compte modifié : ${target.email}.`);
      logger.info(updates.status === 'disabled' ? 'account_disabled' : 'account_updated', { userId: req.user.id, email: req.user.email, targetUserId: target.id, targetEmail: target.email });
    }
    res.json({ user: publicUser(db.get('SELECT * FROM users WHERE id = ?', [target.id])) });
  }));

  app.post('/api/users/:id/unlock', auth, requireRole('admin'), (req, res) => {
    const target = db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'Compte introuvable.' });
    db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [target.id]);
    logAuth(req.user.id, req.user.email, 'unlock', 1, `Compte déverrouillé : ${target.email}.`);
    logger.info('account_unlocked', { userId: req.user.id, email: req.user.email, targetUserId: target.id, targetEmail: target.email });
    res.json({ ok: true });
  });

  app.post('/api/users/:id/resend-invitation', auth, requireRole('admin'), (req, res) => {
    const target = db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'Compte introuvable.' });
    if (target.password_hash) return res.status(400).json({ error: 'Ce compte est déjà activé.' });
    const token = randomToken();
    db.run('UPDATE users SET activation_token = ?, activation_expires = ? WHERE id = ?', [hashToken(token), Date.now() + 48 * 60 * 60 * 1000, target.id]);
    logger.info('invitation_resent', { userId: req.user.id, email: req.user.email, targetUserId: target.id, targetEmail: target.email });
    const activationUrl = `${req.protocol}://${req.get('host')}/#/activate?token=${token}`;
    res.json({ ok: true, activationUrl });
  });

  // Réinitialisation déclenchée par l'Admin, pour un compte déjà activé
  // (PRD §5.3). Distincte de « renvoyer l'invitation », réservée aux
  // comptes non activés. Mêmes règles que le reset libre-service :
  // lien valable 1 heure, utilisable une seule fois (le token est effacé
  // après usage dans POST /api/auth/reset). Le lien est renvoyé à l'Admin,
  // qui connaît déjà le compte : ce n'est pas une fuite d'existence.
  app.post('/api/users/:id/reset-password', auth, requireRole('admin'), (req, res) => {
    const target = db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'Compte introuvable.' });
    if (target.status !== 'active') return res.status(400).json({ error: 'Ce compte est désactivé.' });
    if (!target.password_hash) return res.status(400).json({ error: "Ce compte n'est pas encore activé. Renvoyez l'invitation." });
    // Un Administrateur ne peut pas réinitialiser le mot de passe d'un
    // autre Administrateur : sinon il pourrait récupérer le lien et prendre
    // le compte. Un Admin se réinitialise son propre mot de passe par le
    // flux « Mot de passe oublié ». Décision à confirmer avec le client.
    const targetRoles = JSON.parse(target.roles || '[]');
    if (targetRoles.includes('admin') && target.id !== req.user.id) {
      return res.status(403).json({ error: 'Un Administrateur ne peut pas réinitialiser le mot de passe d’un autre Administrateur. L’autre Admin utilise « Mot de passe oublié ».' });
    }
    const token = randomToken();
    db.run('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [hashToken(token), Date.now() + 60 * 60 * 1000, target.id]);
    // Le compte va changer de mot de passe : ses sessions sont révoquées
    // dès maintenant.
    revokeSessions(target.id);
    logAuth(req.user.id, req.user.email, 'admin_reset_requested', 1, `Réinitialisation déclenchée par l'Admin : ${target.email}.`);
    logger.info('admin_password_reset', { userId: req.user.id, email: req.user.email, targetUserId: target.id, targetEmail: target.email });
    const resetUrl = `${req.protocol}://${req.get('host')}/#/reset?token=${token}`;
    // VERSION DE TEST : pas d'envoi d'e-mail, le lien s'affiche à l'Admin (simulation).
    res.json({ ok: true, resetUrl });
  });

  app.get('/api/admin/auth-logs', auth, requireRole('admin'), (req, res) => {
    const logs = db.all('SELECT * FROM auth_logs ORDER BY created_at DESC, id DESC LIMIT 100');
    res.json({ logs });
  });

  // Toute route /api/* inconnue, quelle que soit la méthode, répond 404 JSON.
  // Placé avant le renvoi SPA : les chemins hors /api/ renvoient toujours index.html.
  app.all('/api/*', (req, res) => res.status(404).json({ error: 'Route inconnue.' }));

  // --- Frontend (SPA) ---
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Route inconnue.' });
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    logger.error('api_error', { message: err.message, path: req.path, method: req.method });
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  });

  const server = app.listen(PORT, () => {
    console.log(`Labcare V1 en écoute sur le port ${PORT}`);
    logger.info('server_started', { port: PORT });
  });
  const shutdown = () => {
    db.save();
    server.close(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  logger.error('server_start_failed', { message: err.message });
  process.exit(1);
});
