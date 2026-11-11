// Labcare V1 — serveur unique (Express + SQLite).
// Sert le frontend et l'API. Construit à partir du PRD final Labcare (11 nov. 2026).
// Usage interne uniquement — aucun accès patient, aucun contenu médical affiché.
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const dbModule = require('./db');

const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

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
const INTERVENANT_ROLES = ['secretariat', 'preleveur', 'transport', 'laboratoire', 'medecin'];
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
const DESKTOP_SESSION_MS = 30 * 60 * 1000;
const MOBILE_SESSION_MS = 7 * 24 * 60 * 60 * 1000;

let db;

function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 10 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}
function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}
function isMobile(req) {
  return /mobile|android|iphone|ipad/i.test(req.get('user-agent') || '');
}
function publicUser(u) {
  if (!u) return null;
  const { password_hash, activation_token, reset_token, ...rest } = u;
  return { ...rest, roles: JSON.parse(u.roles || '[]') };
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
function createSession(user, req) {
  const token = randomToken();
  const mobile = isMobile(req);
  const now = Date.now();
  const expires = now + (mobile ? MOBILE_SESSION_MS : DESKTOP_SESSION_MS);
  db.run('INSERT INTO sessions (user_id, token_hash, is_mobile, created_at, expires_at, last_seen) VALUES (?,?,?,?,?,?)',
    [user.id, sha256(token), mobile ? 1 : 0, now, expires, now]);
  return { token, expires, mobile };
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

async function main() {
  db = await dbModule.init();

  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use(cookieParser());
  app.use(express.static(path.join(__dirname, 'public')));

  const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

  // --- Authentification ---
  async function auth(req, res, next) {
    const token = req.cookies.labcare_session;
    if (!token) return res.status(401).json({ error: 'Non connecté.' });
    const sess = db.get('SELECT * FROM sessions WHERE token_hash = ?', [sha256(token)]);
    if (!sess) return res.status(401).json({ error: 'Non connecté.' });
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
      db.run('UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id = ?', [Date.now(), Date.now() + DESKTOP_SESSION_MS, sess.id]);
    } else {
      db.run('UPDATE sessions SET last_seen = ? WHERE id = ?', [Date.now(), sess.id]);
    }
    req.user = db.parseRoles(user);
    req.session = sess;
    next();
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
  app.get('/api/meta', auth, (req, res) => res.json({ steps: STEPS, roles: ROLES, exceptions: EXCEPTIONS }));

  app.post('/api/auth/login', asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    const user = db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || user.status !== 'active' || !user.password_hash) {
      logAuth(user ? user.id : null, email, 'login', 0, 'Identifiants incorrects ou compte inactif.');
      return res.status(401).json({ error: 'E-mail ou mot de passe incorrect.' });
    }
    if (user.locked_until && user.locked_until > Date.now()) {
      const min = Math.ceil((user.locked_until - Date.now()) / 60000);
      logAuth(user.id, email, 'login', 0, 'Compte verrouillé.');
      return res.status(423).json({ error: `Compte verrouillé. Réessayez dans environ ${min} minute(s), ou demandez à un Administrateur de le déverrouiller.` });
    }
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) {
      const attempts = (user.failed_attempts || 0) + 1;
      const lockedUntil = attempts >= LOCKOUT_AFTER ? Date.now() + LOCKOUT_MS : null;
      db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?', [attempts, lockedUntil, user.id]);
      logAuth(user.id, email, 'login', 0, `Mot de passe incorrect (tentative ${attempts}).`);
      if (lockedUntil) return res.status(423).json({ error: 'Compte verrouillé 15 minutes après 5 échecs. Un Administrateur peut le déverrouiller avant.' });
      return res.status(401).json({ error: 'E-mail ou mot de passe incorrect.' });
    }
    db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
    const roles = JSON.parse(user.roles || '[]');
    // Double authentification obligatoire pour Admin et Médecin (PRD §5.2).
    if (roles.includes('admin') || roles.includes('medecin')) {
      const code = String(Math.floor(100000 + Math.random() * 900000));
      db.run('DELETE FROM two_factor_codes WHERE user_id = ?', [user.id]);
      db.run('INSERT INTO two_factor_codes (user_id, code_hash, expires_at) VALUES (?,?,?)',
        [user.id, bcrypt.hashSync(code, 10), Date.now() + 10 * 60 * 1000]);
      logAuth(user.id, email, 'login_password_ok', 1, 'Mot de passe correct, code 2FA demandé.');
      // VERSION DE TEST : le code s'affiche dans l'application pour simuler l'envoi
      // (en production, il partirait par application d'authentification ou par SMS).
      return res.json({ needs2fa: true, email: user.email, demoCode: code });
    }
    const session = createSession(user, req);
    db.run('UPDATE users SET last_login = ? WHERE id = ?', [Date.now(), user.id]);
    logAuth(user.id, email, 'login', 1, 'Connexion réussie.');
    setSessionCookie(res, session);
    res.json({ user: publicUser(user) });
  }));

  app.post('/api/auth/verify-2fa', asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const code = String(req.body.code || '').trim();
    const user = db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({ error: 'Code incorrect.' });
    const rec = db.get('SELECT * FROM two_factor_codes WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1', [user.id]);
    if (!rec || rec.expires_at < Date.now() || !bcrypt.compareSync(code, rec.code_hash)) {
      logAuth(user.id, email, 'login_2fa', 0, 'Code 2FA incorrect ou expiré.');
      return res.status(401).json({ error: 'Code incorrect ou expiré.' });
    }
    db.run('UPDATE two_factor_codes SET used = 1 WHERE id = ?', [rec.id]);
    const session = createSession(user, req);
    db.run('UPDATE users SET last_login = ? WHERE id = ?', [Date.now(), user.id]);
    logAuth(user.id, email, 'login', 1, 'Connexion réussie (2FA).');
    setSessionCookie(res, session);
    res.json({ user: publicUser(user) });
  }));

  app.post('/api/auth/logout', auth, (req, res) => {
    db.run('DELETE FROM sessions WHERE id = ?', [req.session.id]);
    res.clearCookie('labcare_session', { path: '/' });
    res.json({ ok: true });
  });

  app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

  app.post('/api/auth/forgot', asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const user = db.get('SELECT * FROM users WHERE email = ?', [email]);
    // Le message ne révèle jamais si l'adresse existe (PRD §5.2).
    if (user && user.status === 'active') {
      const token = randomToken();
      db.run('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [token, Date.now() + 60 * 60 * 1000, user.id]);
      logAuth(user.id, email, 'reset_requested', 1, 'Lien de réinitialisation demandé.');
      const resetUrl = `${req.protocol}://${req.get('host')}/#/reset?token=${token}`;
      // VERSION DE TEST : pas d'envoi d'e-mail, le lien s'affiche (simulation).
      // En production, ce lien part uniquement par e-mail et n'apparaît pas ici.
      return res.json({ ok: true, message: 'Si cet e-mail existe, un lien de réinitialisation a été envoyé.', resetUrl });
    }
    return res.json({ ok: true, message: 'Si cet e-mail existe, un lien de réinitialisation a été envoyé.' });
  }));

  app.post('/api/auth/reset', asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'Mot de passe invalide : 10 caractères minimum, avec des lettres et des chiffres.' });
    }
    const user = db.get('SELECT * FROM users WHERE reset_token = ?', [String(token || '')]);
    if (!user || !user.reset_expires || user.reset_expires < Date.now()) {
      return res.status(400).json({ error: 'Lien invalide ou expiré (1 heure, usage unique).' });
    }
    db.run('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL, failed_attempts = 0, locked_until = NULL WHERE id = ?',
      [bcrypt.hashSync(password, 10), user.id]);
    logAuth(user.id, user.email, 'password_reset', 1, 'Mot de passe réinitialisé.');
    res.json({ ok: true, message: 'Mot de passe changé. Vous pouvez vous connecter.' });
  }));

  app.post('/api/auth/activate', asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    if (!validPassword(password)) {
      return res.status(400).json({ error: 'Mot de passe invalide : 10 caractères minimum, avec des lettres et des chiffres.' });
    }
    const user = db.get('SELECT * FROM users WHERE activation_token = ?', [String(token || '')]);
    if (!user || !user.activation_expires || user.activation_expires < Date.now()) {
      return res.status(400).json({ error: "Lien d'activation invalide ou expiré (48 heures). Demandez à un Administrateur de le renvoyer." });
    }
    db.run('UPDATE users SET password_hash = ?, activation_token = NULL, activation_expires = NULL WHERE id = ?',
      [bcrypt.hashSync(password, 10), user.id]);
    logAuth(user.id, user.email, 'activated', 1, 'Compte activé par le lien d’invitation.');
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
    logAuth(user.id, user.email, 'password_change', 1, 'Mot de passe changé depuis le profil.');
    res.json({ ok: true, message: 'Mot de passe changé.' });
  }));

  // --- Dossiers ---
  app.get('/api/dossiers', auth, (req, res) => {
    const q = String(req.query.q || '').trim().toLowerCase();
    let rows = db.all('SELECT * FROM dossiers ORDER BY blocked DESC, rdv_date ASC, code ASC');
    if (q) {
      rows = rows.filter((d) => [d.code, d.client_name, d.company_name, d.phone].filter(Boolean).some((v) => String(v).toLowerCase().includes(q)));
    }
    res.json({ dossiers: rows.map(dossierWithNames) });
  });

  app.get('/api/dossiers/:id', auth, (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    const history = db.all('SELECT * FROM dossier_history WHERE dossier_id = ? ORDER BY created_at ASC, id ASC', [d.id]);
    const step = STEPS.find((s) => s.n === d.step);
    const canAdvance = d.status === 'open' && !d.blocked && step && req.user.roles.includes(step.role);
    const canSignalException = d.status === 'open' && !d.blocked && req.user.roles.some((r) => INTERVENANT_ROLES.includes(r));
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
    if (b.type === 'particulier' && !b.client_name) return res.status(400).json({ error: 'Le nom du client est obligatoire.' });
    if (b.type === 'entreprise' && !b.company_name) return res.status(400).json({ error: "Le nom de l'entreprise est obligatoire." });
    const maxRow = db.get('SELECT MAX(CAST(substr(code, 10) AS INTEGER)) AS m FROM dossiers');
    const num = (maxRow && maxRow.m ? maxRow.m : 161) + 1;
    const code = `LAB-2026-${String(num).padStart(4, '0')}`;
    const assigned = b.assigned_to ? db.get('SELECT * FROM users WHERE id = ? AND status = ?', [b.assigned_to, 'active']) : null;
    const r = db.run(
      `INSERT INTO dossiers (code, type, rdv_date, rdv_time, step, status, client_name, phone, contact, address,
        company_name, hr_contact, formula, effectif, assigned_to, created_by, created_at)
       VALUES (?,?,?,?,1,'open',?,?,?,?,?,?,?,?,?,?,?,?)`,
      [code, b.type, b.rdv_date, b.rdv_time || null, b.client_name || null, b.phone || null, b.contact || null,
        b.address || null, b.company_name || null, b.hr_contact || null, b.formula || null,
        b.effectif ? Number(b.effectif) : null, assigned ? assigned.id : req.user.id, req.user.id, Date.now()]
    );
    addHistory(r.id, req.user, 'create', null, 1, null, 'Dossier créé (RDV pris).');
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
      return res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
    }
    const next = STEPS[d.step]; // step n+1 (index n)
    db.run('UPDATE dossiers SET step = ? WHERE id = ?', [d.step + 1, d.id]);
    addHistory(d.id, req.user, 'advance', d.step, d.step + 1, null, `Passage à « ${next.label} ».`);
    notifyRoles([next.role], d.id, `${d.code} est passé à « ${next.label} » — c'est à vous.`);
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  app.post('/api/dossiers/:id/exception', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    if (d.status !== 'open') return res.status(400).json({ error: 'Ce dossier est clôturé.' });
    if (d.blocked) return res.status(400).json({ error: 'Une exception est déjà signalée sur ce dossier.' });
    if (!req.user.roles.some((r) => INTERVENANT_ROLES.includes(r))) {
      return res.status(403).json({ error: 'Seul un intervenant peut signaler une exception.' });
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
      notifyRoles(exc.notify, d.id, `${d.code} : ${exc.label} — dossier clôturé.`);
    } else {
      db.run('UPDATE dossiers SET exception = ?, blocked = 1 WHERE id = ?', [type, d.id]);
      addHistory(d.id, req.user, 'exception', d.step, d.step, type, note || exc.label);
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
    res.json({ dossier: dossierWithNames(db.get('SELECT * FROM dossiers WHERE id = ?', [d.id])) });
  }));

  app.patch('/api/dossiers/:id', auth, asyncHandler(async (req, res) => {
    const d = db.get('SELECT * FROM dossiers WHERE id = ?', [req.params.id]);
    if (!d) return res.status(404).json({ error: 'Dossier introuvable.' });
    if (!req.user.roles.some((r) => ['secretariat', 'admin'].includes(r))) {
      return res.status(403).json({ error: 'Seuls le Secrétariat ou un Administrateur peuvent modifier un dossier.' });
    }
    const b = req.body;
    const fields = {};
    for (const k of ['rdv_date', 'rdv_time', 'client_name', 'phone', 'contact', 'address', 'company_name', 'hr_contact', 'formula']) {
      if (b[k] !== undefined) fields[k] = b[k] === '' ? null : b[k];
    }
    if (b.effectif !== undefined) fields.effectif = b.effectif === '' || b.effectif === null ? null : Number(b.effectif);
    if (b.assigned_to !== undefined) {
      const u = b.assigned_to ? db.get('SELECT * FROM users WHERE id = ? AND status = ?', [b.assigned_to, 'active']) : null;
      if (b.assigned_to && !u) return res.status(400).json({ error: 'Intervenant introuvable ou désactivé.' });
      fields.assigned_to = b.assigned_to || null;
    }
    const keys = Object.keys(fields);
    if (keys.length) {
      db.run(`UPDATE dossiers SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, [...keys.map((k) => fields[k]), d.id]);
      addHistory(d.id, req.user, 'update', d.step, d.step, null, 'Informations du dossier modifiées.');
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
    const token = randomToken();
    const r = db.run(
      'INSERT INTO users (name, email, phone, roles, status, password_hash, activation_token, activation_expires, created_at) VALUES (?,?,?,?,?,NULL,?,?,?)',
      [String(name).trim(), em, phone || null, JSON.stringify(roles), 'active', token, Date.now() + 48 * 60 * 60 * 1000, Date.now()]
    );
    logAuth(req.user.id, req.user.email, 'user_created', 1, `Compte créé : ${em}.`);
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
      if (targetRoles.includes('admin') && activeAdminCount(target.id) < 2) {
        return res.status(400).json({ error: 'Impossible : il doit rester au moins 2 Administrateurs actifs.' });
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
      if (targetRoles.includes('admin') && !newRoles.includes('admin') && target.status !== 'disabled' && activeAdminCount(target.id) < 2) {
        return res.status(400).json({ error: 'Impossible : il doit rester au moins 2 Administrateurs actifs.' });
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
    }
    res.json({ user: publicUser(db.get('SELECT * FROM users WHERE id = ?', [target.id])) });
  }));

  app.post('/api/users/:id/unlock', auth, requireRole('admin'), (req, res) => {
    const target = db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'Compte introuvable.' });
    db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [target.id]);
    logAuth(req.user.id, req.user.email, 'unlock', 1, `Compte déverrouillé : ${target.email}.`);
    res.json({ ok: true });
  });

  app.post('/api/users/:id/resend-invitation', auth, requireRole('admin'), (req, res) => {
    const target = db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'Compte introuvable.' });
    if (target.password_hash) return res.status(400).json({ error: 'Ce compte est déjà activé.' });
    const token = randomToken();
    db.run('UPDATE users SET activation_token = ?, activation_expires = ? WHERE id = ?', [token, Date.now() + 48 * 60 * 60 * 1000, target.id]);
    const activationUrl = `${req.protocol}://${req.get('host')}/#/activate?token=${token}`;
    res.json({ ok: true, activationUrl });
  });

  app.get('/api/admin/auth-logs', auth, requireRole('admin'), (req, res) => {
    const logs = db.all('SELECT * FROM auth_logs ORDER BY created_at DESC, id DESC LIMIT 100');
    res.json({ logs });
  });

  // --- Frontend (SPA) ---
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Route inconnue.' });
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  });

  const server = app.listen(PORT, () => {
    console.log(`Labcare V1 en écoute sur le port ${PORT}`);
  });
  const shutdown = () => {
    db.save();
    server.close(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('Impossible de démarrer Labcare V1 :', err);
  process.exit(1);
});
