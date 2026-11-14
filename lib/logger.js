// Labcare V1 — journal du serveur (logs fichier).
// Un événement = une ligne JSON dans logs/app-AAAA-MM-JJ.log (un fichier par jour).
// Conservation : 30 jours, les fichiers plus anciens sont supprimés au démarrage.
// Règle de sécurité : on ne journalise JAMAIS de mot de passe, de code 2FA,
// de jeton (JWT, session, activation, réinitialisation) ni de donnée patient
// (nom, téléphone, adresse, contact). Seuls le code interne du dossier
// (ex. LAB-2026-0142), les étapes et les types d'exception sont autorisés.
// En cas d'erreur d'écriture, le serveur ne doit jamais planter :
// l'erreur est ignorée silencieusement.
const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '..', 'logs');
const RETENTION_DAYS = 30;

// Clés interdites : si un appelant les passe par erreur, elles sont supprimées.
const FORBIDDEN_KEYS = new Set([
  'password', 'currentPassword', 'newPassword', 'password_hash',
  'code', 'demoCode', 'twoFactorCode', 'two_factor_code',
  'token', 'reset_token', 'activation_token', 'session', 'jwt',
  'client_name', 'clientName', 'phone', 'contact', 'address',
  'company_name', 'companyName', 'hr_contact', 'hrContact',
  'effectif', 'formula',
]);

// Messages en français simple, un par code d'événement (code stable en anglais).
const MESSAGES = {
  server_started: 'Serveur démarré.',
  server_start_failed: 'Impossible de démarrer le serveur.',
  login_success: 'Connexion réussie.',
  login_failed: 'Connexion refusée : identifiants incorrects ou compte inactif.',
  login_password_ok_2fa: 'Mot de passe correct, code de double authentification demandé.',
  login_2fa_failed: 'Code de double authentification incorrect ou expiré.',
  login_2fa_success: 'Connexion réussie avec double authentification.',
  account_locked: 'Compte verrouillé après 5 échecs de connexion.',
  account_unlocked: 'Compte déverrouillé par un Administrateur.',
  logout: 'Déconnexion.',
  password_changed: 'Mot de passe changé depuis le profil.',
  password_reset: 'Mot de passe réinitialisé par le lien de réinitialisation.',
  password_reset_requested: 'Réinitialisation du mot de passe demandée.',
  admin_password_reset: 'Réinitialisation du mot de passe déclenchée par un Administrateur.',
  account_created: 'Compte créé par un Administrateur.',
  account_updated: 'Compte modifié par un Administrateur.',
  account_disabled: 'Compte désactivé par un Administrateur.',
  account_activated: 'Compte activé par le lien d’invitation.',
  invitation_resent: 'Invitation renvoyée par un Administrateur.',
  dossier_created: 'Dossier créé.',
  dossier_advanced: 'Dossier avancé à l’étape suivante.',
  dossier_closed: 'Dossier clôturé (parcours terminé).',
  dossier_exception: 'Exception signalée sur un dossier.',
  dossier_resumed: 'Dossier repris après une exception.',
  dossier_closed_blocked: 'Dossier bloqué clôturé.',
  dossier_updated: 'Informations du dossier modifiées.',
  api_error: 'Erreur interne du serveur.',
};

function dayStamp(date) {
  return date.toISOString().slice(0, 10); // AAAA-MM-JJ
}

function logFilePath(date) {
  return path.join(LOG_DIR, `app-${dayStamp(date)}.log`);
}

function ensureDir() {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  } catch (_) {
    // Impossible de créer le dossier : les écritures suivantes échoueront
    // silencieusement, le serveur continuera de fonctionner.
  }
}

// Supprime les fichiers de logs de plus de 30 jours (appelés au démarrage).
function pruneOldLogs() {
  try {
    ensureDir();
    const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
    for (const name of fs.readdirSync(LOG_DIR)) {
      if (!/^app-\d{4}-\d{2}-\d{2}\.log$/.test(name)) continue;
      const file = path.join(LOG_DIR, name);
      try {
        if (fs.statSync(file).mtimeMs < cutoff) fs.unlinkSync(file);
      } catch (_) { /* ignorer */ }
    }
  } catch (_) { /* ignorer : le serveur ne doit jamais planter à cause des logs */ }
}

function sanitize(details) {
  if (!details || typeof details !== 'object') return {};
  const out = {};
  for (const [key, value] of Object.entries(details)) {
    if (FORBIDDEN_KEYS.has(key)) continue; // jamais journalisé
    if (value === undefined) continue;
    out[key] = value;
  }
  return out;
}

function write(level, event, details) {
  try {
    ensureDir();
    const now = new Date();
    const line = JSON.stringify({
      time: now.toISOString(),
      level,
      event,
      message: MESSAGES[event] || event,
      ...sanitize(details),
    });
    fs.appendFile(logFilePath(now), line + '\n', (err) => {
      // Erreur d'écriture ignorée : le serveur ne doit pas planter.
    });
  } catch (_) {
    // Ignoré silencieusement.
  }
}

function info(event, details) { write('info', event, details); }
function warn(event, details) { write('warn', event, details); }
function error(event, details) { write('error', event, details); }

// Nettoyage des vieux fichiers au chargement du module (donc au démarrage du serveur).
pruneOldLogs();

module.exports = { info, warn, error, pruneOldLogs, LOG_DIR, RETENTION_DAYS };
