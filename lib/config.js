// Labcare V1 — configuration (secret de signature JWT).
// Lit JWT_SECRET depuis l'environnement, ou depuis un fichier .env simple
// à la racine du projet (lu ligne par ligne KEY=VALUE, sans jamais
// logger les valeurs). Les variables déjà définies dans l'environnement
// restent prioritaires sur le fichier .env.
// - En production (NODE_ENV=production) sans JWT_SECRET : le serveur
//   refuse de démarrer, avec un message clair.
// - En développement sans JWT_SECRET : un secret aléatoire éphémère est
//   généré à chaque démarrage (les sessions sont alors invalidées à
//   chaque redémarrage), avec un avertissement visible. Aucun secret
//   fixe n'est jamais écrit en dur dans le code.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const nodeEnv = process.env.NODE_ENV || 'development';
const isProd = nodeEnv === 'production';

function loadDotEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

loadDotEnv();

let jwtSecret = process.env.JWT_SECRET || '';
if (!jwtSecret) {
  if (isProd) {
    throw new Error(
      'Labcare V1 ne peut pas démarrer en production sans JWT_SECRET : définissez la variable d’environnement JWT_SECRET (ou ajoutez JWT_SECRET=... dans le fichier .env).'
    );
  }
  jwtSecret = crypto.randomBytes(32).toString('hex');
  console.warn(
    '[Labcare] ATTENTION : aucune variable JWT_SECRET définie. Un secret de signature éphémère a été généré pour ce démarrage uniquement : toutes les sessions seront invalidées au prochain redémarrage. Définissez JWT_SECRET dans un fichier .env pour des sessions stables.'
  );
}
// Un secret trop court affaiblit la signature des jetons : en production,
// 32 caractères minimum sont exigés (le README demande une valeur d'au
// moins 32 caractères). En développement, on avertit seulement.
if (jwtSecret.length < 32) {
  if (isProd) {
    throw new Error(
      'Labcare V1 ne peut pas démarrer en production : JWT_SECRET fait moins de 32 caractères. Générez un secret d’au moins 32 caractères (par exemple : node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))").'
    );
  }
  console.warn(
    '[Labcare] ATTENTION : JWT_SECRET fait moins de 32 caractères. Utilisez un secret d’au moins 32 caractères, même en développement.'
  );
}

module.exports = { jwtSecret, isProd, nodeEnv };
