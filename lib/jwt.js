// Labcare V1 — jetons JWT (HS256) pour les sessions.
// Le jeton est signé ici (à la connexion, après la 2FA quand elle est
// requise) et vérifié dans le middleware d'authentification de server.js.
// La table `sessions` reste le registre : chaque jeton émis y a une ligne
// (token_hash = sha256 du jti, l'identifiant unique du jeton), et la
// révocation consiste à supprimer la ligne — le jeton ne fonctionne alors
// plus, même si sa signature reste valide.
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { jwtSecret } = require('./config');

// Durées nominales des jetons à l'émission (PRD §5) : 30 minutes sur
// bureau, 7 jours sur mobile.
const DESKTOP_TTL_MS = 30 * 60 * 1000;
const MOBILE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Empreinte stockée dans sessions.token_hash : on ne stocke jamais le
// jeton (ni son identifiant) en clair, comme avant avec le jeton aléatoire.
function hashTokenId(jti) {
  return crypto.createHash('sha256').update(jti).digest('hex');
}

// Signe un jeton pour l'utilisateur. Retourne { token, jti, expiresAt }.
// Contenu du jeton : sub = id de l'utilisateur, jti = identifiant unique
// du jeton, mobile = true/false, exp = fin de validité nominale à l'émission.
function signSessionToken(userId, mobile) {
  const jti = crypto.randomBytes(16).toString('hex');
  const ttlMs = mobile ? MOBILE_TTL_MS : DESKTOP_TTL_MS;
  const token = jwt.sign(
    { sub: userId, jti, mobile },
    jwtSecret,
    { algorithm: 'HS256', expiresIn: Math.floor(ttlMs / 1000) }
  );
  return { token, jti, expiresAt: Date.now() + ttlMs };
}

// Vérifie la signature du jeton (algorithme HS256 uniquement).
// L'expiration du jeton (exp) n'est PAS vérifiée ici : c'est la ligne du
// registre `sessions` (expires_at) qui fait foi — sur bureau, chaque
// requête authentifiée prolonge la session de 30 minutes, ce que la date
// d'expiration figée dans le jeton ne peut pas exprimer. Sans cela, un
// utilisateur actif serait déconnecté 30 minutes après sa connexion.
// Voir le middleware `auth` dans server.js.
// Retourne le contenu décodé, ou null si la signature est invalide.
function verifySessionToken(token) {
  try {
    return jwt.verify(token, jwtSecret, { algorithms: ['HS256'], ignoreExpiration: true });
  } catch (err) {
    return null;
  }
}

module.exports = { signSessionToken, verifySessionToken, hashTokenId, DESKTOP_TTL_MS, MOBILE_TTL_MS };
