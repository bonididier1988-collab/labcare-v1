// Labcare V1 — suite de tests de l'audit de sécurité (nov. 2026).
// Lance le serveur sur des ports temporaires avec des DATA_DIR temporaires
// (développement ET production) et vérifie chaque correction de l'audit,
// plus les non-régressions (connexion, 11 dossiers, déconnexion → 401).
// Usage : node tests/security-audit-tests.js
// Sortie : 0 si tous les tests passent, 1 sinon. Ne touche jamais à la
// vraie base (data/labcare.db) : tout se passe dans des dossiers temporaires.
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const PORT_DEV = 3431;
const PORT_PROD = 3432;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const CURRENT_YEAR = new Date().getFullYear();

let passed = 0;
let failed = 0;
const failures = [];
function check(name, ok, detail) {
  if (ok) { passed += 1; console.log(`  ✓ ${name}`); }
  else { failed += 1; failures.push(name); console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

// ---------- HTTP (avec jar de cookies simplifié et IP tournante) ----------
// Chaque appel utilise par défaut une adresse IP différente (en-tête
// X-Forwarded-For) pour ne pas déclencher le rate-limit entre les tests.
// Le test du rate-limit, lui, fixe une seule IP.
let ipCounter = 0;
function nextIp() { ipCounter += 1; return `10.99.0.${(ipCounter % 250) + 1}`; }
async function req(base, method, p, { body, cookie, ip, headers } = {}) {
  const h = { 'Content-Type': 'application/json', ...(headers || {}) };
  if (cookie) h.Cookie = cookie;
  h['X-Forwarded-For'] = ip || nextIp();
  const res = await fetch(base + p, {
    method, headers: h, body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* pas du JSON */ }
  return { status: res.status, headers: res.headers, json, text, setCookie: res.headers.get('set-cookie') };
}
function cookieFrom(res) {
  if (!res.setCookie) return null;
  return res.setCookie.split(';')[0];
}

// ---------- Serveur ----------
// Démarre le serveur sur un port et un DATA_DIR temporaires. Retourne un
// objet { child, stop(), getOutput() }.
function startServer({ port, dataDir, env }) {
  const child = spawn('node', ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  return {
    child,
    getOutput: () => out,
    async stop() {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      const t0 = Date.now();
      while (child.exitCode === null && Date.now() - t0 < 5000) await sleep(100);
      if (child.exitCode === null) child.kill('SIGKILL');
    },
  };
}
async function waitUp(base, timeoutMs = 20000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try { const r = await fetch(base + '/api/health'); if (r.ok) return true; } catch (_) { /* pas encore là */ }
    await sleep(250);
  }
  return false;
}
function mkTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------- Lecture directe de la base (sql.js) ----------
// Le serveur sauvegarde le fichier après chaque écriture (écriture
// atomique par .tmp + rename) : le fichier reflète toujours l'état courant.
let SQL = null;
async function loadSqlJs() {
  if (SQL) return SQL;
  const initSqlJs = require(path.join(ROOT, 'node_modules', 'sql.js'));
  SQL = await initSqlJs({ locateFile: (f) => path.join(ROOT, 'node_modules', 'sql.js', 'dist', f) });
  return SQL;
}
async function openDb(dataDir) {
  const sql = await loadSqlJs();
  const buf = fs.readFileSync(path.join(dataDir, 'labcare.db'));
  return new sql.Database(new Uint8Array(buf));
}
function dbGet(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows[0] || null;
}
function dbAll(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function writeDb(db, dataDir) {
  fs.writeFileSync(path.join(dataDir, 'labcare.db'), Buffer.from(db.export()));
}

// ---------- Comptes ----------
// Connexion simple (sans 2FA) : retourne { cookie, user } ou { needs2fa, demoCode }.
async function login(base, email, password, ip) {
  const r = await req(base, 'POST', '/api/auth/login', { body: { email, password }, ip });
  return { ...r, cookie: cookieFrom(r) };
}
// Les liens d'activation et de réinitialisation portent le jeton dans le
// fragment (#/activate?token=... / #/reset?token=...) : il faut le lire
// dans le hash de l'URL, pas dans la query string.
function tokenFromUrl(url, base) {
  const u = new URL(url, base);
  const hash = (u.hash || '').replace(/^#/, '');
  return new URLSearchParams(hash.split('?')[1] || '').get('token');
}
// Connexion Admin (2FA via le code affiché en développement).
async function loginAdmin(base) {
  const l = await login(base, 'admin@labcare-test.ci', 'Labcare2026Admin1');
  if (!l.json || !l.json.needs2fa || !l.json.demoCode) return null;
  const v = await req(base, 'POST', '/api/auth/verify-2fa', { body: { email: 'admin@labcare-test.ci', code: l.json.demoCode } });
  if (v.status !== 200) return null;
  return cookieFrom(v);
}

async function main() {
  const devDir = mkTempDir('labcare-audit-dev-');
  const prodDir = mkTempDir('labcare-audit-prod-');
  const LONG_SECRET = crypto.randomBytes(32).toString('hex');
  let dev = null;
  let prod = null;

  try {
    // ================= DÉVELOPPEMENT =================
    console.log('\n== Développement (NODE_ENV=development) ==');
    dev = startServer({ port: PORT_DEV, dataDir: devDir, env: { NODE_ENV: 'development' } });
    const DEV = `http://127.0.0.1:${PORT_DEV}`;
    if (!(await waitUp(DEV))) { console.log('  ✗ le serveur dev ne démarre pas'); console.log(dev.getOutput()); process.exitCode = 1; return; }
    check('serveur dev démarre', true);

    // 1. Seed en développement : 7 comptes, 11 dossiers.
    let db = await openDb(devDir);
    check('seed dev : 7 comptes', dbGet(db, 'SELECT COUNT(*) AS c FROM users').c === 7, `comptes=${dbGet(db, 'SELECT COUNT(*) AS c FROM users').c}`);
    check('seed dev : 11 dossiers', dbGet(db, 'SELECT COUNT(*) AS c FROM dossiers').c === 11);
    db.close();

    // 2. Connexion Secrétariat (non-régression).
    let sec = await login(DEV, 'secretariat@labcare-test.ci', 'Labcare2026Secret');
    check('connexion Secrétariat OK', sec.status === 200 && sec.json && sec.json.user && sec.json.user.email === 'secretariat@labcare-test.ci', `status=${sec.status}`);
    let secCookie = sec.cookie; // « let » : renouvelé après les réinitialisations de mot de passe (tests 11-12).
    // 3. Liste des dossiers : 11 au total, page 1 = 10, page 2 = 1.
    const d1 = await req(DEV, 'GET', '/api/dossiers?page=1&limit=10', { cookie: secCookie });
    const d2 = await req(DEV, 'GET', '/api/dossiers?page=2&limit=10', { cookie: secCookie });
    check('dossiers : 11 au total, 10 + 1', d1.json && d1.json.total === 11 && d1.json.dossiers.length === 10 && d2.json.dossiers.length === 1, `total=${d1.json && d1.json.total}`);

    // 4. Comptes de test exposés en développement.
    const ta = await req(DEV, 'GET', '/api/test-accounts');
    check('comptes de test exposés en dev (7)', ta.status === 200 && ta.json && Array.isArray(ta.json.accounts) && ta.json.accounts.length === 7, `status=${ta.status}`);
    const pm = await req(DEV, 'GET', '/api/public-meta');
    check('public-meta dev : showTestAccounts=true', pm.status === 200 && pm.json && pm.json.showTestAccounts === true);

    // 5. Login Admin : 2FA demandée, demoCode présent en dev, 6 chiffres.
    const admLogin = await login(DEV, 'admin@labcare-test.ci', 'Labcare2026Admin1');
    check('login Admin : needs2fa + demoCode en dev', admLogin.json && admLogin.json.needs2fa === true && /^\d{6}$/.test(admLogin.json.demoCode || ''), `réponse=${JSON.stringify(admLogin.json)}`);
    const demoCode = admLogin.json.demoCode;

    // 6. 2FA : 5 codes faux → code invalidé ; le bon code ensuite est refusé.
    for (let i = 0; i < 5; i += 1) {
      const v = await req(DEV, 'POST', '/api/auth/verify-2fa', { body: { email: 'admin@labcare-test.ci', code: '000000' } });
      if (v.status !== 401) check(`2FA faux code ${i + 1} → 401`, false, `status=${v.status}`);
    }
    db = await openDb(devDir);
    const rec = dbGet(db, 'SELECT * FROM two_factor_codes WHERE user_id = (SELECT id FROM users WHERE email = ?) ORDER BY id DESC LIMIT 1', ['admin@labcare-test.ci']);
    check('2FA : 5 échecs comptés, code invalidé (used=1)', !!rec && rec.attempts === 5 && rec.used === 1, `attempts=${rec && rec.attempts} used=${rec && rec.used}`);
    db.close();
    const vAfter = await req(DEV, 'POST', '/api/auth/verify-2fa', { body: { email: 'admin@labcare-test.ci', code: demoCode } });
    check('2FA : bon code refusé après 5 échecs', vAfter.status === 401, `status=${vAfter.status}`);

    // 7. 2FA : nouveau code correct → session.
    const admCookie = await loginAdmin(DEV);
    check('2FA : code correct → session Admin', !!admCookie, 'pas de cookie de session');
    const meAdm = await req(DEV, 'GET', '/api/auth/me', { cookie: admCookie });
    check('2FA : /me OK après 2FA', meAdm.status === 200 && meAdm.json.user.roles.includes('admin'));

    // 8. Anti-énumération : même statut et même message pour e-mail inconnu,
    //    mauvais mot de passe et compte verrouillé (jamais de 423).
    const unk = await login(DEV, 'inconnu@labcare-test.ci', 'Nimporte2026');
    const wrong = await login(DEV, 'secretariat@labcare-test.ci', 'Mauvais2026mdp');
    check('login : e-mail inconnu → 401 générique', unk.status === 401 && unk.json.error === 'E-mail ou mot de passe incorrect.', `status=${unk.status} msg=${unk.json && unk.json.error}`);
    check('login : mauvais mot de passe → 401, même message', wrong.status === 401 && wrong.json.error === unk.json.error);
    // Compte dédié au verrouillage : créé par l'Admin, puis activé.
    const created = await req(DEV, 'POST', '/api/users', { cookie: admCookie, body: { name: 'Test Verrouillage', email: 'verrou@labcare-test.ci', phone: '', roles: ['secretariat'] } });
    const actToken = tokenFromUrl(created.json.activationUrl, DEV);
    const act = await req(DEV, 'POST', '/api/auth/activate', { body: { token: actToken, password: 'Verrou2026Test' } });
    check('compte de test verrouillage créé + activé', created.status === 201 && act.status === 200, `create=${created.status} activate=${act.status}`);
    for (let i = 0; i < 5; i += 1) await login(DEV, 'verrou@labcare-test.ci', 'Mauvais2026mdp');
    const lockedOk = await login(DEV, 'verrou@labcare-test.ci', 'Verrou2026Test');
    check('login : compte verrouillé → 401 générique (pas de 423)', lockedOk.status === 401 && lockedOk.json.error === 'E-mail ou mot de passe incorrect.', `status=${lockedOk.status}`);
    db = await openDb(devDir);
    const lockedUser = dbGet(db, 'SELECT * FROM users WHERE email = ?', ['verrou@labcare-test.ci']);
    check('verrouillage actif côté serveur (locked_until futur)', !!lockedUser.locked_until && lockedUser.locked_until > Date.now());
    db.close();
    const unlock = await req(DEV, 'POST', `/api/users/${lockedUser.id}/unlock`, { cookie: admCookie, body: {} });
    const afterUnlock = await login(DEV, 'verrou@labcare-test.ci', 'Verrou2026Test');
    check('déverrouillage par l’Admin puis connexion OK', unlock.status === 200 && afterUnlock.status === 200, `unlock=${unlock.status} login=${afterUnlock.status}`);

    // 9. Jetons hachés en base : activation (création) et réinitialisation (Admin).
    const created2 = await req(DEV, 'POST', '/api/users', { cookie: admCookie, body: { name: 'Test Hash', email: 'hash@labcare-test.ci', phone: '', roles: ['preleveur'] } });
    const actToken2 = tokenFromUrl(created2.json.activationUrl, DEV);
    db = await openDb(devDir);
    const uHash = dbGet(db, 'SELECT * FROM users WHERE email = ?', ['hash@labcare-test.ci']);
    check('jeton d’activation stocké haché (sha256, pas en clair)', !!uHash.activation_token && uHash.activation_token === sha256(actToken2) && uHash.activation_token !== actToken2, `stocké=${uHash.activation_token && uHash.activation_token.slice(0, 12)}…`);
    db.close();
    const resetReq = await req(DEV, 'POST', '/api/users/1/reset-password', { cookie: admCookie, body: {} });
    const resetToken = tokenFromUrl(resetReq.json.resetUrl, DEV);
    db = await openDb(devDir);
    const uReset = dbGet(db, 'SELECT * FROM users WHERE id = ?', [1]);
    check('jeton de réinitialisation stocké haché (sha256, pas en clair)', !!uReset.reset_token && uReset.reset_token === sha256(resetToken) && uReset.reset_token !== resetToken);
    db.close();

    // 10. Un seul Administrateur : création d'un 2e Admin refusée, ajout du
    // rôle Admin à un autre compte refusé, retrait du rôle au seul Admin
    // refusé ; reset d'un non-admin toujours autorisé.
    const createAdmin2 = await req(DEV, 'POST', '/api/users', { cookie: admCookie, body: { name: 'Deuxième Admin', email: 'admin2@labcare-test.ci', phone: '', roles: ['admin'] } });
    check('création d’un 2e Admin refusée (400)', createAdmin2.status === 400, `status=${createAdmin2.status}`);
    const addAdminRole = await req(DEV, 'PATCH', '/api/users/1', { cookie: admCookie, body: { roles: ['secretariat', 'admin'] } });
    check('ajout du rôle Admin refusé (400)', addAdminRole.status === 400, `status=${addAdminRole.status}`);
    const usersList = await req(DEV, 'GET', '/api/users', { cookie: admCookie });
    const admins = (usersList.json.users || []).filter((u) => u.roles.includes('admin'));
    // 9 comptes à ce stade : 7 du seed + 2 créés aux tests 8 et 9.
    check('un seul Admin actif, 9 comptes (7 seed + 2 créés)', admins.length === 1 && usersList.json.users.length === 9, `admins=${admins.length} comptes=${usersList.json.users.length}`);
    const removeAdminRole = await req(DEV, 'PATCH', `/api/users/${admins[0].id}`, { cookie: admCookie, body: { roles: ['secretariat'] } });
    check('retrait du rôle au seul Admin refusé (400)', removeAdminRole.status === 400, `status=${removeAdminRole.status}`);
    check('reset Admin→Secrétariat autorisé (200)', resetReq.status === 200, `status=${resetReq.status}`);

    // 11. Changement de mot de passe → sessions révoquées.
    const sec2 = await login(DEV, 'secretariat@labcare-test.ci', 'Labcare2026Secret');
    const cookieA = sec2.cookie;
    const chg = await req(DEV, 'POST', '/api/auth/change-password', { cookie: cookieA, body: { currentPassword: 'Labcare2026Secret', newPassword: 'Temp2026Pass1' } });
    const meOld = await req(DEV, 'GET', '/api/auth/me', { cookie: cookieA });
    check('change-password : ancien jeton → 401', chg.status === 200 && meOld.status === 401, `change=${chg.status} me=${meOld.status}`);
    const secNew = await login(DEV, 'secretariat@labcare-test.ci', 'Temp2026Pass1');
    check('change-password : connexion avec le nouveau mot de passe', secNew.status === 200, `status=${secNew.status}`);
    await req(DEV, 'POST', '/api/auth/change-password', { cookie: secNew.cookie, body: { currentPassword: 'Temp2026Pass1', newPassword: 'Labcare2026Secret' } });

    // 12. Reset par lien → sessions révoquées (y compris reset déclenché par l'Admin).
    const sec3 = await login(DEV, 'secretariat@labcare-test.ci', 'Labcare2026Secret');
    const cookieB = sec3.cookie;
    const resetReq2 = await req(DEV, 'POST', '/api/users/1/reset-password', { cookie: admCookie, body: {} });
    const meAfterAdminReset = await req(DEV, 'GET', '/api/auth/me', { cookie: cookieB });
    check('reset Admin : sessions révoquées dès le déclenchement', meAfterAdminReset.status === 401, `status=${meAfterAdminReset.status}`);
    const resetToken2 = tokenFromUrl(resetReq2.json.resetUrl, DEV);
    const doReset = await req(DEV, 'POST', '/api/auth/reset', { body: { token: resetToken2, password: 'Temp2026Pass2' } });
    const secNew2 = await login(DEV, 'secretariat@labcare-test.ci', 'Temp2026Pass2');
    check('reset par lien : nouveau mot de passe fonctionne', doReset.status === 200 && secNew2.status === 200, `reset=${doReset.status} login=${secNew2.status}`);
    const resetReq3 = await req(DEV, 'POST', '/api/users/1/reset-password', { cookie: admCookie, body: {} });
    const resetToken3 = tokenFromUrl(resetReq3.json.resetUrl, DEV);
    await req(DEV, 'POST', '/api/auth/reset', { body: { token: resetToken3, password: 'Labcare2026Secret' } });
    // Les changements de mot de passe ci-dessus ont révoqué la session du
    // test 2 : on se reconnecte pour obtenir un cookie frais (utilisé par
    // les tests exception / PATCH / création de dossier ci-dessous).
    const secFresh = await login(DEV, 'secretariat@labcare-test.ci', 'Labcare2026Secret');
    secCookie = secFresh.cookie;
    check('session Secrétariat renouvelée après les réinitialisations', secFresh.status === 200, `login=${secFresh.status}`);

    // 13. Exception : un seul historique, et seulement le rôle de l'étape.
    const pre = await login(DEV, 'preleveuse@labcare-test.ci', 'Labcare2026Prelev');
    db = await openDb(devDir);
    const dosStep3 = dbGet(db, "SELECT * FROM dossiers WHERE step = 3 AND status = 'open' AND blocked = 0 LIMIT 1");
    const dosStep1 = dbGet(db, "SELECT * FROM dossiers WHERE step = 1 AND status = 'open' LIMIT 1");
    db.close();
    const excWrongRole = await req(DEV, 'POST', `/api/dossiers/${dosStep3.id}/exception`, { cookie: secCookie, body: { type: 'absent', note: 'test rôle' } });
    check('exception : Secrétariat sur étape Préleveur → 403', excWrongRole.status === 403, `status=${excWrongRole.status}`);
    const excOk = await req(DEV, 'POST', `/api/dossiers/${dosStep3.id}/exception`, { cookie: pre.cookie, body: { type: 'absent', note: 'Patient absent au test.' } });
    check('exception : Préleveur sur son étape → 200', excOk.status === 200, `status=${excOk.status}`);
    db = await openDb(devDir);
    const excHist = dbAll(db, "SELECT * FROM dossier_history WHERE dossier_id = ? AND action = 'exception'", [dosStep3.id]);
    check('exception : un seul historique (pas de doublon)', excHist.length === 1, `lignes=${excHist.length}`);
    db.close();
    const excSecOk = await req(DEV, 'POST', `/api/dossiers/${dosStep1.id}/exception`, { cookie: secCookie, body: { type: 'annule' } });
    check('exception : Secrétariat sur son étape → 200', excSecOk.status === 200, `status=${excSecOk.status}`);

    // 14. PATCH : validations + historique avec anciennes valeurs.
    db = await openDb(devDir);
    const dosEnt = dbGet(db, "SELECT * FROM dossiers WHERE code = 'LAB-2026-0145'");
    db.close();
    const patchCases = [
      ['effectif "abc" → 400', { effectif: 'abc' }],
      ['effectif -1 → 400', { effectif: -1 }],
      ['effectif 12.5 → 400', { effectif: 12.5 }],
      ['rdv_date 2026-02-30 → 400', { rdv_date: '2026-02-30' }],
      ['rdv_date "pas-une-date" → 400', { rdv_date: 'pas-une-date' }],
      ['objet JSON dans un champ → 400 (pas 500)', { client_name: { x: 1 } }],
    ];
    for (const [label, body] of patchCases) {
      const r = await req(DEV, 'PATCH', `/api/dossiers/${dosEnt.id}`, { cookie: secCookie, body });
      check(`PATCH ${label}`, r.status === 400, `status=${r.status}`);
    }
    const patchOk = await req(DEV, 'PATCH', `/api/dossiers/${dosEnt.id}`, { cookie: secCookie, body: { effectif: 30 } });
    check('PATCH effectif 25 → 30 accepté', patchOk.status === 200 && patchOk.json.dossier.effectif === 30, `status=${patchOk.status}`);
    db = await openDb(devDir);
    const updHist = dbGet(db, "SELECT * FROM dossier_history WHERE dossier_id = ? AND action = 'update' ORDER BY id DESC LIMIT 1", [dosEnt.id]);
    check('PATCH : historique « 25 → 30 »', !!updHist && updHist.note && updHist.note.includes('25 → 30'), `note=${updHist && updHist.note}`);
    db.close();
    const patchClosed = await req(DEV, 'PATCH', `/api/dossiers/${dosStep1.id}`, { cookie: secCookie, body: { effectif: 5 } });
    check('PATCH dossier clôturé → 400', patchClosed.status === 400, `status=${patchClosed.status}`);

    // 15. Nouveau dossier : code avec l'année courante.
    const created3 = await req(DEV, 'POST', '/api/dossiers', { cookie: secCookie, body: { type: 'particulier', rdv_date: '2026-11-20', client_name: 'Test Année', phone: '+225 00 00 00 00', address: 'Test' } });
    check(`nouveau dossier : code LAB-${CURRENT_YEAR}-…`, created3.status === 201 && created3.json.dossier.code.startsWith(`LAB-${CURRENT_YEAR}-`), `code=${created3.json && created3.json.dossier && created3.json.dossier.code}`);

    // 16. Rate-limit : 21 connexions depuis la même IP → 429.
    let got429 = false;
    for (let i = 0; i < 21; i += 1) {
      const r = await login(DEV, 'ratelimit@labcare-test.ci', 'Nimporte2026', '10.99.9.9');
      if (r.status === 429) { got429 = true; break; }
    }
    check('rate-limit login : 429 après 20 tentatives (même IP)', got429);

    // 17. En-têtes de sécurité (helmet + CSP).
    const home = await req(DEV, 'GET', '/');
    check('helmet : x-content-type-options nosniff', (home.headers.get('x-content-type-options') || '') === 'nosniff');
    check('helmet : CSP avec default-src \'self\'', (home.headers.get('content-security-policy') || '').includes("default-src 'self'"));
    check('helmet : x-frame-options présent', !!home.headers.get('x-frame-options'));

    // 18. Vérifications statiques du code.
    const serverSrc = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
    const dbSrc = fs.readFileSync(path.join(ROOT, 'db.js'), 'utf8');
    check('code : 2FA avec crypto.randomInt', serverSrc.includes('crypto.randomInt'));
    check('code : plus de Math.random côté serveur', !serverSrc.includes('Math.random'));
    check('code : save() atomique (.tmp + renameSync)', dbSrc.includes('.tmp') && dbSrc.includes('renameSync'));
    check('code : révocation des sessions après changement de mot de passe',
      serverSrc.includes('function revokeSessions') && (serverSrc.match(/revokeSessions\(/g) || []).length >= 4); // 1 définition + 3 appels (reset, change-password, reset Admin)
    check('code : jetons hachés (hashToken)', (serverSrc.match(/hashToken\(/g) || []).length >= 5);
    check('code : plus de 423 au login', !/res\.status\(423\)/.test(serverSrc));
    const appSrc = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');
    check('code : TEST_ACCOUNTS retiré du frontend', !appSrc.includes('Labcare2026'));
    check('code : seed conditionné (NODE_ENV production)', dbSrc.includes('if (!isProd) seed()'));

    // 19. Déconnexion → 401 (non-régression).
    const sec4 = await login(DEV, 'secretariat@labcare-test.ci', 'Labcare2026Secret');
    const lo = await req(DEV, 'POST', '/api/auth/logout', { cookie: sec4.cookie });
    const meAfterLo = await req(DEV, 'GET', '/api/auth/me', { cookie: sec4.cookie });
    check('déconnexion → 401', lo.status === 200 && meAfterLo.status === 401, `logout=${lo.status} me=${meAfterLo.status}`);

    // 20. Purge : sessions et codes expirés supprimés au (re)démarrage.
    await dev.stop();
    db = await openDb(devDir);
    const sess = dbGet(db, 'SELECT * FROM sessions LIMIT 1');
    if (sess) db.run("UPDATE sessions SET expires_at = ? WHERE id = ?", [Date.now() - 1000, sess.id]);
    db.run('INSERT INTO two_factor_codes (user_id, code_hash, expires_at, used) VALUES (?,?,?,0)', [1, 'x', Date.now() - 1000]);
    writeDb(db, devDir);
    const before = dbGet(db, 'SELECT COUNT(*) AS c FROM two_factor_codes WHERE expires_at < ?', [Date.now()]);
    db.close();
    check('purge : données expirées préparées', !!sess && before.c >= 1, `sessions=${!!sess} codes expirés=${before.c}`);
    dev = startServer({ port: PORT_DEV, dataDir: devDir, env: { NODE_ENV: 'development' } });
    if (!(await waitUp(DEV))) { console.log('  ✗ le serveur dev ne redémarre pas'); process.exitCode = 1; return; }
    db = await openDb(devDir);
    const sessAfter = sess ? dbGet(db, 'SELECT * FROM sessions WHERE id = ?', [sess.id]) : null;
    const codesAfter = dbGet(db, 'SELECT COUNT(*) AS c FROM two_factor_codes WHERE expires_at < ?', [Date.now()]);
    check('purge : session expirée supprimée au démarrage', !sessAfter);
    check('purge : codes 2FA expirés supprimés au démarrage', codesAfter.c === 0, `restants=${codesAfter.c}`);
    db.close();

    await dev.stop();
    dev = null;

    // ================= PRODUCTION =================
    console.log('\n== Production (NODE_ENV=production) ==');
    // 21. JWT_SECRET absent ou trop court → refus de démarrer.
    async function expectExit(env, label) {
      const s = startServer({ port: PORT_PROD, dataDir: mkTempDir('labcare-audit-prod-short-'), env });
      const t0 = Date.now();
      while (s.child.exitCode === null && Date.now() - t0 < 8000) await sleep(200);
      const exited = s.child.exitCode !== null && s.child.exitCode !== 0;
      if (s.child.exitCode === null) await s.stop();
      check(label, exited, `exitCode=${s.child.exitCode}`);
    }
    const envNoSecret = { NODE_ENV: 'production' };
    delete envNoSecret.JWT_SECRET;
    await expectExit(envNoSecret, 'prod sans JWT_SECRET → refus de démarrer');
    await expectExit({ NODE_ENV: 'production', JWT_SECRET: 'trop-court' }, 'prod JWT_SECRET < 32 caractères → refus de démarrer');

    // 22. Serveur prod : base vide, pas de seed, pas de comptes de test.
    prod = startServer({ port: PORT_PROD, dataDir: prodDir, env: { NODE_ENV: 'production', JWT_SECRET: LONG_SECRET } });
    const PROD = `http://127.0.0.1:${PORT_PROD}`;
    if (!(await waitUp(PROD))) { console.log('  ✗ le serveur prod ne démarre pas'); console.log(prod.getOutput()); process.exitCode = 1; return; }
    check('serveur prod démarre (JWT_SECRET long)', true);
    db = await openDb(prodDir);
    check('prod : 0 compte (pas de seed)', dbGet(db, 'SELECT COUNT(*) AS c FROM users').c === 0);
    check('prod : 0 dossier (pas de seed)', dbGet(db, 'SELECT COUNT(*) AS c FROM dossiers').c === 0);
    db.close();
    const taProd = await req(PROD, 'GET', '/api/test-accounts');
    check('prod : /api/test-accounts → 404', taProd.status === 404, `status=${taProd.status}`);
    const pmProd = await req(PROD, 'GET', '/api/public-meta');
    check('prod : public-meta showTestAccounts=false', pmProd.status === 200 && pmProd.json.showTestAccounts === false);
    const appJs = await req(PROD, 'GET', '/app.js');
    check('prod : app.js ne contient aucun mot de passe de test', appJs.status === 200 && !appJs.text.includes('Labcare2026'));
    const loginTestProd = await login(PROD, 'secretariat@labcare-test.ci', 'Labcare2026Secret');
    check('prod : compte de test rejeté', loginTestProd.status === 401, `status=${loginTestProd.status}`);
    const homeProd = await req(PROD, 'GET', '/');
    check('prod : en-têtes helmet présents', (homeProd.headers.get('x-content-type-options') || '') === 'nosniff' && !!(homeProd.headers.get('content-security-policy') || '').includes("default-src 'self'"));

    // 23. Setup : premier Admin, puis route fermée.
    const setup1 = await req(PROD, 'POST', '/api/setup', { body: { name: 'Admin Prod', email: 'admin-prod@labcare-test.ci', phone: '+225 00 00 00 00', password: 'AdminProd2026' } });
    check('prod : /api/setup crée le premier Admin', setup1.status === 201, `status=${setup1.status}`);
    const setup2 = await req(PROD, 'POST', '/api/setup', { body: { name: 'Admin 2', email: 'admin2-prod@labcare-test.ci', phone: '', password: 'AdminProd2026' } });
    check('prod : /api/setup refermé après le premier compte (404)', setup2.status === 404, `status=${setup2.status}`);

    // 24. Login Admin en prod : 2FA demandée, demoCode ABSENT.
    const admProd = await login(PROD, 'admin-prod@labcare-test.ci', 'AdminProd2026');
    check('prod : login Admin → needs2fa sans demoCode', admProd.json && admProd.json.needs2fa === true && !('demoCode' in admProd.json), `réponse=${JSON.stringify(admProd.json)}`);

    // 25. 2FA en prod : 5 échecs → code invalidé (vérifié en base).
    for (let i = 0; i < 5; i += 1) {
      await req(PROD, 'POST', '/api/auth/verify-2fa', { body: { email: 'admin-prod@labcare-test.ci', code: '000000' } });
    }
    db = await openDb(prodDir);
    const recProd = dbGet(db, 'SELECT * FROM two_factor_codes WHERE user_id = (SELECT id FROM users WHERE email = ?) ORDER BY id DESC LIMIT 1', ['admin-prod@labcare-test.ci']);
    check('prod : 2FA 5 échecs comptés, code invalidé', !!recProd && recProd.attempts === 5 && recProd.used === 1, `attempts=${recProd && recProd.attempts} used=${recProd && recProd.used}`);
    db.close();

    await prod.stop();
    prod = null;
  } finally {
    if (dev) await dev.stop().catch(() => {});
    if (prod) await prod.stop().catch(() => {});
  }

  console.log(`\nRésultat : ${passed} réussis, ${failed} échoués.`);
  if (failed > 0) {
    console.log('Échecs :');
    for (const f of failures) console.log(`  - ${f}`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('Erreur du script de test :', err);
  process.exitCode = 1;
});
