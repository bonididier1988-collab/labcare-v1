// Labcare V1 — base de données SQLite (sql.js, SQLite compilé en WebAssembly).
// Aucune compilation native : fonctionne sur Node 20 comme sur Node 24, et sur Render.
// La base est gardée en mémoire et sauvegardée dans un fichier après chaque écriture.
// Sur le plan gratuit de Render, le disque est éphémère : la base peut être
// réinitialisée au redéploiement. Version de test uniquement, pas de vrais dossiers.
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { isProd } = require('./lib/config');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'labcare.db');

let SQL = null;
let db = null;

function save() {
  if (!db) return;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const data = db.export();
  // Écriture atomique : on écrit d'abord dans un fichier temporaire, puis on
  // renomme vers le fichier final. Un arrêt en plein milieu d'une écriture
  // ne corrompt jamais la base (le fichier final est remplacé d'un coup).
  const tmpPath = DB_PATH + '.tmp';
  fs.writeFileSync(tmpPath, Buffer.from(data));
  fs.renameSync(tmpPath, DB_PATH);
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function get(sql, params = []) {
  const rows = all(sql, params);
  return rows[0] || null;
}

function run(sql, params = []) {
  db.run(sql, params);
  const row = get('SELECT last_insert_rowid() AS id');
  const changes = db.getRowsModified();
  save();
  return { id: row ? row.id : null, changes };
}

function exec(sql) {
  db.exec(sql);
  save();
}

function parseRoles(user) {
  if (!user) return null;
  return { ...user, roles: JSON.parse(user.roles || '[]') };
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  roles TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  password_hash TEXT,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  activation_token TEXT,
  activation_expires INTEGER,
  reset_token TEXT,
  reset_expires INTEGER,
  last_login INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE,
  is_mobile INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS two_factor_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dossiers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  rdv_date TEXT NOT NULL,
  rdv_time TEXT,
  step INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'open',
  exception TEXT,
  blocked INTEGER NOT NULL DEFAULT 0,
  client_name TEXT,
  phone TEXT,
  contact TEXT,
  address TEXT,
  company_name TEXT,
  hr_contact TEXT,
  formula TEXT,
  effectif INTEGER,
  assigned_to INTEGER REFERENCES users(id),
  created_by INTEGER REFERENCES users(id),
  created_at INTEGER NOT NULL,
  closed_at INTEGER,
  close_reason TEXT
);
CREATE TABLE IF NOT EXISTS dossier_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dossier_id INTEGER NOT NULL REFERENCES dossiers(id),
  user_id INTEGER REFERENCES users(id),
  user_name TEXT,
  action TEXT NOT NULL,
  from_step INTEGER,
  to_step INTEGER,
  exception TEXT,
  note TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  dossier_id INTEGER REFERENCES dossiers(id),
  message TEXT NOT NULL,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  event TEXT NOT NULL,
  success INTEGER NOT NULL,
  detail TEXT,
  created_at INTEGER NOT NULL
);
`;

// --- Données fictives de test (aucun vrai patient) ---
const SEED_USERS = [
  { name: 'Secrétariat Labcare', email: 'secretariat@labcare-test.ci', phone: '+225 01 00 00 01', roles: ['secretariat'], password: 'Labcare2026Secret' },
  { name: 'Awa Diallo', email: 'preleveuse@labcare-test.ci', phone: '+225 01 00 00 02', roles: ['preleveur'], password: 'Labcare2026Prelev' },
  { name: 'Jean Dupont', email: 'transport@labcare-test.ci', phone: '+225 01 00 00 03', roles: ['preleveur', 'transport'], password: 'Labcare2026Transp' },
  { name: 'Marie Koné', email: 'labo@labcare-test.ci', phone: '+225 01 00 00 04', roles: ['laboratoire'], password: 'Labcare2026Labo12' },
  { name: 'Dr Aya Kouassi', email: 'medecin@labcare-test.ci', phone: '+225 01 00 00 05', roles: ['medecin'], password: 'Labcare2026Medecin' },
  { name: 'Hervé Admin', email: 'admin@labcare-test.ci', phone: '+225 01 00 00 06', roles: ['admin'], password: 'Labcare2026Admin1' },
  { name: "Paul N'Guessan", email: 'preleveur2@labcare-test.ci', phone: '+225 01 00 00 08', roles: ['preleveur'], password: 'Labcare2026Prelev2' },
];

function seed() {
  const count = get('SELECT COUNT(*) AS c FROM users').c;
  if (count > 0) return;
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  const d = (offset) => new Date(now + offset * day).toISOString().slice(0, 10);

  const userIds = {};
  for (const u of SEED_USERS) {
    const r = run(
      'INSERT INTO users (name, email, phone, roles, status, password_hash, created_at) VALUES (?,?,?,?,?,?,?)',
      [u.name, u.email, u.phone, JSON.stringify(u.roles), 'active', bcrypt.hashSync(u.password, 10), now]
    );
    userIds[u.email] = r.id;
  }
  const sec = userIds['secretariat@labcare-test.ci'];
  const pre1 = userIds['preleveuse@labcare-test.ci'];
  const trs = userIds['transport@labcare-test.ci'];
  const lab = userIds['labo@labcare-test.ci'];
  const med = userIds['medecin@labcare-test.ci'];

  // 11 dossiers fictifs, dont 2 bloqués.
  const dossiers = [
    { code: 'LAB-2026-0142', type: 'particulier', rdv: d(0), time: '09:30', step: 4, client: 'Aminata Diallo', phone: '+225 07 11 11 11', contact: '+225 07 11 11 11', address: '12 rue Fictive, Abidjan', assigned: pre1 },
    { code: 'LAB-2026-0138', type: 'particulier', rdv: d(-1), time: '08:00', step: 3, client: 'Kouassi Yao', phone: '+225 07 22 22 22', contact: '+225 07 22 22 22', address: '5 avenue Exemple, Abidjan', assigned: pre1, exception: 'absent' },
    { code: 'LAB-2026-0145', type: 'entreprise', rdv: d(-2), time: '10:00', step: 5, company: 'Société Exemple SARL', hr: 'rh@exemple-test.ci', formula: 'Standard', effectif: 25, assigned: lab, exception: 'echantillon' },
    { code: 'LAB-2026-0151', type: 'particulier', rdv: d(1), time: '09:00', step: 1, client: 'Mariam Koné', phone: '+225 07 33 33 33', contact: '+225 07 33 33 33', address: '8 impasse Démo, Abidjan', assigned: sec },
    { code: 'LAB-2026-0152', type: 'entreprise', rdv: d(1), time: '11:00', step: 1, company: 'Groupe Fictif SA', hr: 'contact@fictif-test.ci', formula: 'Premium', effectif: 40, assigned: sec },
    { code: 'LAB-2026-0149', type: 'particulier', rdv: d(0), time: '14:00', step: 2, client: 'Jean-Marc Bamba', phone: '+225 07 44 44 44', contact: '+225 07 44 44 44', address: '21 boulevard Test, Abidjan', assigned: sec },
    { code: 'LAB-2026-0147', type: 'particulier', rdv: d(0), time: '08:30', step: 3, client: "Sophie N'Guessan", phone: '+225 07 55 55 55', contact: '+225 07 55 55 55', address: '3 rue des Exemples, Abidjan', assigned: pre1 },
    { code: 'LAB-2026-0155', type: 'entreprise', rdv: d(-1), time: '09:00', step: 5, company: 'Entreprise Démo CI', hr: 'rh@demo-test.ci', formula: 'Standard', effectif: 12, assigned: trs },
    { code: 'LAB-2026-0157', type: 'particulier', rdv: d(-2), time: '10:30', step: 6, client: 'Ibrahim Touré', phone: '+225 07 66 66 66', contact: '+225 07 66 66 66', address: '17 rue Fictive, Abidjan', assigned: lab },
    { code: 'LAB-2026-0159', type: 'entreprise', rdv: d(-3), time: '09:00', step: 7, company: 'Compagnie Test SARL', hr: 'rh@test-test.ci', formula: 'Essentiel', effectif: 8, assigned: med },
    { code: 'LAB-2026-0161', type: 'particulier', rdv: d(-3), time: '15:00', step: 8, client: 'Aya Koffi', phone: '+225 07 77 77 77', contact: '+225 07 77 77 77', address: '9 avenue Démo, Abidjan', assigned: sec },
  ];

  const names = {
    [sec]: 'Secrétariat Labcare',
    [pre1]: 'Awa Diallo',
    [trs]: 'Jean Dupont',
    [lab]: 'Marie Koné',
    [med]: 'Dr Aya Kouassi',
  };
  const stepUser = { 1: sec, 2: sec, 3: pre1, 4: pre1, 5: trs, 6: lab, 7: med, 8: sec };
  const stepLabels = { 1: 'RDV pris', 2: 'RDV confirmé', 3: 'Accueilli', 4: 'Prélevé', 5: 'Envoyé au labo', 6: 'Résultat reçu', 7: 'Validé par le médecin', 8: 'Remis au patient' };

  for (const dos of dossiers) {
    const blocked = dos.exception ? 1 : 0;
    const r = run(
      `INSERT INTO dossiers (code, type, rdv_date, rdv_time, step, status, exception, blocked,
        client_name, phone, contact, address, company_name, hr_contact, formula, effectif,
        assigned_to, created_by, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [dos.code, dos.type, dos.rdv, dos.time, dos.step, 'open', dos.exception || null, blocked,
        dos.client || null, dos.phone || null, dos.contact || null, dos.address || null,
        dos.company || null, dos.hr || null, dos.formula || null, dos.effectif || null,
        dos.assigned, sec, now - 3 * day]
    );
    const id = r.id;
    // Historique : création puis chaque étape atteinte.
    run(
      'INSERT INTO dossier_history (dossier_id, user_id, user_name, action, from_step, to_step, created_at) VALUES (?,?,?,?,?,?,?)',
      [id, sec, names[sec], 'create', null, 1, now - 3 * day]
    );
    for (let s = 2; s <= dos.step; s++) {
      run(
        'INSERT INTO dossier_history (dossier_id, user_id, user_name, action, from_step, to_step, created_at) VALUES (?,?,?,?,?,?,?)',
        [id, stepUser[s], names[stepUser[s]], 'advance', s - 1, s, now - (3 - s * 0.3) * day]
      );
    }
    if (dos.exception === 'absent') {
      run(
        'INSERT INTO dossier_history (dossier_id, user_id, user_name, action, from_step, to_step, exception, note, created_at) VALUES (?,?,?,?,?,?,?,?,?)',
        [id, pre1, names[pre1], 'exception', 3, 3, 'absent', 'Patient absent à domicile à l’arrivée du préleveur.', now - 1 * day]
      );
    }
    if (dos.exception === 'echantillon') {
      run(
        'INSERT INTO dossier_history (dossier_id, user_id, user_name, action, from_step, to_step, exception, note, created_at) VALUES (?,?,?,?,?,?,?,?,?)',
        [id, lab, names[lab], 'exception', 5, 5, 'echantillon', 'Échantillon non conforme, à refaire.', now - 1 * day]
      );
    }
  }
}

async function init() {
  const initSqlJs = require('sql.js');
  SQL = await initSqlJs({
    locateFile: (file) => path.join(__dirname, 'node_modules', 'sql.js', 'dist', file),
  });
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(new Uint8Array(buf));
  } else {
    db = new SQL.Database();
  }
  db.exec(SCHEMA);
  // Migration des bases créées avant l'audit de sécurité : ajoute la
  // colonne `attempts` à two_factor_codes si elle manque (CREATE TABLE IF
  // NOT EXISTS ne modifie pas une table déjà créée).
  const tfCols = all('PRAGMA table_info(two_factor_codes)').map((c) => c.name);
  if (!tfCols.includes('attempts')) {
    db.exec('ALTER TABLE two_factor_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0');
  }
  // Comptes de test : DÉVELOPPEMENT UNIQUEMENT. En production, la base
  // démarre vide — aucun compte test n'est jamais créé. Le premier
  // Administrateur est créé par la route /api/setup (voir server.js),
  // utilisable uniquement tant qu'aucun compte n'existe.
  if (!isProd) seed();
  save();
  return { all, get, run, exec, save, parseRoles };
}

module.exports = { init };
