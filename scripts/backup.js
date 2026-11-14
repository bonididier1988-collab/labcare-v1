// Labcare V1 — script de sauvegarde manuelle de la base de données.
//
// Usage :  node scripts/backup.js
//          (ou : npm run backup, une fois le script ajouté dans package.json)
//
// Ce que fait le script :
//   1. Copie data/labcare.db vers backups/labcare-AAAA-MM-JJ_HH-MM-SS.db.
//   2. Vérifie la copie : taille > 0, puis ouverture en lecture seule avec
//      comptage des dossiers et des utilisateurs.
//   3. Supprime automatiquement les sauvegardes de plus de 7 jours.
//   4. Ne touche jamais à data/labcare.db (lecture seule) et ne démarre
//      jamais le serveur.
//
// Chemins : même règle que db.js — la variable d'environnement DATA_DIR
// choisit le dossier de la base, sinon c'est data/ à la racine du projet.
// Le dossier backups/ est créé automatiquement s'il est absent.
//
// Données fictives de test uniquement — pas de vrais dossiers.

const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..');
const DATA_DIR = process.env.DATA_DIR || path.join(PROJECT_ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'labcare.db');
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(PROJECT_ROOT, 'backups');
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 jours

function horodatage(date) {
  const p = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())}_` +
    `${p(date.getHours())}-${p(date.getMinutes())}-${p(date.getSeconds())}`;
}

function compterLignes(db, table) {
  const stmt = db.prepare(`SELECT COUNT(*) AS c FROM ${table}`);
  stmt.step();
  const row = stmt.getAsObject();
  stmt.free();
  return row.c;
}

async function verifierCopie(cheminCopie) {
  // Ouvre la copie en lecture (en mémoire) et compte dossiers et utilisateurs.
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs({
    locateFile: (file) => path.join(PROJECT_ROOT, 'node_modules', 'sql.js', 'dist', file),
  });
  const buf = fs.readFileSync(cheminCopie);
  const copie = new SQL.Database(new Uint8Array(buf));
  try {
    const dossiers = compterLignes(copie, 'dossiers');
    const utilisateurs = compterLignes(copie, 'users');
    return { dossiers, utilisateurs };
  } finally {
    copie.close();
  }
}

function nettoyerAnciennesSauvegardes() {
  const maintenant = Date.now();
  let supprimees = 0;
  if (!fs.existsSync(BACKUP_DIR)) return 0;
  for (const nom of fs.readdirSync(BACKUP_DIR)) {
    if (!/^labcare-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.db$/.test(nom)) continue;
    const chemin = path.join(BACKUP_DIR, nom);
    const stat = fs.statSync(chemin);
    if (maintenant - stat.mtimeMs > RETENTION_MS) {
      fs.unlinkSync(chemin);
      console.log(`Ancienne sauvegarde supprimée (plus de 7 jours) : ${nom}`);
      supprimees += 1;
    }
  }
  return supprimees;
}

async function main() {
  // 1. La base source doit exister. On ne la modifie jamais : lecture seule.
  if (!fs.existsSync(DB_PATH)) {
    console.error(`Échec de la sauvegarde : la base est introuvable (${DB_PATH}).`);
    console.error('Démarrez d’abord le serveur une fois (npm start) pour créer la base avec les données de test.');
    process.exit(1);
  }

  fs.mkdirSync(BACKUP_DIR, { recursive: true });

  const nom = `labcare-${horodatage(new Date())}.db`;
  const destination = path.join(BACKUP_DIR, nom);

  // 2. Copie (jamais d'écrasement de data/labcare.db : on écrit seulement dans backups/).
  try {
    fs.copyFileSync(DB_PATH, destination, fs.constants.COPYFILE_EXCL);
  } catch (err) {
    console.error(`Échec de la sauvegarde : impossible de copier la base vers ${destination} (${err.message}).`);
    process.exit(1);
  }

  // 3. Vérification : la copie ne doit pas être vide, et elle doit s'ouvrir.
  const taille = fs.statSync(destination).size;
  if (taille <= 0) {
    fs.unlinkSync(destination);
    console.error('Échec de la sauvegarde : la copie créée est vide, elle a été supprimée.');
    process.exit(1);
  }
  let contenu;
  try {
    contenu = await verifierCopie(destination);
  } catch (err) {
    fs.unlinkSync(destination);
    console.error(`Échec de la sauvegarde : la copie ne s'ouvre pas ou est illisible (${err.message}). La copie a été supprimée.`);
    process.exit(1);
  }

  // 4. Nettoyage : sauvegardes de plus de 7 jours supprimées.
  const supprimees = nettoyerAnciennesSauvegardes();

  console.log('Sauvegarde réussie !');
  console.log(`  Fichier : ${destination}`);
  console.log(`  Taille : ${taille} octets`);
  console.log(`  Contenu vérifié : ${contenu.dossiers} dossier(s), ${contenu.utilisateurs} compte(s) utilisateur(s)`);
  if (supprimees > 0) {
    console.log(`  Nettoyage : ${supprimees} ancienne(s) sauvegarde(s) de plus de 7 jours supprimée(s).`);
  } else {
    console.log('  Nettoyage : aucune sauvegarde de plus de 7 jours à supprimer.');
  }
  console.log('  Rappel : sur Render gratuit, le disque est éphémère — copiez cette sauvegarde hors du serveur (téléchargez-la), sinon elle disparaît avec le service.');
}

main().catch((err) => {
  console.error(`Échec de la sauvegarde : ${err.message}`);
  process.exit(1);
});
