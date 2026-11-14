# Labcare V1 — application web (version autonome, déployable)

Suivi du parcours d'intervention, pour l'équipe Labcare uniquement.
Construite à partir du **PRD final Labcare** (11 novembre 2026, sans cotation).
**Données fictives de test uniquement — pas de vrais dossiers, pas de vrais patients.**

## Ce que fait l'application

- **Connexion** : e-mail et mot de passe. Aucun dossier n'est visible avant la connexion.
- **Tableau des dossiers** : tous les dossiers, regroupés par les 8 étapes du parcours
  (RDV pris → RDV confirmé → Accueilli → Prélevé → Envoyé au labo → Résultat reçu →
  Validé par le médecin → Remis au patient), avec les dossiers bloqués en premier.
- **Fiche dossier** : particulier (nom, téléphone, adresse) ou entreprise
  (nom, contact RH, formule, effectif prévu). **Aucun contenu médical, aucun résultat affiché.**
- **Chaque intervenant ne fait avancer que sa propre étape** : Secrétariat (étapes 1, 2, 8,
  et c'est lui seul qui crée un dossier), Préleveur (3, 4), Transport (5),
  Laboratoire (6), Médecin (7). L'Administrateur ne fait pas avancer les dossiers,
  sauf s'il cumule aussi un rôle d'intervenant.
- **Les 5 exceptions** : RDV annulé, patient absent, prélèvement impossible,
  échantillon à refaire, résultat en retard. Un dossier en exception reste visible,
  en haut du tableau, jusqu'à sa reprise ou sa clôture. Les suites appliquées sont
  celles proposées dans le PRD §8.1 (proposition à valider, pas encore décidée).
- **Notification** à chaque changement de statut, aux utilisateurs actifs dont le rôle
  correspond à l'étape suivante.
- **Historique complet** : qui a changé le statut, et quand. Il ne peut être modifié
  par aucun utilisateur.
- **Écran « Utilisateurs » (Administrateur)** : créer des comptes par invitation
  uniquement (pas d'inscription libre), choisir un ou plusieurs rôles, modifier,
  désactiver (jamais supprimer), déverrouiller, journal des connexions.

## Règles d'authentification (PRD §5)

- Mot de passe : 10 caractères minimum, lettres et chiffres, stocké haché (bcrypt).
- Après 5 échecs consécutifs, le compte est verrouillé 15 minutes ;
  l'Administrateur peut le déverrouiller avant. La réponse reste la même
  erreur générique (« E-mail ou mot de passe incorrect ») : elle ne révèle
  jamais si le compte existe ou s'il est verrouillé.
- Après un changement de mot de passe, toutes les sessions du compte sont
  révoquées : il faut se reconnecter avec le nouveau mot de passe.
- Les jetons d'activation et de réinitialisation sont stockés hachés en base,
  jamais en clair.
- Limitation de débit sur la connexion, le mot de passe oublié et la double
  authentification, et en-têtes de sécurité (helmet + politique CSP).
- Double authentification obligatoire pour l'Administrateur et le Médecin.
  Le code à 6 chiffres est généré de façon sécurisée, vaut 10 minutes et est
  invalidé après 5 essais ratés. **Version de test : pas d'envoi par SMS ni par
  application — le code à usage unique s'affiche dans l'application pour simuler
  l'envoi. En production, le code n'est jamais renvoyé par le serveur : il part
  par application d'authentification ou par SMS.**
- Lien d'activation par e-mail valable 48 h ; lien de réinitialisation valable 1 h,
  utilisable une seule fois. **Version de test : pas d'envoi d'e-mail — les liens
  d'activation et de réinitialisation déclenchée par l'Admin s'affichent à
  l'Administrateur (simulation).** En revanche, « Mot de passe oublié » ne renvoie
  jamais le lien : la réponse est identique que l'adresse existe ou non, pour ne
  jamais révéler si une adresse existe. Le message d'erreur ne révèle jamais
  si une adresse e-mail existe. L'Admin peut déclencher une réinitialisation
  pour un compte déjà activé, depuis l'écran « Utilisateurs ».
- Session : déconnexion après 30 minutes d'inactivité sur ordinateur,
  7 jours sur mobile. Il y a un seul Administrateur.

## Journal du serveur (logs)

Le serveur écrit un journal dans des fichiers, en plus de l'historique
dans l'application.

- **Où sont les logs ?** Dans le dossier `logs/` à côté de `server.js`,
  un fichier par jour : `logs/app-AAAA-MM-JJ.log` (par exemple
  `logs/app-2026-11-13.log`). Chaque ligne est un événement au format JSON :
  la date, le niveau (info, avertissement ou erreur), le code de l'événement
  (par exemple `login_success`, `dossier_advanced`, `api_error`) et un message
  court en français.
- **Combien de temps sont-ils gardés ?** 30 jours. Les fichiers de plus de
  30 jours sont supprimés automatiquement au démarrage du serveur.
- **Ce qu'on y trouve :** les connexions réussies et échouées, la double
  authentification, les verrouillages et déverrouillages de compte, les
  changements et réinitialisations de mot de passe, la création et la
  modification des comptes, l'avancement des dossiers, les exceptions,
  les reprises et les clôtures, et les erreurs du serveur.
- **Ce qu'on n'y trouve jamais :** aucun mot de passe, aucun code de double
  authentification, aucun jeton (de session, d'activation ou de
  réinitialisation), et aucune donnée patient (nom, téléphone, adresse).
  Seul le code interne du dossier (par exemple `LAB-2026-0142`) y apparaît.
- **Ce journal ne remplace rien :** l'historique complet des dossiers
  (qui a changé le statut, et quand) et le journal des connexions
  consultable par l'Administrateur (table `auth_logs` dans la base)
  restent en place, comme avant.

## Technique

- Un seul service Node.js (Express) qui sert le frontend et l'API.
- Base de données **SQLite** (via `sql.js`, SQLite compilé en WebAssembly —
  aucune compilation native, fonctionne sur Node 20 comme sur Node 24).
- Aucune étape de build pour le frontend (HTML, CSS et JavaScript simples).
- **Une seule instance à la fois.** La base SQLite est un fichier écrit par
  un seul processus : il ne faut jamais lancer deux serveurs sur la même base
  (par exemple deux instances Render), sinon des écritures sont perdues.

## Lancer en local

```bash
npm install
npm start
```

Puis ouvrir http://localhost:3000 — la base de données se crée dans `data/labcare.db`
avec les comptes et dossiers de test.

## Secrets et variables d'environnement

Certains réglages du serveur sont des **secrets** : ils ne doivent jamais être
écrits dans le code ni envoyés sur GitHub. Ils se règlent avec des
**variables d'environnement** (des réglages que le serveur lit au démarrage).

**En local (sur votre ordinateur) :**

1. Copiez le fichier d'exemple : `cp .env.example .env`
   (ou copiez-collez le fichier dans l'explorateur et renommez la copie `.env`).
2. Ouvrez le fichier `.env` et remplacez les valeurs d'exemple par les vraies.
3. Le fichier `.env` reste sur votre ordinateur : il est dans `.gitignore`,
   donc il n'est jamais envoyé sur GitHub. **Ne l'envoyez jamais par e-mail
   ni par message, et ne le partagez pas.**

**La variable la plus importante : `JWT_SECRET`.** C'est le secret qui signe
les jetons de connexion. En production, il doit être **long (au moins
32 caractères) et aléatoire** — par exemple une suite de lettres et de chiffres
tirée au hasard, impossible à deviner. Sans `JWT_SECRET`, ou avec un secret
de moins de 32 caractères, le serveur refuse de démarrer en production.
En développement seulement, un secret temporaire est généré automatiquement
si la variable est absente.

**Sur Render (au déploiement) :** les variables ne se mettent pas dans un
fichier `.env`, mais dans le tableau de bord Render (onglet Environment du
service). Il faudra y déclarer `JWT_SECRET` avec une valeur longue et
aléatoire, et `NODE_ENV=production`. Le fichier `render.yaml` demande
`JWT_SECRET` avec `sync: false` : Render ne le remplit pas tout seul, il
faut le saisir à la main dans le tableau de bord.

**Les comptes de test ne sont pas des secrets de production.** Les 7 comptes
de test (voir la liste plus bas, sans les mots de passe) sont des **données
fictives** : ils sont créés uniquement en développement (`NODE_ENV` différent
de `production`). En production, la base démarre vide et aucun compte de test
n'est jamais créé. Les mots de passe de test ne figurent nulle part dans ce
document : ils sont dans le code de développement uniquement, et la page de
connexion ne les affiche qu'en développement. Sur le serveur des vrais
dossiers, chaque membre de l'équipe aura son propre compte, créé par
invitation, avec son propre mot de passe qu'il choisit lui-même.

### Premier compte en production

En production, la base démarre vide : aucun compte de test n'est créé. Pour
créer le premier Administrateur, appelez une seule fois `POST /api/setup`
avec le nom, l'e-mail, le téléphone et le mot de passe du premier Admin.
La route ne fonctionne que tant qu'aucun compte n'existe : après la création
du premier compte, elle répond 404. Ensuite, cet Admin crée les autres
comptes par invitation depuis l'écran « Utilisateurs ».

## Sauvegardes

La base de données est le fichier `data/labcare.db`. Elle contient tous les
comptes et tous les dossiers. Si ce fichier est perdu, tout est perdu.
Faites une sauvegarde régulièrement, surtout avant une mise à jour ou un
déploiement.

### Faire une sauvegarde

Dans le dossier du projet, lancez :

```bash
npm run backup
```

(ou directement : `node scripts/backup.js`)

Le script copie `data/labcare.db` dans le dossier `backups/`, avec un nom
horodaté, par exemple `backups/labcare-2026-11-13_12-53-18.db`.
Il vérifie ensuite que la copie n'est pas vide et qu'elle s'ouvre bien
(nombre de dossiers et de comptes affichés), puis il affiche un message
de succès avec le chemin et la taille du fichier. En cas de problème
(base introuvable, copie impossible ou illisible), il affiche la raison
et ne laisse pas de copie incomplète.

Les sauvegardes de plus de **7 jours sont supprimées automatiquement**
à chaque lancement du script. Le script ne modifie jamais `data/labcare.db`
et ne démarre pas le serveur.

### Restaurer une sauvegarde

1. **Arrêtez le serveur** s'il tourne (Ctrl+C dans le terminal).
2. **Copiez la sauvegarde choisie** vers `data/labcare.db`, par exemple :
   ```bash
   cp backups/labcare-2026-11-13_12-53-18.db data/labcare.db
   ```
   Choisissez la sauvegarde par sa date dans le nom du fichier.
   Gardez une copie de l'ancien `data/labcare.db` si vous voulez pouvoir
   revenir en arrière.
3. **Redémarrez le serveur** : `npm start`.
4. **Vérifiez** : connectez-vous avec le compte Secrétariat et contrôlez
   que les dossiers sont bien là (en test : 11 dossiers, dont 2 bloqués,
   et 7 comptes).

### ⚠️ Attention — Render gratuit : le disque est éphémère

Sur le plan gratuit de Render, le dossier `backups/` est sur le disque du
service, comme la base elle-même : **il disparaît si le service est
redéployé ou redémarré**. Une sauvegarde qui reste seulement sur le serveur
ne protège donc de rien.

**Après chaque sauvegarde, copiez le fichier hors du serveur**
(par exemple, téléchargez-le sur votre ordinateur et gardez-le dans le
dossier du projet Labcare). Sans cette copie hors serveur, la sauvegarde
est perdue en même temps que la base.

## Déployer gratuitement sur Render

Hervé a déjà un compte Render gratuit et un compte GitHub. Étapes :

1. **Mettre ce code dans un dépôt GitHub** : nouveau dépôt public ou privé nommé
   **`labcare-v1`** sur le compte GitHub de Hervé (**bonididier1988-collab**),
   soit `github.com/bonididier1988-collab/labcare-v1`.
   Ne pas mettre le dossier `node_modules/` ni `data/` (ils sont dans `.gitignore`).
2. **Sur Render** : New → Web Service → choisir le dépôt GitHub.
   Render détecte Node.js. Le fichier `render.yaml` choisit déjà le plan **Free** :
   `buildCommand: npm install`, `startCommand: npm start`.
   Déclarez `JWT_SECRET` dans le tableau de bord Render (onglet Environment) :
   `render.yaml` le demande avec `sync: false`, il faut donc le saisir à la
   main, avec au moins 32 caractères aléatoires.
3. Cliquer sur **Create Web Service**. La première mise en ligne prend quelques minutes.
4. L'adresse gratuite sera du type `https://labcare-v1.onrender.com`
   (un sous-domaine gratuit de Render, pas un domaine .com — voir ci-dessous).

## Limites du plan gratuit de Render — à connaître

- **Le service s'endort après 15 minutes sans visite.** La première ouverture
  prend alors environ 1 minute (le service se réveille). C'est normal sur le plan gratuit.
- **La base de données SQLite vit sur le disque du service.** Sur le plan gratuit,
  ce disque est éphémère : la base peut être réinitialisée au redéploiement ou au
  redémarrage. Les dossiers créés pendant le test peuvent donc disparaître.
  Le fichier `render.yaml` déclare un disque persistant et `DATA_DIR`, mais les
  disques persistants ne sont pas disponibles sur le plan gratuit : il faut une
  instance payante (Starter) pour qu'ils soient pris en compte.
  **Cette version sert à voir et à tester comment l'application fonctionne.
  Elle n'est pas faite pour les vrais dossiers.** Pour les vrais dossiers, il faudra
  une base de données persistante (ou le VPS Hostinger prévu dans le PRD).
- **Adresse gratuite = sous-domaine Render** (`*.onrender.com`). Un vrai domaine
  (.com, .ci) n'est pas gratuit : il faut l'acheter à part. Depuis Freenom (fermé
  en 2023-2024), il n'existe plus de vrai domaine gratuit.
- **HTTPS** (le cadenas) est inclus gratuitement par Render.

## Comptes de test (données fictives — développement uniquement)

| Personne (fictive) | E-mail | Rôle(s) |
|---|---|---|
| Secrétariat Labcare | secretariat@labcare-test.ci | Secrétariat / Accueil |
| Awa Diallo | preleveuse@labcare-test.ci | Préleveur |
| Jean Dupont | transport@labcare-test.ci | Préleveur + Transport |
| Marie Koné | labo@labcare-test.ci | Laboratoire |
| Dr Aya Kouassi | medecin@labcare-test.ci | Médecin (2FA) |
| Hervé Admin | admin@labcare-test.ci | Administrateur (2FA) |
| Paul N'Guessan | preleveur2@labcare-test.ci | Préleveur |

Les mots de passe de test ne sont pas écrits dans ce document : ils sont dans
le code de développement uniquement. En développement, ces comptes sont aussi
affichés sur l'écran de connexion (bouton « Remplir »), avec leurs mots de
passe — la page de connexion les demande au serveur, qui ne les expose
jamais en production.
Pour les comptes Admin et Médecin, le code de double authentification s'affiche
dans l'application (simulation d'envoi) en développement uniquement.

**11 dossiers fictifs** sont déjà créés, dont **2 bloqués** :
LAB-2026-0138 (patient absent à domicile) et LAB-2026-0145 (échantillon à refaire).

## Test rapide (5 minutes)

1. Se connecter avec le compte Secrétariat.
2. Voir les dossiers groupés par étape, avec les 2 bloqués en premier.
3. Ouvrir un dossier et revenir à la liste.
4. Faire avancer un dossier à l'étape 1 (RDV pris → RDV confirmé).
5. Se connecter avec le compte Médecin et constater qu'il ne peut pas valider
   l'étape du Secrétariat.
6. Se connecter avec le compte Admin et ouvrir l'écran « Utilisateurs ».

## Points encore ouverts (PRD §13)

Ces points ne sont pas décidés dans le PRD. Ils sont appliqués ici comme proposé
dans le PRD quand une proposition existe, et restent à valider par Hervé :

- Canal d'invitation et de réinitialisation : e-mail seul, ou aussi SMS / WhatsApp ?
- Double authentification : par application ou par SMS ?
- Qui est l'Administrateur ? Un seul Administrateur (décidé par Hervé le 14 novembre 2026 ; le serveur refuse d'en créer un deuxième).
- Sessions sur mobile : téléphone personnel ou professionnel ?
- Cumul de rôles en pratique.
- Suites des exceptions (§8.1) : appliquées comme proposé, à valider.
- Les 8 groupes restent-ils affichés même vides ? (Ici : oui, comme dans les maquettes.)
- Faut-il une confirmation avant de notifier l'intervenant suivant ?
  (Ici : le passage est immédiat, avec notification.)

## Hors périmètre V1

Aucun accès patient, aucune réservation en ligne, aucun paiement, aucun affichage
de résultat médical, aucune gestion des campagnes de prévention, aucune connexion
Google ou Microsoft.
