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
  l'Administrateur peut le déverrouiller avant.
- Double authentification obligatoire pour l'Administrateur et le Médecin.
  **Version de test : pas d'envoi par SMS ni par application — le code à usage unique
  s'affiche dans l'application pour simuler l'envoi.**
- Lien d'activation par e-mail valable 48 h ; lien de réinitialisation valable 1 h,
  utilisable une seule fois. **Version de test : pas d'envoi d'e-mail — les liens
  s'affichent dans l'application (simulation).** Le message d'erreur ne révèle jamais
  si une adresse e-mail existe.
- Session : déconnexion après 30 minutes d'inactivité sur ordinateur,
  7 jours sur mobile. Il doit rester au moins 2 Administrateurs actifs.

## Technique

- Un seul service Node.js (Express) qui sert le frontend et l'API.
- Base de données **SQLite** (via `sql.js`, SQLite compilé en WebAssembly —
  aucune compilation native, fonctionne sur Node 20 comme sur Node 24).
- Aucune étape de build pour le frontend (HTML, CSS et JavaScript simples).

## Lancer en local

```bash
npm install
npm start
```

Puis ouvrir http://localhost:3000 — la base de données se crée dans `data/labcare.db`
avec les comptes et dossiers de test.

## Déployer gratuitement sur Render

Hervé a déjà un compte Render gratuit et un compte GitHub. Étapes :

1. **Mettre ce code dans un dépôt GitHub** : nouveau dépôt public ou privé nommé
   **`labcare-v1`** sur le compte GitHub de Hervé (**bonididier1988-collab**),
   soit `github.com/bonididier1988-collab/labcare-v1`.
   Ne pas mettre le dossier `node_modules/` ni `data/` (ils sont dans `.gitignore`).
2. **Sur Render** : New → Web Service → choisir le dépôt GitHub.
   Render détecte Node.js. Le fichier `render.yaml` choisit déjà le plan **Free** :
   `buildCommand: npm install`, `startCommand: npm start`.
3. Cliquer sur **Create Web Service**. La première mise en ligne prend quelques minutes.
4. L'adresse gratuite sera du type `https://labcare-v1.onrender.com`
   (un sous-domaine gratuit de Render, pas un domaine .com — voir ci-dessous).

## Limites du plan gratuit de Render — à connaître

- **Le service s'endort après 15 minutes sans visite.** La première ouverture
  prend alors environ 1 minute (le service se réveille). C'est normal sur le plan gratuit.
- **La base de données SQLite vit sur le disque du service.** Sur le plan gratuit,
  ce disque est éphémère : la base peut être réinitialisée au redéploiement ou au
  redémarrage. Les dossiers créés pendant le test peuvent donc disparaître.
  **Cette version sert à voir et à tester comment l'application fonctionne.
  Elle n'est pas faite pour les vrais dossiers.** Pour les vrais dossiers, il faudra
  une base de données persistante (ou le VPS Hostinger prévu dans le PRD).
- **Adresse gratuite = sous-domaine Render** (`*.onrender.com`). Un vrai domaine
  (.com, .ci) n'est pas gratuit : il faut l'acheter à part. Depuis Freenom (fermé
  en 2023-2024), il n'existe plus de vrai domaine gratuit.
- **HTTPS** (le cadenas) est inclus gratuitement par Render.

## Comptes de test (données fictives)

| Personne (fictive) | E-mail | Mot de passe | Rôle(s) |
|---|---|---|---|
| Secrétariat Labcare | secretariat@labcare-test.ci | Labcare2026Secret | Secrétariat / Accueil |
| Awa Diallo | preleveuse@labcare-test.ci | Labcare2026Prelev | Préleveur |
| Jean Dupont | transport@labcare-test.ci | Labcare2026Transp | Préleveur + Transport |
| Marie Koné | labo@labcare-test.ci | Labcare2026Labo12 | Laboratoire |
| Dr Aya Kouassi | medecin@labcare-test.ci | Labcare2026Medecin | Médecin (2FA) |
| Hervé Admin | admin@labcare-test.ci | Labcare2026Admin1 | Administrateur (2FA) |
| Fatou Traoré | admin2@labcare-test.ci | Labcare2026Admin2 | Administrateur + Secrétariat (2FA) |
| Paul N'Guessan | preleveur2@labcare-test.ci | Labcare2026Prelev2 | Préleveur |

Ces comptes sont aussi affichés sur l'écran de connexion (bouton « Remplir »).
Pour les comptes Admin et Médecin, le code de double authentification s'affiche
dans l'application (simulation d'envoi).

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
- Qui est l'Administrateur ? (au moins 2 actifs, règle appliquée.)
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
