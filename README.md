# T.CH MANANJARY 🇲🇬

Site full-stack pour le cinéma, l'entertainment et la promotion des talents de Mananjary.

## Stack
- Frontend: HTML5, CSS3, JavaScript vanilla
- Backend: Node.js + Express
- Base de données: SQLite (`better-sqlite3`)
- Sessions: `express-session` + SQLite store
- Uploads: `multer`
- Sécurité HTTP: `helmet` + rate limiting

## Démarrage
1. Installer Node.js 20+.
2. Copier `.env.example` vers `.env`.
3. Changer `SESSION_SECRET` et `ADMIN_PASSWORD`.
4. `npm install`
5. `npm start`
6. Ouvrir `http://localhost:3000`.

Le code d'accès public demandé est lu uniquement côté serveur via `PUBLIC_ACCESS_CODE` et n'est jamais envoyé au navigateur.

## Admin
- URL: `/admin.html`
- Identifiant: `ADMIN_USERNAME`
- Mot de passe: `ADMIN_PASSWORD`

L'admin peut gérer films, vidéos, images, membres, candidatures et projets à venir.

## Médias payants
Les vidéos de films sont stockées hors de `public/` et servies par une route protégée (`/api/media/video/:id`). Le frontend ne reçoit jamais l'URL physique du fichier vidéo.

La couche `paymentAdapter` est volontairement un adaptateur: aucun moyen de paiement malgache n'est inventé. Pour une mise en production, connecter un prestataire réel et faire confirmer les paiements par son webhook signé.

## Données fournies
Les deux fichiers fournis dans la demande sont utilisés réellement:
- `public/assets/tch-logo.png` = logo T.CH fourni
- `public/assets/long-time-poster.png` = affiche LONG TIME fournie

## Important production
- Servir en HTTPS.
- Mettre un vrai secret de session long et aléatoire.
- Utiliser un compte admin unique avec mot de passe fort.
- Brancher un vrai stockage objet privé pour les gros films si nécessaire.
- Brancher un prestataire de paiement réel avant d'accepter des paiements.
