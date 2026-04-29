# MasterPASS — Espace Documentaire

Plateforme de partage de documents sécurisée pour MasterPASS.

## Prérequis

- **Node.js** version 16 ou supérieure → https://nodejs.org

## Installation et démarrage

```bash
# 1. Décompressez l'archive et entrez dans le dossier
cd masterpass

# 2. Installez les dépendances (une seule fois)
npm install

# 3. Démarrez le serveur
npm start
```

Ouvrez ensuite votre navigateur sur **http://localhost:3000**

## Compte admin par défaut

| Identifiant | Mot de passe |
|-------------|--------------|
| `admin`     | `admin123`   |

⚠️ Pensez à changer ce mot de passe après la première connexion (via "Gestion des comptes" → supprimer l'ancien compte → créer un nouveau compte admin).

## Structure des fichiers

```
masterpass/
├── server.js          ← Serveur Node.js (API + sécurité)
├── package.json       ← Dépendances
├── data/
│   ├── db.json        ← Base de données (créée automatiquement)
│   └── uploads/       ← Fichiers déposés (créé automatiquement)
└── public/
    └── index.html     ← Interface web
```

## Fonctionnalités

### Interface Administrateur
- Tableau de bord avec statistiques
- Créer / supprimer des dossiers
- Déposer des fichiers (glisser-déposer ou parcourir)
- Supprimer des fichiers
- Créer et supprimer des comptes (étudiants ou admins)

### Interface Étudiant
- Voir les dossiers disponibles
- Télécharger les fichiers
- Aucun accès à la gestion des comptes ou aux fonctions d'administration

## Sécurité

- Les mots de passe sont chiffrés avec bcrypt
- Les sessions durent 8 heures
- Les routes admin sont protégées côté serveur
- Un étudiant ne peut PAS accéder aux routes admin même en bricolant l'URL

## Déploiement en ligne

Pour mettre le site en ligne (accessible depuis internet) :

1. **Option simple** : [Railway](https://railway.app) ou [Render](https://render.com) — gratuit, déployez le dossier directement
2. **Option avancée** : VPS avec Nginx + PM2 pour la production

Pour Railway :
```bash
# Installez la CLI Railway
npm install -g @railway/cli
railway login
railway init
railway up
```


