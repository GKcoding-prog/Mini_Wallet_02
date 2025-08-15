# 📋 Endpoints de l'API Mini-Wallet

Bienvenue dans la documentation des endpoints de l'API Mini-Wallet. Cette API permet la gestion des utilisateurs et des transactions Bitcoin sur le réseau Testnet. Les endpoints sont divisés en deux catégories : **Authentification** (`/api/auth`) et **Portefeuille** (`/api/wallet`).

---

## 🔑 Endpoints d'Authentification (`/api/auth`)

Ces endpoints gèrent l'enregistrement, la connexion, la vérification OTP, le rafraîchissement des tokens, et la déconnexion des utilisateurs. Aucun header d'authentification n'est requis pour ces routes.

### 1. `POST /api/auth/register`
**Créer un compte utilisateur et envoyer un code OTP par email.**

- **🔍 Description** : Enregistre un nouvel utilisateur et envoie un code OTP à son email pour vérification.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `email` (string, requis) : Adresse email de l'utilisateur.
  - `password` (string, requis) : Mot de passe de l'utilisateur.
- **🚀 Headers** : Aucun.
- **✅ Réponses** :
  - `200 OK` : `{ "message": "Code OTP envoyé à votre email. Veuillez le vérifier." }`
  - `400 Bad Request` : `{ "message": "Email et mot de passe requis" }` ou `{ "message": "Email déjà utilisé" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@example.com&password=test123"
  ```

---

### 2. `POST /api/auth/verify-otp`
**Vérifier le code OTP et finaliser l'enregistrement.**

- **🔍 Description** : Vérifie le code OTP envoyé par email et crée l'utilisateur avec une adresse Testnet.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `email` (string, requis) : Adresse email de l'utilisateur.
  - `otp` (string, requis) : Code OTP reçu par email.
  - `password` (string, requis) : Mot de passe de l'utilisateur.
- **🚀 Headers** : Aucun.
- **✅ Réponses** :
  - `201 Created` : `{ "message": "Utilisateur créé avec succès. Veuillez vous connecter.", "bitcoinAddress": "<adresse_testnet>" }`
  - `400 Bad Request` : `{ "message": "Email, OTP et mot de passe requis" }`, `{ "message": "Code OTP invalide" }`, ou `{ "message": "Code OTP expiré" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/auth/verify-otp \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@example.com&otp=123456&password=test123"
  ```

---

### 3. `POST /api/auth/login`
**Connecter un utilisateur et obtenir des tokens.**

- **🔍 Description** : Authentifie un utilisateur et retourne un access token, un refresh token, et son adresse Testnet.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `email` (string, requis) : Adresse email de l'utilisateur.
  - `password` (string, requis) : Mot de passe de l'utilisateur.
- **🚀 Headers** : Aucun.
- **✅ Réponses** :
  - `200 OK` : `{ "accessToken": "<token>", "refreshToken": "<token>", "bitcoinAddress": "<adresse_testnet>" }`
  - `400 Bad Request` : `{ "message": "Email et mot de passe requis" }`
  - `401 Unauthorized` : `{ "message": "Email ou mot de passe invalide" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@example.com&password=test123"
  ```

---

### 4. `POST /api/auth/refresh-token`
**Rafraîchir l'access token.**

- **🔍 Description** : Génère un nouvel access token à partir d'un refresh token valide.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `refreshToken` (string, requis) : Refresh token obtenu lors de la connexion.
- **🚀 Headers** : Aucun.
- **✅ Réponses** :
  - `200 OK` : `{ "accessToken": "<nouveau_token>" }`
  - `400 Bad Request` : `{ "message": "Refresh token requis" }`
  - `401 Unauthorized` : `{ "message": "Refresh token invalide ou expiré" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/auth/refresh-token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "refreshToken=<votre_refresh_token>"
  ```

---

### 5. `POST /api/auth/logout`
**Déconnecter un utilisateur.**

- **🔍 Description** : Blackliste le refresh token et, optionnellement, l'access token pour déconnexion.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `refreshToken` (string, requis) : Refresh token à blacklister.
  - `accessToken` (string, optionnel) : Access token à blacklister.
- **🚀 Headers** : Aucun.
- **✅ Réponses** :
  - `200 OK` : `{ "message": "Déconnexion réussie" }`
  - `400 Bad Request` : `{ "message": "Refresh token requis" }` ou `{ "message": "Refresh token invalide" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/auth/logout \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "refreshToken=<votre_refresh_token>&accessToken=<votre_access_token>"
  ```

---

## 💸 Endpoints de Portefeuille (`/api/wallet`)

Ces endpoints gèrent les transactions Bitcoin sur le réseau Testnet. **Tous nécessitent le header `Authorization: Bearer <access_token>`** obtenu via `/api/auth/login` ou `/api/auth/refresh-token`. Les frais de transaction sont estimés via BlockCypher pour simuler le mainnet.

### 1. `POST /api/wallet/deposit`
**Enregistrer un dépôt Testnet.**

- **🔍 Description** : Valide et enregistre une transaction Testnet reçue sur l'adresse de l'utilisateur.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `amount` (number, requis) : Montant en BTC (ex. `0.01`).
  - `txId` (string, requis) : ID de la transaction Testnet.
- **🚀 Headers** :
  - `Authorization: Bearer <access_token>` (requis)
- **✅ Réponses** :
  - `200 OK` : `{ "message": "Dépôt Testnet enregistré", "balance": <nouveau_solde> }`
  - `400 Bad Request` : `{ "message": "Montant ou TxID invalide" }` ou `{ "message": "Transaction non destinée à votre adresse" }`
  - `401 Unauthorized` : `{ "message": "Token manquant" }`, `{ "message": "Token invalide" }`, ou `{ "message": "Utilisateur non trouvé" }`
  - `404 Not Found` : `{ "message": "Utilisateur ou adresse Testnet non trouvé" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/wallet/deposit \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer <votre_access_token>" \
  -d "amount=0.01&txId=<votre_txid>"
  ```

---

### 2. `POST /api/wallet/withdraw`
**Effectuer un retrait Testnet.**

- **🔍 Description** : Envoie des BTC depuis l'adresse de l'utilisateur vers une adresse externe, avec frais estimés via BlockCypher.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `amount` (number, requis) : Montant en BTC à retirer.
  - `destinationAddress` (string, requis) : Adresse Bitcoin de destination.
  - `password` (string, requis) : Mot de passe pour décrypter la clé privée.
- **🚀 Headers** :
  - `Authorization: Bearer <access_token>` (requis)
- **✅ Réponses** :
  - `200 OK` : `{ "message": "Retrait Testnet initié", "balance": <nouveau_solde> }`
  - `400 Bad Request` : `{ "message": "Paramètres invalides" }` ou `{ "message": "Solde insuffisant" }`
  - `401 Unauthorized` : `{ "message": "Token manquant" }`, `{ "message": "Token invalide" }`, ou `{ "message": "Utilisateur non trouvé" }`
  - `404 Not Found` : `{ "message": "Utilisateur ou adresse Testnet non trouvé" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/wallet/withdraw \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer <votre_access_token>" \
  -d "amount=0.005&destinationAddress=<adresse_testnet>&password=test123"
  ```

---

### 3. `POST /api/wallet/transfer`
**Transférer des BTC à un autre utilisateur.**

- **🔍 Description** : Transfère des BTC à un autre utilisateur via son email, avec frais estimés via BlockCypher.
- **📋 Paramètres** (body, `application/x-www-form-urlencoded`) :
  - `amount` (number, requis) : Montant en BTC à transférer.
  - `receiverEmail` (string, requis) : Email de l'utilisateur destinataire.
  - `password` (string, requis) : Mot de passe pour décrypter la clé privée.
- **🚀 Headers** :
  - `Authorization: Bearer <access_token>` (requis)
- **✅ Réponses** :
  - `200 OK` : `{ "message": "Transfert Testnet initié", "balance": <nouveau_solde> }`
  - `400 Bad Request` : `{ "message": "Paramètres invalides" }` ou `{ "message": "Solde insuffisant" }`
  - `401 Unauthorized` : `{ "message": "Token manquant" }`, `{ "message": "Token invalide" }`, ou `{ "message": "Utilisateur non trouvé" }`
  - `404 Not Found` : `{ "message": "Utilisateur expéditeur non trouvé" }` ou `{ "message": "Utilisateur destinataire ou adresse Testnet non trouvé" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X POST http://localhost:3000/api/wallet/transfer \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer <votre_access_token>" \
  -d "amount=0.005&receiverEmail=recipient@example.com&password=test123"
  ```

---

### 4. `GET /api/wallet/history`
**Consulter l'historique des transactions.**

- **🔍 Description** : Récupère l'historique des transactions (dépôts, retraits, transferts) de l'utilisateur, avec vérification des confirmations Testnet.
- **📋 Paramètres** : Aucun.
- **🚀 Headers** :
  - `Authorization: Bearer <access_token>` (requis)
- **✅ Réponses** :
  - `200 OK` : `[{ id, senderId, receiverId, amount, type, txId, status, confirmations, createdAt }, ...]`
  - `401 Unauthorized` : `{ "message": "Token manquant" }`, `{ "message": "Token invalide" }`, ou `{ "message": "Utilisateur non trouvé" }`
  - `500 Internal Server Error` : `{ "message": "Erreur serveur" }`
- **💻 Exemple** :
  ```bash
  curl -X GET http://localhost:3000/api/wallet/history \
  -H "Authorization: Bearer <votre_access_token>"
  ```

---

## 📝 Notes Générales

- **🔗 Content-Type** : Tous les endpoints POST utilisent `application/x-www-form-urlencoded` pour les données du corps.
- **🔒 Authentification** : Les endpoints `/api/wallet/*` nécessitent un header `Authorization: Bearer <access_token>` valide.
- **🌐 Testnet** : Les opérations de portefeuille interagissent avec le réseau Testnet via Bitcoin Core.
- **💰 Frais** : Les endpoints `/withdraw` et `/transfer` utilisent l'API BlockCypher pour estimer les frais du mainnet.
- **🕒 Date** : Documentation générée le 15 août 2025 à 12:35 PM CAT.