// Script pour afficher toutes les clés privées déchiffrées de la table Wallet
// Permet d'identifier les entrées invalides ou corrompues
// À lancer avec: node check-wallet-keys.js

require('dotenv').config();
const { models } = require('./src/models');
const { decryptData } = require('./src/services/encryption');

async function checkWalletKeys() {
  const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
  const wallets = await models.Wallet.findAll();
  let ok = 0, invalid = 0;

  for (const wallet of wallets) {
    if (!wallet.server_encrypted_private_key) continue;
    try {
      const encrypted = JSON.parse(wallet.server_encrypted_private_key);
      const privateKey = decryptData(encrypted, serverKey);
      // Affiche la clé privée déchiffrée
      console.log(`Wallet ${wallet.wallet_id} : ${privateKey}`);
      // Vérifie si la clé ressemble à une WIF
      if (/^[c9KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(privateKey)) {
        ok++;
      } else {
        console.log(`  -> Clé WIF invalide !`);
        invalid++;
      }
    } catch (e) {
      console.log(`Wallet ${wallet.wallet_id} : Erreur de déchiffrement (${e.message})`);
      invalid++;
    }
  }
  console.log(`\nRésultat : ${ok} clés valides, ${invalid} invalides ou corrompues.`);
}

checkWalletKeys().catch(console.error);
