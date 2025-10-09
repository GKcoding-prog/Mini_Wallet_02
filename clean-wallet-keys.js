// Script pour nettoyer le champ server_encrypted_private_key dans la table Wallet
// Il supprime toute partie WIF en clair et ne garde que le JSON chiffré
// À lancer avec: node clean-wallet-keys.js

require('dotenv').config();
const { models } = require('./src/models');

async function cleanWalletKeys() {
  const wallets = await models.Wallet.findAll();
  let cleaned = 0;

  for (const wallet of wallets) {
    let value = wallet.server_encrypted_private_key;
    if (!value) continue;
    // Si la valeur commence par une clé WIF suivie d'une virgule, on ne garde que la partie JSON
    if (typeof value === 'string' && value.includes(',{"iv"')) {
      const jsonPart = value.substring(value.indexOf('{'));
      try {
        const obj = JSON.parse(jsonPart);
        if (obj.iv && (obj.encryptedData || obj.data)) {
          wallet.server_encrypted_private_key = jsonPart;
          await wallet.save();
          cleaned++;
          console.log(`Wallet ${wallet.wallet_id} nettoyé.`);
        }
      } catch (e) {
        console.log(`Wallet ${wallet.wallet_id} : JSON invalide, à corriger manuellement.`);
      }
    }
  }
  console.log(`Nettoyage terminé. ${cleaned} wallets corrigés.`);
}

cleanWalletKeys().catch(console.error);
