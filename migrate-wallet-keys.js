// Script de migration pour chiffrer les anciennes clés privées WIF dans la table Wallet
// À lancer avec: node migrate-wallet-keys.js

require('dotenv').config();
const { models } = require('./src/models');
const { encryptData } = require('./src/services/encryption');

async function migrateWalletKeys() {
  const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
  const wallets = await models.Wallet.findAll();
  let updated = 0;

  for (const wallet of wallets) {
    // Si la clé est déjà au bon format, on saute
    try {
      if (wallet.server_encrypted_private_key) {
        const obj = JSON.parse(wallet.server_encrypted_private_key);
        if (obj.iv && (obj.encryptedData || obj.data)) continue;
      }
    } catch (e) {}

    // Si la clé privée existe en clair (WIF) et semble valide
    if (wallet.private_key && /^[c9KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(wallet.private_key)) {
      const encrypted = encryptData(wallet.private_key, serverKey);
      wallet.server_encrypted_private_key = JSON.stringify(encrypted);
      await wallet.save();
      updated++;
      console.log(`Wallet ${wallet.wallet_id} migré.`);
    } else if (wallet.private_key) {
      console.log(`Wallet ${wallet.wallet_id} : clé privée non WIF, ignorée.`);
    }
  }
  console.log(`Migration terminée. ${updated} wallets mis à jour.`);
}

migrateWalletKeys().catch(console.error);
