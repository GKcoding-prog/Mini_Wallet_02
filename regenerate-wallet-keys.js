// Script pour régénérer les wallets corrompus ou sans clé privée valide
// Génère une nouvelle clé WIF et adresse pour chaque wallet invalide
// À lancer avec: node regenerate-wallet-keys.js

require('dotenv').config();
const bitcoin = require('bitcoinjs-lib');
const ECPairFactory = require('ecpair').ECPairFactory;
const tinysecp = require('tiny-secp256k1');
const { models } = require('./src/models');
const { encryptData, decryptData } = require('./src/services/encryption');

const network = bitcoin.networks.testnet; // adapte si mainnet
const ECPair = ECPairFactory(tinysecp);

async function regenerateWalletKeys() {
  const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
  const wallets = await models.Wallet.findAll();
  let regenerated = 0;

  for (const wallet of wallets) {
    let isValid = false;
    if (wallet.server_encrypted_private_key) {
      try {
        const encrypted = JSON.parse(wallet.server_encrypted_private_key);
        const privateKey = decryptData(encrypted, serverKey);
        if (/^[c9KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(privateKey)) {
          isValid = true;
        }
      } catch (e) {}
    }
    if (!isValid) {
      // Générer une nouvelle clé
      const keyPair = ECPair.makeRandom({ network });
      const wif = keyPair.toWIF();
      const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });
      const encrypted = encryptData(wif, serverKey);
  wallet.server_encrypted_private_key = JSON.stringify(encrypted);
  wallet.private_key = wif; // garder la clé WIF pour respecter la contrainte NOT NULL
  wallet.address = address;
  await wallet.save();
  regenerated++;
  console.log(`Wallet ${wallet.wallet_id} régénéré. Nouvelle adresse : ${address}`);
    }
  }
  console.log(`\nRégénération terminée. ${regenerated} wallets mis à jour.`);
}

regenerateWalletKeys().catch(console.error);
