const bitcoin = require('bitcoinjs-lib');
const ECPairFactory = require('ecpair').ECPairFactory;
const ecc = require('tiny-secp256k1');
const { encryptData } = require('../services/encryption');
const { models } = require('../models');
const crypto = require('crypto');
const axios = require('axios');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

async function createWallet(user, password) {
  try {
    const keyPair = ECPair.makeRandom({ network });
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: keyPair.publicKey,
      network,
    });

    const privateKeyHex = keyPair.toWIF();
    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKey = encryptData(privateKeyHex, passwordKey);

    // Chiffrement pour le serveur avec SERVER_MASTER_KEY
    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const serverEncryptedKey = encryptData(privateKeyHex, serverKey);

    // Création du portefeuille avec private_key inclus
    const wallet = await models.Wallet.create({
      user_id: user.id,
      address,
      private_key: privateKeyHex, // Ajout de la clé privée en clair
      encrypted_private_key: JSON.stringify(encryptedKey),
      server_encrypted_private_key: JSON.stringify(serverEncryptedKey),
    });

    return { address };
  } catch (error) {
    console.error('Erreur lors de la création du portefeuille:', error);
    throw new Error(`Erreur lors de la création du portefeuille: ${error.message}`);
  }
}

async function fetchAndSaveUtxos(wallet, address) {
  try {
    console.debug('Récupération des UTXOs pour adresse:', address);
    const response = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${address}?unspentOnly=true`);
    const apiUtxos = response.data.txrefs || [];

    for (const utxo of apiUtxos) {
      const existingUtxo = await models.Utxo.findOne({
        where: {
          wallet_id: wallet.wallet_id,
          tx_hash: utxo.tx_hash,
          output_index: utxo.tx_output_n,
        },
      });

      if (!existingUtxo) {
        await models.Utxo.create({
          wallet_id: wallet.wallet_id,
          tx_hash: utxo.tx_hash,
          output_index: utxo.tx_output_n,
          amount: utxo.value,
          used: false,
        });
      }
    }
  } catch (error) {
    console.error('Erreur lors de la récupération des UTXOs:', error.message);
  }
}

module.exports = {
  createWallet,
  fetchAndSaveUtxos,
};