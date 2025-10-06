const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { models } = require('../models');
const { encryptData } = require('../services/encryption');
const { checkEmailExists, SALT_ROUNDS, network } = require('./utils');
const axios = require('axios');
const ECPairFactory = require('ecpair').ECPairFactory;
const tinysecp = require('tiny-secp256k1');
const bitcoin = require('bitcoinjs-lib');

async function createAdmin(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    if (await checkEmailExists(email)) {
      return res.status(400).json({ message: 'Email déjà utilisé' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const aesKey = crypto.randomBytes(32);
    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKey = encryptData(aesKey.toString('hex'), passwordKey);
    const encryptedKeyString = JSON.stringify(encryptedKey);

    const keyPair = ECPairFactory(tinysecp).makeRandom({ network });
    const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });
    const privateKey = keyPair.toWIF();
    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const encryptedPrivateKey = encryptData(privateKey, serverKey);
    const encryptedPrivateKeyString = JSON.stringify(encryptedPrivateKey);

    const user = await models.User.create({
      email,
      password: hashedPassword,
      encrypted_key: encryptedKeyString,
      role: 'admin',
    });

    const wallet = await models.Wallet.create({
      user_id: user.id,
      address,
      private_key: encryptedPrivateKeyString,
      server_encrypted_private_key: encryptedPrivateKeyString,
    });

    let utxos = [];
    try {
      const utxoResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${address}?unspentOnly=true`);
      utxos = utxoResponse.data.txrefs || [];
    } catch (apiError) {
      console.warn(`Échec de l'API pour ${address}:`, apiError.message);
    }

    if (utxos && Array.isArray(utxos) && utxos.length > 0) {
      for (const utxo of utxos) {
        if (!utxo || !utxo.tx_hash || !utxo.tx_output_n || !utxo.value) {
          console.error('UTXO invalide ignoré:', JSON.stringify(utxo));
          continue;
        }
        await models.Utxo.create({
          wallet_id: wallet.wallet_id,
          tx_hash: utxo.tx_hash,
          output_index: utxo.tx_output_n,
          amount: utxo.value,
          used: false,
        });
      }
    } else {
      console.log(`Aucun UTXO valide pour ${address}. Création réussie sans UTXOs.`);
    }

    res.status(201).json({ message: 'Admin créé avec succès.', bitcoinAddress: address });
  } catch (error) {
    console.error('Erreur lors de la création de l\'admin:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

module.exports = { createAdmin };