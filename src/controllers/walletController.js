const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const ECPairFactory = require('ecpair').ECPairFactory;
const tinysecp = require('tiny-secp256k1');
const axios = require('axios');
const { models } = require('../models');
const { encryptData, decryptData } = require('../services/encryption');

const network = bitcoin.networks.testnet;
const ECPair = ECPairFactory(tinysecp);

async function listUsers(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== 'admin') {
      return res.status(403).json({ message: 'Accès refusé: Admin seulement' });
    }

    const users = await models.User.findAll({
      attributes: ['id', 'email', 'role'],
      include: [{ model: models.Wallet, attributes: ['address'] }],
    });
    res.json(users);
  } catch (error) {
    console.error('Erreur lors de la liste des utilisateurs:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function getBalance(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const wallet = await models.Wallet.findOne({ where: { user_id: payload.id } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé' });

    const response = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${wallet.address}/balance`);
    const balance = response.data.final_balance / 100000000;

    res.json({ address: wallet.address, balance });
  } catch (error) {
    console.error('Erreur lors de la récupération du solde:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function sendBitcoin(req, res) {
  let keyPair; // Déclaration au niveau de la fonction
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const { toAddress, amount, password } = req.body;

    if (!toAddress || !amount || !password) {
      return res.status(400).json({ message: 'Adresse de destination, montant et mot de passe requis' });
    }

    try {
      bitcoin.address.toOutputScript(toAddress, network);
    } catch (e) {
      return res.status(400).json({ message: 'Adresse de destination invalide' });
    }

    const user = await models.User.findByPk(payload.id);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Mot de passe invalide' });
    }

    const wallet = await models.Wallet.findOne({ where: { user_id: payload.id } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé' });

    const passwordKey = crypto.createHash('sha256').update(password).digest();
    console.log('Password used:', password);
    console.log('passwordKey length:', passwordKey.length);
    console.log('wallet.private_key raw:', wallet.private_key);
    const encryptedPrivateKeyObject = JSON.parse(wallet.private_key);
    console.log('encryptedPrivateKeyObject:', encryptedPrivateKeyObject);
    try {
      const privateKey = decryptData(encryptedPrivateKeyObject, passwordKey);
      console.log('Decrypted privateKey:', privateKey);
      // Validation et conversion en keyPair avec ECPair
      try {
        keyPair = ECPair.fromWIF(privateKey, network);
      } catch (wifError) {
        console.error('WIF invalide:', wifError.message);
        // Régénération de la clé privée si invalide
        const newPrivateKey = ECPair.makeRandom({ network }).toWIF();
        const newEncrypted = encryptData(newPrivateKey, passwordKey);
        await models.Wallet.update({ private_key: JSON.stringify(newEncrypted) }, { where: { user_id: payload.id } });
        console.log('Nouvelle clé privée générée:', newPrivateKey);
        return res.status(400).json({ message: 'Clé privée invalide, régénérée. Relance la requête.', newPrivateKey });
      }
    } catch (error) {
      console.error('Déchiffrement ou validation échoué:', error.message);
      return res.status(400).json({ message: 'Erreur de déchiffrement ou clé invalide: ' + error.message });
    }

    let utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
    if (!utxos || utxos.length === 0) {
      const utxoResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${wallet.address}?unspentOnly=true`);
      const apiUtxos = utxoResponse.data.txrefs || [];
      for (const utxo of apiUtxos) {
        await models.Utxo.create({
          wallet_id: wallet.wallet_id,
          tx_hash: utxo.tx_hash,
          output_index: utxo.tx_output_n,
          amount: utxo.value,
          used: false,
        });
      }
      utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
    }

    if (utxos.length === 0) {
      return res.status(400).json({ error: 'Aucun UTXO disponible' });
    }

    const psbt = new bitcoin.Psbt({ network });
    let totalInput = 0;

    for (const utxo of utxos) {
      const txResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/txs/${utxo.tx_hash}?includeHex=true`);
      const rawTx = txResponse.data.hex;
      if (!rawTx) {
        return res.status(500).json({ message: 'Impossible de récupérer les données de la transaction UTXO' });
      }
      psbt.addInput({
        hash: utxo.tx_hash,
        index: utxo.output_index,
        nonWitnessUtxo: Buffer.from(rawTx, 'hex'),
      });
      totalInput += utxo.amount;
    }

    const amountSat = parseInt(amount * 100000000);
    psbt.addOutput({
      address: toAddress,
      value: amountSat,
    });

    const fee = 100;
    const change = totalInput - amountSat - fee;

    if (change < 0) {
      return res.status(400).json({ error: 'Fonds insuffisants' });
    }
    if (change > 0) {
      psbt.addOutput({
        address: wallet.address,
        value: change,
      });
    }

    for (let i = 0; i < utxos.length; i++) {
      psbt.signInput(i, keyPair); // Utilisation de keyPair défini au niveau supérieur
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();

    const response = await axios.post('https://api.blockcypher.com/v1/btc/test3/txs/push', { tx: txHex });

    const receiverWallet = await models.Wallet.findOne({ where: { address: toAddress } });
    const receiverId = receiverWallet ? receiverWallet.user_id : null;

    const txData = { txid: response.data.tx.hash, amount, toAddress };
    const encryptedTxData = JSON.stringify(encryptData(JSON.stringify(txData), passwordKey));

    await models.Transaction.create({
      wallet_id: wallet.wallet_id,
      senderId: user.id,
      receiverId,
      encrypted_data: encryptedTxData,
      type: 'withdrawal',
      txid: response.data.tx.hash,
      status: 'pending',
      confirmations: 0,
    });

    if (receiverId) {
      await models.Transaction.create({
        wallet_id: receiverWallet.wallet_id,
        senderId: user.id,
        receiverId,
        encrypted_data: encryptedTxData,
        type: 'deposit',
        txid: response.data.tx.hash,
        status: 'pending',
        confirmations: 0,
      });
    }

    for (const utxo of utxos) {
      await utxo.update({ used: true });
    }

    res.json({ txid: response.data.tx.hash, fee: fee / 100000000 + ' tBTC' });
  } catch (error) {
    console.error('Erreur lors de l\'envoi de la transaction:', error);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

async function getTransactionHistory(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const wallet = await models.Wallet.findOne({ where: { user_id: payload.id } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé' });

    const transactions = await models.Transaction.findAll({
      where: { wallet_id: wallet.wallet_id },
      attributes: ['id', 'type', 'txid', 'status', 'confirmations', 'created_at', 'encrypted_data'],
      include: [
        { model: models.User, as: 'Sender', attributes: ['email'] },
        { model: models.User, as: 'Receiver', attributes: ['email'] },
      ],
    });

    const password = req.body.password;
    if (!password) return res.status(400).json({ message: 'Mot de passe requis pour déchiffrer les données' });

    const user = await models.User.findByPk(payload.id);
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Mot de passe invalide' });
    }

    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const decryptedTransactions = transactions.map(tx => {
      let decryptedData = {};
      try {
        if (tx.encrypted_data) {
          const encryptedData = JSON.parse(tx.encrypted_data);
          const rawDecryptedData = decryptData(encryptedData, passwordKey);
          decryptedData = JSON.parse(rawDecryptedData);
        }
      } catch (error) {
        console.warn(`Échec du déchiffrement pour transaction ${tx.id}:`, error.message);
        decryptedData = { error: 'Données corrompues ou mot de passe incorrect' };
      }
      return {
        id: tx.id,
        type: tx.type,
        txid: tx.txid,
        status: tx.status,
        confirmations: tx.confirmations,
        created_at: tx.created_at,
        senderEmail: tx.Sender?.email || null,
        receiverEmail: tx.Receiver?.email || null,
        ...decryptedData,
      };
    });

    res.json(decryptedTransactions);
  } catch (error) {
    console.error('Erreur lors de la récupération de l\'historique:', error);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

module.exports = {
  listUsers,
  getBalance,
  sendBitcoin,
  getTransactionHistory,
};