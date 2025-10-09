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
  let keyPair;
  try {
    const { fromAddress, toAddress, amount } = req.body;
    const user = req.user; // Set by verify2FAMiddleware

    if (!fromAddress || !toAddress || !amount) {
      return res.status(400).json({ message: 'Adresse d\'envoi, adresse de destination et montant requis' });
    }

    try {
      bitcoin.address.toOutputScript(fromAddress, network);
      bitcoin.address.toOutputScript(toAddress, network);
    } catch (e) {
      return res.status(400).json({ message: 'Adresse d\'envoi ou de destination invalide' });
    }

    const wallet = await models.Wallet.findOne({ where: { user_id: user.id, address: fromAddress } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé pour cette adresse d\'envoi' });

    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const encryptedPrivateKeyObject = JSON.parse(wallet.server_encrypted_private_key || wallet.private_key);
    try {
      const privateKey = decryptData(encryptedPrivateKeyObject, serverKey);
      try {
        keyPair = ECPair.fromWIF(privateKey, network);
      } catch (wifError) {
        console.error('WIF invalide:', wifError.message);
        return res.status(400).json({ message: 'Clé privée invalide' });
      }
    } catch (error) {
      console.error('Déchiffrement échoué:', error.message);
      return res.status(400).json({ message: 'Erreur de déchiffrement de la clé privée' });
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
        address: fromAddress,
        value: change,
      });
    }

    for (let i = 0; i < utxos.length; i++) {
      psbt.signInput(i, keyPair);
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();

    const response = await axios.post('https://api.blockcypher.com/v1/btc/test3/txs/push', { tx: txHex });

    const receiverWallet = await models.Wallet.findOne({ where: { address: toAddress } });
    const receiverId = receiverWallet ? receiverWallet.user_id : null;

    const txData = { txid: response.data.tx.hash, amount, fromAddress, toAddress };
    const encryptedTxData = JSON.stringify(encryptData(JSON.stringify(txData), serverKey));

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
    process.stdout.write('Log: Fonction getTransactionHistory appelée\n');
    process.stdout.write('Log: En-tête Authorization: ' + JSON.stringify(req.headers.authorization) + '\n');
    process.stdout.write('Log: Corps de la requête: ' + JSON.stringify(req.body) + '\n');

    const token = req.headers.authorization?.split(' ')[1] || req.body.token;
    if (!token) {
      process.stdout.write('Log: Aucun token trouvé\n');
      return res.status(401).json({ message: 'Token requis' });
    }

    process.stdout.write('Log: Token extrait: ' + token + '\n');

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    process.stdout.write('Log: Payload décodé: ' + JSON.stringify(payload) + '\n');

    const user = await models.User.findByPk(payload.id);
    if (!user) {
      process.stdout.write('Log: Utilisateur non trouvé\n');
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }

    process.stdout.write('Log: Utilisateur trouvé: ' + user.id + ', ' + user.email + '\n');

    const wallet = await models.Wallet.findOne({ where: { user_id: user.id } });
    if (!wallet) {
      process.stdout.write('Log: Portefeuille non trouvé\n');
      return res.status(404).json({ message: 'Portefeuille non trouvé' });
    }

    process.stdout.write('Log: Portefeuille trouvé: ' + wallet.wallet_id + ', ' + wallet.address + '\n');

    const transactions = await models.Transaction.findAll({
      where: { wallet_id: wallet.wallet_id },
      attributes: ['id', 'type', 'txid', 'status', 'confirmations', 'created_at', 'encrypted_data'],
      include: [
        {
          model: models.User,
          as: 'Sender',
          attributes: ['email'],
          include: [{ model: models.Wallet, attributes: ['address'] }],
        },
        {
          model: models.User,
          as: 'Receiver',
          attributes: ['email'],
          include: [{ model: models.Wallet, attributes: ['address'] }],
        },
      ],
    });

    process.stdout.write('Log: Transactions récupérées: ' + transactions.length + '\n');

    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const decryptedTransactions = transactions.map(tx => {
      let decryptedData = {};
      try {
        process.stdout.write('Log: Début déchiffrement pour transaction ' + tx.id + '\n');
        process.stdout.write('Log: encrypted_data brute: ' + JSON.stringify(tx.encrypted_data) + '\n');
        if (tx.encrypted_data) {
          const encryptedData = JSON.parse(tx.encrypted_data);
          process.stdout.write('Log: encryptedData après parse: ' + JSON.stringify(encryptedData) + '\n');
          const rawDecryptedData = decryptData(encryptedData, serverKey);
          process.stdout.write('Log: rawDecryptedData: ' + rawDecryptedData + '\n');
          decryptedData = JSON.parse(rawDecryptedData);
        }
      } catch (error) {
        process.stdout.write('Log: Échec du déchiffrement pour transaction ' + tx.id + ': ' + error.message + '\n');
        decryptedData = { error: 'Données corrompues' };
      }
      return {
        id: tx.id,
        type: tx.type,
        txid: tx.txid,
        status: tx.status,
        confirmations: tx.confirmations,
        created_at: tx.created_at,
        senderEmail: tx.Sender?.email || null,
        senderAddress: tx.Sender?.Wallet?.address || null,
        receiverEmail: tx.Receiver?.email || null,
        receiverAddress: tx.Receiver?.Wallet?.address || null,
        ...decryptedData,
      };
    });

    process.stdout.write('Log: Transactions décryptées: ' + JSON.stringify(decryptedTransactions) + '\n');

    res.json(decryptedTransactions);
  } catch (error) {
    process.stdout.write('Log: Erreur lors de la récupération de l\'historique: ' + error.message + '\n');
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function sendPayment(req, res) {
  let keyPair;
  try {
    const { fromAddress, toAddress, amount } = req.body;
    const user = req.user;

    if (!fromAddress || !toAddress || !amount) {
      return res.status(400).json({ message: 'Adresse d\'envoi, adresse de destination et montant requis' });
    }

    try {
      bitcoin.address.toOutputScript(fromAddress, network);
      bitcoin.address.toOutputScript(toAddress, network);
    } catch (e) {
      return res.status(400).json({ message: 'Adresse d\'envoi ou de destination invalide' });
    }

    const wallet = await models.Wallet.findOne({ where: { user_id: user.id, address: fromAddress } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé pour cette adresse d\'envoi' });

    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const encryptedPrivateKeyObject = JSON.parse(wallet.server_encrypted_private_key || wallet.private_key);
    try {
      const privateKey = decryptData(encryptedPrivateKeyObject, serverKey);
      try {
        keyPair = ECPair.fromWIF(privateKey, network);
      } catch (wifError) {
        console.error('WIF invalide:', wifError.message);
        return res.status(400).json({ message: 'Clé privée invalide' });
      }
    } catch (error) {
      console.error('Déchiffrement échoué:', error.message);
      return res.status(400).json({ message: 'Erreur de déchiffrement de la clé privée' });
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
        address: fromAddress,
        value: change,
      });
    }

    for (let i = 0; i < utxos.length; i++) {
      psbt.signInput(i, keyPair);
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();

    const response = await axios.post('https://api.blockcypher.com/v1/btc/test3/txs/push', { tx: txHex });

    const receiverWallet = await models.Wallet.findOne({ where: { address: toAddress } });
    const receiverId = receiverWallet ? receiverWallet.user_id : null;

    const txData = { txid: response.data.tx.hash, amount, fromAddress, toAddress };
    const encryptedTxData = JSON.stringify(encryptData(JSON.stringify(txData), serverKey));

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
    console.error('Erreur lors de l\'envoi du paiement:', error);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

module.exports = {
  listUsers,
  getBalance,
  sendBitcoin,
  getTransactionHistory,
  sendPayment,
};