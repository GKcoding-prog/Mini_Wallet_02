const axios = require('axios');
const { Op } = require('sequelize');
const BitcoinClient = require('bitcoin-core');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { encryptData, decryptData } = require('../services/encryption');
const crypto = require('crypto');

const bitcoinClient = new BitcoinClient({
  network: 'testnet',
  host: 'localhost',
  port: 18332,
  username: process.env.BITCOIN_RPC_USER,
  password: process.env.BITCOIN_RPC_PASSWORD,
});

async function deposit(req, res) {
  try {
    console.log('req.body (deposit):', req.body);
    console.log('Headers (deposit):', req.headers);
    const { amount, txId } = req.body;
    const userId = req.user.id;

    const parsedAmount = parseFloat(amount);
    if (!amount || parsedAmount <= 0 || !txId) {
      return res.status(400).json({ message: 'Montant ou TxID invalide' });
    }

    const user = await User.findByPk(userId);
    if (!user || !user.bitcoinAddress) {
      return res.status(404).json({ message: 'Utilisateur ou adresse Testnet non trouvé' });
    }

    const tx = await bitcoinClient.getTransaction(txId);
    if (!tx.details || !tx.details.some(detail => detail.address === user.bitcoinAddress && detail.category === 'receive')) {
      return res.status(400).json({ message: 'Transaction non destinée à votre adresse' });
    }

    const txAmount = tx.details.find(detail => detail.address === user.bitcoinAddress).amount;
    if (txAmount !== parsedAmount) {
      return res.status(400).json({ message: 'Montant de la transaction ne correspond pas' });
    }

    const aesKey = Buffer.from(req.user.aesKey, 'base64');
    const encrypted = encryptData(`+${parsedAmount}`, aesKey);
    const confirmations = tx.confirmations || 0;
    const status = confirmations >= 6 ? 'confirmed' : 'pending';

    await Transaction.create({
      senderId: null,
      receiverId: userId,
      encrypted_data: JSON.stringify(encrypted),
      type: 'deposit',
      txId,
      status,
      confirmations,
    });

    if (status === 'confirmed') {
      user.balance = parseFloat(user.balance) + parsedAmount;
      await user.save();
    }

    res.status(200).json({ message: 'Dépôt Testnet enregistré', balance: user.balance });
  } catch (error) {
    console.error('Erreur lors du dépôt:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function withdraw(req, res) {
  try {
    console.log('req.body (withdraw):', req.body);
    console.log('Headers (withdraw):', req.headers);
    const { amount, destinationAddress, password } = req.body;
    const userId = req.user.id;

    const parsedAmount = parseFloat(amount);
    if (!parsedAmount || parsedAmount <= 0 || !destinationAddress || !password) {
      return res.status(400).json({ message: 'Paramètres invalides' });
    }

    const user = await User.findByPk(userId);
    if (!user || !user.bitcoinAddress || !user.encrypted_private_key) {
      return res.status(404).json({ message: 'Utilisateur ou adresse Testnet non trouvé' });
    }

    if (parseFloat(user.balance) < parsedAmount) {
      return res.status(400).json({ message: 'Solde insuffisant' });
    }

    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedPrivateKeyObject = JSON.parse(user.encrypted_private_key);
    const privateKey = decryptData(encryptedPrivateKeyObject, passwordKey);

    await bitcoinClient.importPrivKey(privateKey, '', false);

    const feeResponse = await axios.get('https://api.blockcypher.com/v1/btc/main');
    const feePerByte = Math.round(feeResponse.data.high_fee_per_kb / 1000);
    await bitcoinClient.setTxFee(feePerByte / 100000000);

    const txId = await bitcoinClient.sendToAddress(destinationAddress, parsedAmount);

    const aesKey = Buffer.from(req.user.aesKey, 'base64');
    const encrypted = encryptData(`-${parsedAmount}`, aesKey);

    await Transaction.create({
      senderId: userId,
      receiverId: null,
      encrypted_data: JSON.stringify(encrypted),
      type: 'withdrawal',
      txId,
      status: 'pending',
      confirmations: 0,
    });

    user.balance = parseFloat(user.balance) - parsedAmount;
    await user.save();

    const newAddress = await bitcoinClient.getNewAddress();
    await bitcoinClient.generateToAddress(1, newAddress);

    res.status(200).json({ message: 'Retrait Testnet initié', balance: user.balance });
  } catch (error) {
    console.error('Erreur lors du retrait:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function transfer(req, res) {
  try {
    console.log('req.body (transfer):', req.body);
    console.log('Headers (transfer):', req.headers);
    const { receiverEmail, amount, password } = req.body;
    const senderId = req.user.id;

    const parsedAmount = parseFloat(amount);
    if (!receiverEmail || !parsedAmount || parsedAmount <= 0 || !password) {
      return res.status(400).json({ message: 'Paramètres invalides' });
    }

    const sender = await User.findByPk(senderId);
    const receiver = await User.findOne({ where: { email: receiverEmail } });

    if (!sender || !sender.bitcoinAddress || !sender.encrypted_private_key) {
      return res.status(404).json({ message: 'Utilisateur expéditeur non trouvé' });
    }
    if (!receiver || !receiver.bitcoinAddress) {
      return res.status(404).json({ message: 'Utilisateur destinataire ou adresse Testnet non trouvé' });
    }
    if (parseFloat(sender.balance) < parsedAmount) {
      return res.status(400).json({ message: 'Solde insuffisant' });
    }

    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedPrivateKeyObject = JSON.parse(sender.encrypted_private_key);
    const privateKey = decryptData(encryptedPrivateKeyObject, passwordKey);

    await bitcoinClient.importPrivKey(privateKey, '', false);

    const feeResponse = await axios.get('https://api.blockcypher.com/v1/btc/main');
    const feePerByte = Math.round(feeResponse.data.high_fee_per_kb / 1000);
    await bitcoinClient.setTxFee(feePerByte / 100000000);

    const txId = await bitcoinClient.sendToAddress(receiver.bitcoinAddress, parsedAmount);

    const aesKey = Buffer.from(req.user.aesKey, 'base64');
    const encrypted = encryptData(`-${parsedAmount} to ${receiverEmail}`, aesKey);

    await Transaction.create({
      senderId,
      receiverId: receiver.id,
      encrypted_data: JSON.stringify(encrypted),
      type: 'transfer',
      txId,
      status: 'pending',
      confirmations: 0,
    });

    sender.balance = parseFloat(sender.balance) - parsedAmount;
    receiver.balance = parseFloat(receiver.balance) + parsedAmount;
    await sender.save();
    await receiver.save();

    const newAddress = await bitcoinClient.getNewAddress();
    await bitcoinClient.generateToAddress(1, newAddress);

    res.status(200).json({ message: 'Transfert Testnet initié', balance: sender.balance });
  } catch (error) {
    console.error('Erreur lors du transfert:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function getHistory(req, res) {
  try {
    console.log('req.query (getHistory):', req.query);
    console.log('Headers (getHistory):', req.headers);
    const userId = req.user.id;
    const aesKey = Buffer.from(req.user.aesKey, 'base64');

    const transactions = await Transaction.findAll({
      where: {
        [Op.or]: [{ senderId: userId }, { receiverId: userId }],
      },
      order: [['createdAt', 'DESC']],
    });

    for (const tx of transactions) {
      if (tx.txId && tx.status !== 'confirmed') {
        try {
          const txInfo = await bitcoinClient.getTransaction(tx.txId);
          tx.confirmations = txInfo.confirmations || 0;
          tx.status = tx.confirmations >= 6 ? 'confirmed' : 'pending';
          await tx.save();

          if (tx.status === 'confirmed' && tx.type === 'deposit') {
            const user = await User.findByPk(tx.receiverId);
            if (user) {
              const decrypted = decryptData(JSON.parse(tx.encrypted_data), aesKey);
              const amount = parseFloat(decrypted.replace('+', ''));
              user.balance = parseFloat(user.balance) + amount;
              await user.save();
            }
          }
        } catch (error) {
          console.warn(`Erreur lors de la vérification de TxID ${tx.txId}:`, error.message);
        }
      }
    }

    const result = transactions.map(tx => ({
      id: tx.id,
      senderId: tx.senderId,
      receiverId: tx.receiverId,
      amount: decryptData(JSON.parse(tx.encrypted_data), aesKey),
      type: tx.type,
      txId: tx.txId,
      status: tx.status,
      confirmations: tx.confirmations,
      createdAt: tx.createdAt,
    }));

    res.json(result);
  } catch (error) {
    console.error('Erreur lors de la récupération de l\'historique:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

module.exports = { deposit, withdraw, transfer, getHistory };