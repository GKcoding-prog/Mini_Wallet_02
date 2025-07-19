const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { encryptData, decryptData } = require('../services/encryption');

async function deposit(req, res) {
  try {
    const userId = req.user.id;
    const amount = parseFloat(req.body.amount);
    if (!amount || amount <= 0)
      return res.status(400).json({ message: 'Montant invalide' });

    const user = await User.findByPk(userId);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    // récupérer clé AES depuis JWT (base64 → Buffer)
    const aesKey = Buffer.from(req.user.aesKey, 'base64');

    const encrypted = encryptData(`+${amount}`, aesKey);

    await Transaction.create({
      senderId: null,
      receiverId: userId,
      encrypted_data: encrypted,
      type: 'deposit',
    });

    user.balance = parseFloat(user.balance) + amount;
    await user.save();

    res.status(200).json({ message: 'Dépôt effectué avec succès', balance: user.balance });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function transfer(req, res) {
  try {
    const senderId = req.user.id;
    const { receiverEmail, amount } = req.body;

    if (!receiverEmail || !amount || amount <= 0)
      return res.status(400).json({ message: 'Paramètres invalides' });

    const sender = await User.findByPk(senderId);
    if (!sender) return res.status(404).json({ message: 'Utilisateur expéditeur non trouvé' });

    const receiver = await User.findOne({ where: { email: receiverEmail } });
    if (!receiver) return res.status(404).json({ message: 'Utilisateur destinataire non trouvé' });

    if (parseFloat(sender.balance) < amount)
      return res.status(400).json({ message: 'Solde insuffisant' });

    const aesKey = Buffer.from(req.user.aesKey, 'base64');

    const encrypted = encryptData(`-${amount} to ${receiverEmail}`, aesKey);

    await Transaction.create({
      senderId,
      receiverId: receiver.id,
      encrypted_data: encrypted,
      type: 'transfer',
    });

    sender.balance = parseFloat(sender.balance) - amount;
    receiver.balance = parseFloat(receiver.balance) + amount;

    await sender.save();
    await receiver.save();

    res.status(200).json({ message: 'Transfert effectué avec succès' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function getHistory(req, res) {
  try {
    const userId = req.user.id;
    const aesKey = Buffer.from(req.user.aesKey, 'base64');

    // Récupérer les transactions où user est sender ou receiver
    const transactions = await Transaction.findAll({
      where: {
        // Sequelize or condition for senderId or receiverId = userId
        [require('sequelize').Op.or]: [{ senderId: userId }, { receiverId: userId }],
      },
      order: [['createdAt', 'DESC']],
    });

    // Déchiffrer les données
    const result = transactions.map(tx => ({
      id: tx.id,
      senderId: tx.senderId,
      receiverId: tx.receiverId,
      amount: decryptData(tx.encrypted_data, aesKey),
      type: tx.type,
      createdAt: tx.createdAt,
    }));

    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

module.exports = { deposit, transfer, getHistory };
