const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const ECPairFactory = require('ecpair').ECPairFactory;
const tinysecp = require('tiny-secp256k1');
const axios = require('axios');
const { models } = require('../models');
const { encryptData, decryptData } = require('../services/encryption');
const { sendOtpEmail } = require('../services/email');

const SALT_ROUNDS = 10;
const network = bitcoin.networks.testnet;

async function checkEmailExists(email) {
  const existingUser = await models.User.findOne({ where: { email } });
  return !!existingUser;
}

async function register(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    if (await checkEmailExists(email)) {
      return res.status(400).json({ message: 'Email déjà utilisé' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await models.Otp.create({
      email,
      code: otp,
      expiresAt,
    });

    await sendOtpEmail(email, otp);

    res.status(200).json({ message: 'Code OTP envoyé à votre email. Veuillez le vérifier.' });
  } catch (error) {
    console.error('Erreur lors de l\'envoi de l\'OTP:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function verifyOtp(req, res) {
  try {
    const { email, otp, password } = req.body;

    if (!email || !otp || !password) {
      return res.status(400).json({ message: 'Email, OTP et mot de passe requis' });
    }

    const otpRecord = await models.Otp.findOne({ where: { email, code: otp } });
    if (!otpRecord) {
      return res.status(400).json({ message: 'Code OTP invalide' });
    }

    if (otpRecord.expiresAt < new Date()) {
      await otpRecord.destroy();
      return res.status(400).json({ message: 'Code OTP expiré' });
    }

    await otpRecord.destroy();

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const aesKey = crypto.randomBytes(32);
    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKey = encryptData(aesKey.toString('hex'), passwordKey);
    const encryptedKeyString = JSON.stringify(encryptedKey);

    const keyPair = ECPairFactory(tinysecp).makeRandom({ network });
    const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });
    const privateKey = keyPair.toWIF();
    const encryptedPrivateKey = encryptData(privateKey, passwordKey);
    const encryptedPrivateKeyString = JSON.stringify(encryptedPrivateKey);

    const user = await models.User.create({
      email,
      password: hashedPassword,
      encrypted_key: encryptedKeyString,
      role: 'user',
    });

    const wallet = await models.Wallet.create({
      user_id: user.id,
      address,
      private_key: encryptedPrivateKeyString,
    });

    // Récupérer les UTXOs avec gestion des erreurs
    let utxos = [];
    try {
      const utxoResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${address}?unspentOnly=true`);
      utxos = utxoResponse.data.txrefs || [];
    } catch (apiError) {
      console.warn(`Échec de la récupération des UTXOs pour ${address}:`, apiError.message);
    }

    // Créer les UTXOs uniquement s'il y en a
    if (utxos && utxos.length > 0) {
      for (const utxo of utxos) {
        await models.Utxo.create({
          wallet_id: wallet.wallet_id,
          tx_hash: utxo.tx_hash,
          output_index: utxo.tx_output_n,
          amount: utxo.value,
          used: false,
        });
      }
    } else {
      console.log(`Aucun UTXO trouvé pour l'adresse ${address}. UTXOs seront ajoutés ultérieurement si des fonds sont reçus.`);
    }

    res.status(201).json({
      message: 'Utilisateur créé avec succès. Veuillez vous connecter.',
      bitcoinAddress: address,
    });
  } catch (error) {
    console.error('Erreur lors de la vérification de l\'OTP:', error);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

async function login(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    if (!(await checkEmailExists(email))) {
      return res.status(401).json({ message: 'Email ou mot de passe invalide' });
    }

    const user = await models.User.findOne({ where: { email } });
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Email ou mot de passe invalide' });
    }

    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKeyObject = JSON.parse(user.encrypted_key);
    const aesKeyHex = decryptData(encryptedKeyObject, passwordKey);
    const aesKey = Buffer.from(aesKeyHex, 'hex');

    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64'), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    const accessToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64'), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const wallet = await models.Wallet.findOne({ where: { user_id: user.id } });
    const bitcoinAddress = wallet ? wallet.address : null;

    res.json({ accessToken, refreshToken, bitcoinAddress });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function refreshToken(req, res) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token requis' });
    }

    const blacklisted = await models.BlacklistedToken.findOne({ where: { token: refreshToken } });
    if (blacklisted) {
      return res.status(401).json({ message: 'Refresh token invalide' });
    }

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Refresh token invalide ou expiré' });
    }

    const accessToken = jwt.sign(
      { id: payload.id, email: payload.email, aesKey: payload.aesKey, role: payload.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken });
  } catch (error) {
    console.error('Erreur lors du refresh token:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function logout(req, res) {
  try {
    const { refreshToken, accessToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token requis' });
    }

    let refreshPayload;
    try {
      refreshPayload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ message: 'Refresh token invalide' });
    }

    await models.BlacklistedToken.create({
      token: refreshToken,
      expiresAt: new Date(refreshPayload.exp * 1000),
    });

    if (accessToken) {
      try {
        const accessPayload = jwt.verify(accessToken, process.env.JWT_SECRET);
        await models.BlacklistedToken.create({
          token: accessToken,
          expiresAt: new Date(accessPayload.exp * 1000),
        });
      } catch (error) {
        console.warn('Access token invalide ou expiré, ignoré');
      }
    }

    res.status(200).json({ message: 'Déconnexion réussie' });
  } catch (error) {
    console.error('Erreur lors de la déconnexion:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

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
    const encryptedPrivateKey = encryptData(privateKey, passwordKey);
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
    });

    // Récupérer les UTXOs avec débogage
    let utxos = [];
    console.log('Avant appel API, utxos:', JSON.stringify(utxos));
    try {
      const utxoResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${address}?unspentOnly=true`);
      utxos = utxoResponse.data.txrefs || [];
      console.log('Après appel API, utxos:', JSON.stringify(utxos));
    } catch (apiError) {
      console.warn(`Échec de l'API pour ${address}:`, apiError.message);
    }

    // Créer les UTXOs avec validation stricte
    console.log('Avant boucle, utxos.length:', utxos ? utxos.length : 'null');
    if (utxos && Array.isArray(utxos) && utxos.length > 0) {
      console.log('Entrée dans la boucle, utxos:', JSON.stringify(utxos));
      for (const utxo of utxos) {
        console.log('UTXO à créer:', JSON.stringify(utxo));
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
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

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

const ECPair = ECPairFactory(tinysecp);

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

    const txData = { txId: response.data.tx.hash, amount, toAddress };
    const encryptedTxData = JSON.stringify(encryptData(JSON.stringify(txData), passwordKey));

    await models.Transaction.create({
      wallet_id: wallet.wallet_id,
      senderId: user.id,
      receiverId,
      encrypted_data: encryptedTxData,
      type: 'withdrawal',
      txId: response.data.tx.hash,
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
        txId: response.data.tx.hash,
        status: 'pending',
        confirmations: 0,
      });
    }

    for (const utxo of utxos) {
      await utxo.update({ used: true });
    }

    res.json({ txId: response.data.tx.hash, fee: fee / 100000000 + ' tBTC' });
  } catch (error) {
    console.error('Erreur lors de l\'envoi de la transaction:', error);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

module.exports = { sendBitcoin };
async function getTransactionHistory(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const wallet = await models.Wallet.findOne({ where: { user_id: payload.id } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé' });

    const transactions = await models.Transaction.findAll({
      where: { wallet_id: wallet.wallet_id },
      attributes: ['id', 'type', 'txId', 'status', 'confirmations', 'created_at'],
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
      const encryptedData = JSON.parse(tx.encrypted_data);
      const decryptedData = JSON.parse(decryptData(encryptedData, passwordKey));
      return {
        id: tx.id,
        type: tx.type,
        txId: tx.txId,
        status: tx.status,
        confirmations: tx.confirmations,
        created_at: tx.created_at,
        senderEmail: tx.Sender?.email,
        receiverEmail: tx.Receiver?.email,
        ...decryptedData,
      };
    });

    res.json(decryptedTransactions);
  } catch (error) {
    console.error('Erreur lors de la récupération de l\'historique:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

module.exports = {
  register,
  login,
  verifyOtp,
  refreshToken,
  logout,
  createAdmin,
  listUsers,
  getBalance,
  sendBitcoin,
  getTransactionHistory,
};