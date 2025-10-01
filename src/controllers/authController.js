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
      { expiresIn: '7d' } // Changé de '1h' à '7d'
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

module.exports = {
  checkEmailExists,
  register,
  verifyOtp,
  login,
  refreshToken,
  logout,
  createAdmin,
};