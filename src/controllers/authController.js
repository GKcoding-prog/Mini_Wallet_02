const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const BitcoinClient = require('bitcoin-core');
const User = require('../models/User');
const Otp = require('../models/Otp');
const BlacklistedToken = require('../models/BlacklistedToken');
const { encryptData, decryptData } = require('../services/encryption');
const { sendOtpEmail } = require('../services/email');

const SALT_ROUNDS = 10;

const bitcoinClient = new BitcoinClient({
  network: 'testnet',
  host: 'localhost',
  port: 18332,
  username: process.env.BITCOIN_RPC_USER,
  password: process.env.BITCOIN_RPC_PASSWORD,
});

async function register(req, res) {
  try {
    console.log('req.body (register):', req.body);
    console.log('Headers (register):', req.headers);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'Email déjà utilisé' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await Otp.create({
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
    console.log('req.body (verifyOtp):', req.body);
    console.log('Headers (verifyOtp):', req.headers);
    const { email, otp, password } = req.body;

    if (!email || !otp || !password) {
      return res.status(400).json({ message: 'Email, OTP et mot de passe requis' });
    }

    const otpRecord = await Otp.findOne({ where: { email, code: otp } });
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

    const bitcoinAddress = await bitcoinClient.getNewAddress();
    const privateKey = await bitcoinClient.dumpPrivKey(bitcoinAddress);
    const encryptedPrivateKey = encryptData(privateKey, passwordKey);
    const encryptedPrivateKeyString = JSON.stringify(encryptedPrivateKey);

    await bitcoinClient.importAddress(bitcoinAddress, '', false);

    const user = await User.create({
      email,
      password: hashedPassword,
      encrypted_key: encryptedKeyString,
      balance: 0,
      bitcoinAddress,
      encrypted_private_key: encryptedPrivateKeyString,
    });

    res.status(201).json({
      message: 'Utilisateur créé avec succès. Veuillez vous connecter.',
      bitcoinAddress: user.bitcoinAddress,
    });
  } catch (error) {
    console.error('Erreur lors de la vérification de l\'OTP:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function login(req, res) {
  try {
    console.log('req.body (login):', req.body);
    console.log('Headers (login):', req.headers);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: 'Email ou mot de passe invalide' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Email ou mot de passe invalide' });
    }

    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKeyObject = JSON.parse(user.encrypted_key);
    const aesKeyHex = decryptData(encryptedKeyObject, passwordKey);
    const aesKey = Buffer.from(aesKeyHex, 'hex');

    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64') },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    const accessToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64') },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken, refreshToken, bitcoinAddress: user.bitcoinAddress });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function refreshToken(req, res) {
  try {
    console.log('req.body (refreshToken):', req.body);
    console.log('Headers (refreshToken):', req.headers);
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token requis' });
    }

    const blacklisted = await BlacklistedToken.findOne({ where: { token: refreshToken } });
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
      { id: payload.id, email: payload.email, aesKey: payload.aesKey },
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
    console.log('req.body (logout):', req.body);
    console.log('Headers (logout):', req.headers);
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

    await BlacklistedToken.create({
      token: refreshToken,
      expiresAt: new Date(refreshPayload.exp * 1000),
    });

    if (accessToken) {
      try {
        const accessPayload = jwt.verify(accessToken, process.env.JWT_SECRET);
        await BlacklistedToken.create({
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

module.exports = { register, login, verifyOtp, refreshToken, logout };