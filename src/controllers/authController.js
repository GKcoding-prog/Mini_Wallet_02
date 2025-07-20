const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const Otp = require('../models/Otp');
const BlacklistedToken = require('../models/BlacklistedToken');
const { encryptData, decryptData } = require('../services/encryption');
const { sendOtpEmail } = require('../services/email');

const SALT_ROUNDS = 10;

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

    // Générer un OTP de 6 chiffres
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // Expire dans 5 minutes

    // Stocker l'OTP dans la base
    await Otp.create({
      email,
      code: otp,
      expiresAt,
    });

    // Envoyer l'OTP par email
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

    // Supprimer l'OTP après vérification
    await otpRecord.destroy();

    // Créer l'utilisateur
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Générer clé AES aléatoire (32 bytes)
    const aesKey = crypto.randomBytes(32);
    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKey = encryptData(aesKey.toString('hex'), passwordKey);
    const encryptedKeyString = JSON.stringify(encryptedKey);

    await User.create({
      email,
      password: hashedPassword,
      encrypted_key: encryptedKeyString,
      balance: 0,
    });

    res.status(201).json({ message: 'Utilisateur créé avec succès. Veuillez vous connecter.' });
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

    // Générer un refresh token (30 jours)
    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64') },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Générer un access token (1 heure)
    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken, refreshToken });
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

    // Vérifier si le refresh token est blacklisté
    const blacklisted = await BlacklistedToken.findOne({ where: { token: refreshToken } });
    if (blacklisted) {
      return res.status(401).json({ message: 'Refresh token invalide' });
    }

    // Vérifier et décoder le refresh token
    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Refresh token invalide ou expiré' });
    }

    // Générer un nouvel access token (1 heure)
    const accessToken = jwt.sign(
      { id: payload.id, email: payload.email },
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
    console.log('req.body (logout):', req.body); // Log pour déboguer
    console.log('Headers (logout):', req.headers); // Log pour vérifier Content-Type
    const { refreshToken, accessToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token requis' });
    }

    // Vérifier et décoder le refresh token pour obtenir l'expiration
    let refreshPayload;
    try {
      refreshPayload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ message: 'Refresh token invalide' });
    }

    // Ajouter le refresh token à la liste noire
    await BlacklistedToken.create({
      token: refreshToken,
      expiresAt: new Date(refreshPayload.exp * 1000),
    });

    // Si un access token est fourni, l'ajouter à la liste noire
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