const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { models } = require('../models');
const { decryptData } = require('../services/encryption');
const speakeasy = require('speakeasy');
const { checkEmailExists } = require('./utils');
const { SALT_ROUNDS } = require('./constants');
const { sendOtpEmail } = require('../services/email');
const { createWallet, fetchAndSaveUtxos } = require('./walletUtils');

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
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
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
    const user = await models.User.create({
      email,
      password: hashedPassword,
      role: 'user',
    });

    const { address } = await createWallet(user, password);
    await fetchAndSaveUtxos(user.wallet, address);

    res.status(201).json({
      message: 'Utilisateur créé avec succès. Veuillez vous connecter.',
      bitcoinAddress: address,
    });
  } catch (error) {
    console.error('Erreur lors de la vérification de l\'OTP:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

async function login(req, res) {
  try {
    const { email, password, emailOtp, totpCode } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    const user = await models.User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: 'Email ou mot de passe invalide' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Email ou mot de passe invalide' });
    }

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET non défini');
      return res.status(500).json({ message: 'Configuration serveur incorrecte' });
    }

    // Gestion de la 2FA
    const requires2FA = user.email_2fa_enabled || user.totp_secret;
    if (requires2FA && !emailOtp && !totpCode) {
      return res.status(400).json({ message: 'Code OTP email ou code TOTP requis pour la 2FA' });
    }

    const passwordKey = crypto.createHash('sha256').update(password).digest();

    if (emailOtp) {
      if (!user.email_2fa_enabled) return res.status(400).json({ message: '2FA par email non activée pour cet utilisateur' });
      const otpRecord = await models.Otp.findOne({ where: { email, code: emailOtp } });
      if (!otpRecord) {
        return res.status(400).json({ message: 'Code OTP email invalide' });
      }
      if (otpRecord.expiresAt < new Date()) {
        await otpRecord.destroy();
        return res.status(400).json({ message: 'Code OTP email expiré' });
      }
      await otpRecord.destroy();
    }

    if (totpCode) {
      if (!user.totp_secret) return res.status(400).json({ message: '2FA par TOTP non activée pour cet utilisateur' });
      try {
        const encryptedSecretObject = JSON.parse(user.totp_secret);
        console.debug('Encrypted secret object:', encryptedSecretObject);
        const masterKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
        const secret = decryptData(encryptedSecretObject, masterKey);
        console.debug('Decrypted secret:', secret);
        const verified = speakeasy.totp.verify({
          secret,
          encoding: 'base32',
          token: totpCode,
          window: 1,
        });
        if (!verified) {
          return res.status(400).json({ message: 'Code TOTP invalide' });
        }
      } catch (error) {
        console.error('Erreur lors de la vérification TOTP:', error);
        return res.status(400).json({ message: `Erreur lors de la vérification du code TOTP: ${error.message}` });
      }
    }

    if (!requires2FA && (emailOtp || totpCode)) {
      return res.status(400).json({ message: '2FA non activée pour cet utilisateur. Aucun code OTP ou TOTP requis.' });
    }

    // Décrypter la clé AES
    let aesKey;
    try {
      const encryptedKeyObject = JSON.parse(user.encrypted_key);
      const aesKeyHex = decryptData(encryptedKeyObject, passwordKey);
      aesKey = Buffer.from(aesKeyHex, 'hex');
    } catch (error) {
      console.error('Erreur lors du décryptage de la clé AES:', error);
      return res.status(500).json({ message: 'Erreur lors du décryptage des données utilisateur' });
    }

    console.debug('JWT_SECRET utilisé dans login:', process.env.JWT_SECRET); // Modification ajoutée ici

    // Générer les tokens
    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64'), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    const accessToken = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64'), role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' } // Ajuste à '15d' si tu l'as modifié localement
    );

    const wallet = await models.Wallet.findOne({ where: { user_id: user.id } });
    const bitcoinAddress = wallet ? wallet.address : null;

    res.json({ accessToken, refreshToken, bitcoinAddress });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
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

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET non défini');
      return res.status(500).json({ message: 'Configuration serveur incorrecte' });
    }

    const accessToken = jwt.sign(
      { id: payload.id, email: payload.email, aesKey: payload.aesKey, role: payload.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ accessToken });
  } catch (error) {
    console.error('Erreur lors du refresh token:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
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
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

module.exports = {
  register,
  verifyOtp,
  login,
  refreshToken,
  logout,
};