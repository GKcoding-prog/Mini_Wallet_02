const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { models } = require('../models');
const { encryptData, decryptData } = require('../services/encryption');
const { sendOtpEmail } = require('../services/email');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { SALT_ROUNDS } = require('./constants'); 

async function enableEmail2FA(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Token invalide ou expiré' });
    }

    const user = await models.User.findByPk(payload.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    const password = req.body.password;
    if (!password) return res.status(400).json({ message: 'Mot de passe requis' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Mot de passe invalide' });

    if (user.email_2fa_enabled) return res.status(400).json({ message: '2FA par email déjà activée' });

    await user.update({ email_2fa_enabled: true });

    res.json({ message: '2FA par email activée avec succès' });
  } catch (error) {
    console.error('Erreur lors de l\'activation de la 2FA par email:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

async function disableEmail2FA(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Token invalide ou expiré' });
    }

    const user = await models.User.findByPk(payload.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    const password = req.body.password;
    if (!password) return res.status(400).json({ message: 'Mot de passe requis' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Mot de passe invalide' });

    if (!user.email_2fa_enabled) return res.status(400).json({ message: '2FA par email non activée' });

    await user.update({ email_2fa_enabled: false });

    res.json({ message: '2FA par email désactivée avec succès' });
  } catch (error) {
    console.error('Erreur lors de la désactivation de la 2FA par email:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}
async function enableTotp2FA(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await models.User.findByPk(payload.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    const password = req.body.password;
    if (!password) return res.status(400).json({ message: 'Mot de passe requis' });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Mot de passe incorrect' });
    }

    const secret = speakeasy.generateSecret({
      name: `WalletApp:${user.email}`,
      issuer: 'WalletApp',
    });

    const encryptedSecret = encryptData(secret.base32, Buffer.from(process.env.SERVER_MASTER_KEY, 'hex'));
    await user.update({
      totp_secret: JSON.stringify(encryptedSecret),
      email_2fa_enabled: true,
    });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url, { width: 300, height: 300 });

    res.json({
      message: '2FA par TOTP activée. Scannez ce QR code avec Google Authenticator (agrandissez-le dans le navigateur). Sauvegardez le secret ci-dessous.',
      qrCodeUrl,
      secret: secret.base32,
    });
  } catch (error) {
    console.error('Erreur lors de l\'activation de la 2FA TOTP:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

module.exports = {
  enableTotp2FA,
};
async function disableTotp2FA(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Token invalide ou expiré' });
    }

    const user = await models.User.findByPk(payload.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    const password = req.body.password;
    if (!password) return res.status(400).json({ message: 'Mot de passe requis' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Mot de passe invalide' });

    if (!user.totp_secret) return res.status(400).json({ message: '2FA par TOTP non activée' });

    await user.update({ totp_secret: null });

    res.json({ message: '2FA par TOTP désactivée avec succès' });
  } catch (error) {
    console.error('Erreur lors de la désactivation de la 2FA par TOTP:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

async function verify2FAEmail(req, res) {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email requis' });

    const user = await models.User.findOne({ where: { email } });
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    if (!user.email_2fa_enabled) return res.status(400).json({ message: '2FA par email non activée pour cet utilisateur' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await models.Otp.create({
      email,
      code: otp,
      expiresAt,
    });

    await sendOtpEmail(email, otp);

    res.status(200).json({ message: 'Code OTP envoyé à votre email pour 2FA.' });
  } catch (error) {
    console.error('Erreur lors de l\'envoi de l\'OTP 2FA:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}
async function verify2FATotp(req, res) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Token Bearer requis' });
    }

    const token = authHeader.split(' ')[1];
    console.debug('Token reçu dans verify2FATotp:', token);
    console.debug('JWT_SECRET utilisé dans verify2FATotp:', process.env.JWT_SECRET);
    const { totpCode } = req.body;
    if (!totpCode) {
      return res.status(400).json({ message: 'Code TOTP requis' });
    }

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
      console.debug('Payload vérifié dans verify2FATotp:', payload);
    } catch (error) {
      console.error('Erreur de vérification du token dans verify2FATotp:', error.message, 'Stack:', error.stack);
      // Tentative de débogage manuel
      const [headerEncoded, payloadEncoded, signature] = token.split('.');
      console.debug('Header décodé:', Buffer.from(headerEncoded, 'base64').toString('utf8'));
      console.debug('Payload décodé:', Buffer.from(payloadEncoded, 'base64').toString('utf8'));
      return res.status(401).json({ message: 'Token invalide ou expiré' });
    }

    const user = await models.User.findByPk(payload.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });
    if (!user.totp_secret) return res.status(400).json({ message: '2FA par TOTP non activée pour cet utilisateur' });

    const masterKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    let secret;
    try {
      const encryptedSecretObject = JSON.parse(user.totp_secret);
      console.debug('Encrypted secret object dans verify2FATotp:', encryptedSecretObject);
      secret = decryptData(encryptedSecretObject, masterKey);
      console.debug('Decrypted secret dans verify2FATotp:', secret);
    } catch (error) {
      console.error('Erreur lors du décryptage du secret TOTP dans verify2FATotp:', error);
      return res.status(400).json({ message: 'Erreur lors du décryptage du secret TOTP' });
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: totpCode,
      window: 1,
    });

    if (!verified) return res.status(400).json({ message: 'Code TOTP invalide' });

    res.json({ message: 'Code TOTP vérifié avec succès' });
  } catch (error) {
    console.error('Erreur lors de la vérification du TOTP dans verify2FATotp:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

module.exports = {
  enableEmail2FA,
  disableEmail2FA,
  enableTotp2FA,
  disableTotp2FA,
  verify2FAEmail,
  verify2FATotp,
};