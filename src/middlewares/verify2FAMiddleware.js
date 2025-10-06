const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const { models } = require('../models');
const { decryptData } = require('../services/encryption');

async function verify2FAMiddleware(req, res, next) {
  try {
    const { token, emailOtp, totpCode } = req.body;
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await models.User.findByPk(payload.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });

    if (user.totp_secret) {
      if (!emailOtp && !totpCode) {
        return res.status(400).json({ message: 'Code OTP email ou code TOTP requis pour la 2FA' });
      }

      const passwordKey = crypto.createHash('sha256').update(req.body.password || 'facile').digest();

      if (emailOtp) {
        const otpRecord = await models.Otp.findOne({ where: { email: user.email, code: emailOtp } });
        if (!otpRecord) {
          return res.status(400).json({ message: 'Code OTP email invalide' });
        }
        if (otpRecord.expiresAt < new Date()) {
          await otpRecord.destroy();
          return res.status(400).json({ message: 'Code OTP email expiré' });
        }
        await otpRecord.destroy();
      } else if (totpCode) {
        const encryptedSecretObject = JSON.parse(user.totp_secret);
        const secret = decryptData(encryptedSecretObject, passwordKey);
        const verified = speakeasy.totp.verify({
          secret,
          encoding: 'base32',
          token: totpCode,
          window: 1,
        });
        if (!verified) {
          return res.status(400).json({ message: 'Code TOTP invalide' });
        }
      }
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Erreur lors de la vérification 2FA:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

module.exports = verify2FAMiddleware;