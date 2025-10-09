const jwt = require('jsonwebtoken');
const { models } = require('../models');
require('dotenv').config();

async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Token manquant' });

  const token = authHeader.split(' ')[1] || authHeader;

  const blacklisted = await models.BlacklistedToken.findOne({ where: { token } });
  if (blacklisted) return res.status(401).json({ message: 'Token invalide' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await models.User.findByPk(decoded.id);
    if (!user) return res.status(401).json({ message: 'Utilisateur non trouvé' });

    req.user = { id: user.id, email: user.email, aesKey: decoded.aesKey };
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Token invalide' });
  }
}

module.exports = authenticate;