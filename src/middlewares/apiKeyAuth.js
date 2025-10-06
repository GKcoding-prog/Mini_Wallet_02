const { models } = require('../models');

async function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ message: 'Clé API requise' });
  }

  try {
    const keyRecord = await models.ApiKey.findOne({ where: { key: apiKey } });
    if (!keyRecord) {
      return res.status(401).json({ message: 'Clé API invalide' });
    }

    const user = await models.User.findByPk(keyRecord.user_id);
    if (!user) {
      return res.status(404).json({ message: 'Utilisateur associé à la clé API non trouvé' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Erreur lors de la vérification de la clé API:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

module.exports = apiKeyAuth;