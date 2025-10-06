const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { models } = require('../models');

async function generateApiKey(req, res) {
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

    const apiKey = crypto.randomBytes(32).toString('hex');

    await models.ApiKey.create({
      key: apiKey,
      user_id: user.id,
      description: req.body.description || 'Clé API pour service externe',
    });

    res.json({ apiKey, message: 'Clé API générée avec succès' });
  } catch (error) {
    console.error('Erreur lors de la génération de la clé API:', error);
    res.status(500).json({ message: `Erreur serveur: ${error.message}` });
  }
}

module.exports = { generateApiKey };