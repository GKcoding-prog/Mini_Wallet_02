const { models } = require('../models');
const jwt = require('jsonwebtoken');

const FALLBACK_ENABLED = process.env.API_KEY_FALLBACK_ENABLED === 'true';
const FALLBACK_KEY = process.env.API_KEY_FALLBACK_KEY || '';
const FALLBACK_LOCALHOST_ONLY = (process.env.API_KEY_FALLBACK_LOCALHOST_ONLY || 'true') !== 'false';

function extractApiKey(req) {
  // Primary: x-api-key header
  let key = req.headers['x-api-key'];
  if (key && typeof key === 'string') return key.trim();

  // Fallback: Authorization: ApiKey <key>
  const auth = req.headers.authorization;
  if (auth && typeof auth === 'string') {
    const match = auth.match(/^ApiKey\s+(.+)$/i);
    if (match && match[1]) return match[1].trim();
  }

  // Also accept api_key via query or body (for server-to-server or limited clients)
  if (req.query && typeof req.query.api_key === 'string' && req.query.api_key.trim()) {
    return req.query.api_key.trim();
  }
  if (req.body && typeof req.body.api_key === 'string' && req.body.api_key.trim()) {
    return req.body.api_key.trim();
  }
  return null;
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) {
    return fwd.split(',')[0].trim();
  }
  return (req.ip || req.connection?.remoteAddress || '') + '';
}

async function apiKeyAuth(req, res, next) {
  const apiKey = extractApiKey(req);
  if (!apiKey) {
    // Alternative 1: Autoriser un JWT Bearer (même logique que les autres endpoints)
    const auth = req.headers.authorization;
    const bearerMatch = auth && auth.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch) {
      try {
        const token = bearerMatch[1];
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        const user = await models.User.findByPk(payload.id);
        if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });
        req.user = user;
        return next();
      } catch (e) {
        // Si JWT invalide, on continue vers la logique de fallback/clé API requise
      }
    }

    // Fallback optionnel (config) — utile pour des appels locaux automatisés
    const remote = getClientIp(req);
    const isLocal = /(^127\.0\.0\.1$)|(^::1$)/.test(remote);
    const ipWhitelistRaw = process.env.API_KEY_FALLBACK_IP_WHITELIST || '';
    const ipWhitelist = new Set(ipWhitelistRaw.split(',').map(s => s.trim()).filter(Boolean));
    const ipAllowed = isLocal || (ipWhitelist.size > 0 && ipWhitelist.has(remote));
    if (FALLBACK_ENABLED && FALLBACK_KEY) {
      if (!FALLBACK_LOCALHOST_ONLY ? true : isLocal || ipAllowed) {
        try {
          const keyRecord = await models.ApiKey.findOne({ where: { key: FALLBACK_KEY } });
          if (keyRecord) {
            const user = await models.User.findByPk(keyRecord.user_id);
            if (user) {
              req.user = user;
              return next();
            }
          }
        } catch (e) {
          // ignore et on retombera sur 401 ci-dessous
        }
      }
    }

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