const adminSecret = (req, res, next) => {
  const secret = req.headers['admin-secret'];
  if (secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ message: 'Accès refusé: Clé secrète invalide' });
  }
  next();
};

module.exports = adminSecret;