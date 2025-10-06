function adminSecret(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ message: 'Accès interdit : secret admin invalide' });
  }
  next();
}

module.exports = adminSecret;