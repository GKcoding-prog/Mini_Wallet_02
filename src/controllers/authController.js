const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { encryptData, decryptData } = require('../services/encryption');

const SALT_ROUNDS = 10;

async function register(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'Email déjà utilisé' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Générer clé AES aléatoire (32 bytes)
    const aesKey = crypto.randomBytes(32);

    // Chiffrer la clé AES avec le hash du mot de passe
    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKey = encryptData(aesKey.toString('hex'), passwordKey);

    // Convertir l'objet encryptedKey en chaîne JSON
    const encryptedKeyString = JSON.stringify(encryptedKey);

    const newUser = await User.create({
      email,
      password: hashedPassword,
      encrypted_key: encryptedKeyString, // Stocker la chaîne JSON
      balance: 0,
    });

    res.status(201).json({ message: 'Utilisateur créé avec succès' });
  } catch (error) {
    console.error('Erreur lors de l\'inscription:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function login(req, res) {
  try {
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

    // Déchiffrer la clé AES stockée
    const passwordKey = crypto.createHash('sha256').update(password).digest();
    const encryptedKeyObject = JSON.parse(user.encrypted_key); // Parser la chaîne JSON
    const aesKeyHex = decryptData(encryptedKeyObject, passwordKey);
    const aesKey = Buffer.from(aesKeyHex, 'hex');

    // Générer JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, aesKey: aesKey.toString('base64') },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

module.exports = { register, login };