require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');
const { encryptData, decryptData } = require('./src/services/encryption');
const crypto = require('crypto');

// Initialisation de Sequelize
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'postgres',
    logging: false,
  }
);

// Définir les modèles
const User = sequelize.define('User', {
  email: DataTypes.STRING,
}, { timestamps: false });

const Wallet = sequelize.define('Wallet', {
  user_id: DataTypes.INTEGER,
  private_key: DataTypes.JSON,
  server_encrypted_private_key: DataTypes.TEXT,
}, { timestamps: false });

console.log('SERVER_MASTER_KEY:', process.env.SERVER_MASTER_KEY); // Débogage

async function migratePrivateKeys() {
  try {
    if (!process.env.SERVER_MASTER_KEY) {
      throw new Error('SERVER_MASTER_KEY is not defined in .env');
    }

    await sequelize.authenticate();
    console.log('Connexion à la base de données établie.');

    // Synchroniser les modèles (optionnel, si pas déjà fait)
    await sequelize.sync();

    const users = [
      { email: 'pacmugisha0@gmail.com', password: 'facile' },
      { email: 'voirtonfilm@gmail.com', password: 'facile' },
    ];

    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');

    for (const user of users) {
      const userRecord = await User.findOne({ where: { email: user.email } });
      if (!userRecord) {
        console.log(`Utilisateur non trouvé pour ${user.email}`);
        continue;
      }

      const wallet = await Wallet.findOne({ where: { user_id: userRecord.id } });
      if (!wallet) {
        console.log(`Portefeuille non trouvé pour ${user.email}`);
        continue;
      }

      const passwordKey = crypto.createHash('sha256').update(user.password).digest();
      const encryptedPrivateKeyObject = JSON.parse(wallet.private_key);
      let privateKey;
      try {
        privateKey = decryptData(encryptedPrivateKeyObject, passwordKey);
      } catch (error) {
        console.error(`Échec du déchiffrement pour ${user.email}:`, error.message);
        continue;
      }

      const newEncryptedPrivateKey = encryptData(privateKey, serverKey);
      const newEncryptedPrivateKeyString = JSON.stringify(newEncryptedPrivateKey);

      await wallet.update({ server_encrypted_private_key: newEncryptedPrivateKeyString });
      console.log(`Clé privée migrée pour ${user.email}`);
    }

    console.log('Migration terminée.');
    process.exit(0);
  } catch (error) {
    console.error('Erreur lors de la migration:', error);
    process.exit(1);
  }
}

migratePrivateKeys();