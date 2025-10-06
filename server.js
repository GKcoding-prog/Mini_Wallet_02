require('dotenv').config({ debug: false });
const express = require('express');
const multer = require('multer');
const sequelize = require('./src/config/database');
const authRoutes = require('./src/routes/authRoutes');
const walletRoutes = require('./src/routes/walletRoutes');
const cron = require('node-cron');
const updateConfirmations = require('./src/jobs/updateConfirmations');

// Charger les modèles manuellement
const { Otp, BlacklistedToken, ApiKey, Wallet, User, Transaction, Utxo } = require('./src/models');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(multer().none());

app.use('/api/auth', authRoutes);
app.use('/api/wallet', walletRoutes);

// Planifier la mise à jour des confirmations toutes les 5 minutes
cron.schedule('*/5 * * * *', updateConfirmations);

const PORT = process.env.PORT || 3000;

// Synchronisation sans forcer les contraintes NOT NULL immédiatement
sequelize.sync().then(() => {
  console.log('✅ Base de données synchronisée');
  app.listen(PORT, () => console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`));
}).catch(error => {
  console.error('Erreur lors de la synchronisation de la base de données:', error);
  // Ajouter une colonne senderId sans NOT NULL initialement si besoin
  sequelize.getQueryInterface().addColumn('transactions', 'senderId', {
    type: sequelize.DataTypes.UUID,
    references: {
      model: 'users',
      key: 'id'
    }
  }).then(() => {
    console.log('✅ Colonne senderId ajoutée sans contrainte NOT NULL');
    app.listen(PORT, () => console.log(`🚀 Serveur lancé sur http://localhost:${PORT} après correction`));
  }).catch(err => {
    console.error('Erreur lors de l\'ajout de senderId:', err);
    app.listen(PORT, () => console.log(`🚀 Serveur lancé sur http://localhost:${PORT} malgré une erreur`));
  });
});