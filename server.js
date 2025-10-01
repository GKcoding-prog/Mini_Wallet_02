require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sequelize = require('./src/config/database');
const authRoutes = require('./src/routes/authRoutes');
const walletRoutes = require('./src/routes/walletRoutes');

// Charger les modèles
require('./src/models/Otp');
require('./src/models/BlacklistedToken');
require('./src/models/User');
require('./src/models/Wallet');
require('./src/models/Utxo');
require('./src/models/Transaction');

// Charger les jobs
require('./src/jobs/updateConfirmations');

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(multer().none());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/wallet', walletRoutes);

// Gestion des erreurs globales
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err.stack);
  res.status(500).json({ message: 'Erreur serveur' });
});

const PORT = process.env.PORT || 3000;

// Synchronisation de la base de données et démarrage du serveur
sequelize
 // Désactiver alter pour éviter les modifications automatiques
  .sync({ alter: false })
  .then(() => {
    console.log('✅ Base de données synchronisée');
    app.listen(PORT, () => {
      console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Erreur lors de la synchronisation de la base de données:', error);
    // Arrêter le processus en cas d'erreur critique
    process.exit(1); 
  });