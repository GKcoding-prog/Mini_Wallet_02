require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sequelize = require('./src/config/database');
const authRoutes = require('./src/routes/authRoutes');
const walletRoutes = require('./src/routes/walletRoutes');
require('./src/models/Otp');
require('./src/models/BlacklistedToken');
require('./src/jobs/updateConfirmations');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(multer().none());

app.use('/api/auth', authRoutes);
app.use('/api/wallet', walletRoutes);

const PORT = process.env.PORT || 3000;

// Désactiver alter: true après initialisation manuelle
sequelize.sync().then(() => {
  console.log('✅ Base de données synchronisée');
  app.listen(PORT, () => console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`));
}).catch(error => {
  console.error('Erreur lors de la synchronisation de la base de données:', error);
});