require('dotenv').config();
const express = require('express');
const multer = require('multer');
const app = express();
const sequelize = require('./config/database');
const authRoutes = require('./routes/authRoutes');
const walletRoutes = require('./routes/walletRoutes');
require('./models/Otp');
require('./models/BlacklistedToken');

app.use(express.json()); // Parser JSON
app.use(express.urlencoded({ extended: true })); // Parser formulaires urlencoded
app.use(multer().none()); // Parser formulaires multipart sans fichiers

app.use('/api/auth', authRoutes);
app.use('/api/wallet', walletRoutes);

const PORT = process.env.PORT || 3000;

sequelize.sync({ alter: true }).then(() => {
  console.log('✅ Base de données synchronisée');
  app.listen(PORT, () => console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`));
});