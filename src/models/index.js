// src/models/index.js
const sequelize = require('../config/database');
const User = require('./User');
const Wallet = require('./Wallet');
const Transaction = require('./Transaction');
const Utxo = require('./Utxo');
const Otp = require('./Otp');
const BlacklistedToken = require('./BlacklistedToken');

const models = {
  User,
  Wallet,
  Transaction,
  Utxo,
  Otp,
  BlacklistedToken,
};

// Appeler les méthodes associate des modèles
Object.values(models).forEach(model => {
  if (model.associate) {
    model.associate(models);
  }
});

// Synchroniser la base de données
sequelize.sync({ force: false }).catch(err => {
  console.error('Erreur lors de la synchronisation de la base de données :', err);
});

module.exports = { sequelize, models };