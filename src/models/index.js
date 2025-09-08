const sequelize = require('../config/database');
const userModel = require('./User');
const walletModel = require('./Wallet');
const transactionModel = require('./Transaction');
const utxoModel = require('./Utxo');
const otpModel = require('./Otp');
const blacklistedTokenModel = require('./BlacklistedToken');

const models = {
  User: userModel,
  Wallet: walletModel,
  Transaction: transactionModel,
  Utxo: utxoModel,
  Otp: otpModel,
  BlacklistedToken: blacklistedTokenModel,
};

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