// src/models/index.js
const sequelize = require('../config/database'); // On récupère ta connexion PostgreSQL
const { DataTypes } = require('sequelize');

const db = {};
db.sequelize = sequelize;
db.Sequelize = sequelize.Sequelize;

// Exemple: importer les modèles
// db.User = require('./user')(sequelize, DataTypes);
// db.Wallet = require('./wallet')(sequelize, DataTypes);

module.exports = db;
