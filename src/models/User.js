const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  encrypted_key: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  balance: {
    type: DataTypes.DECIMAL(15, 8),
    defaultValue: 0,
  },
  bitcoinAddress: {
    type: DataTypes.STRING,
    allowNull: true,
    unique: true,
  },
  encrypted_private_key: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
});

module.exports = User;