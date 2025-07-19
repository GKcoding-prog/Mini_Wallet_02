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
    unique: true,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  encrypted_key: {
    type: DataTypes.TEXT, // Revenir à TEXT
    allowNull: false,
  },
  balance: {
    type: DataTypes.DECIMAL,
    defaultValue: 0,
  },
});

module.exports = User;