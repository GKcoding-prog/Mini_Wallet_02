const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const BlacklistedToken = sequelize.define('BlacklistedToken', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  token: {
    type: DataTypes.TEXT,
    allowNull: false,
    unique: true,
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false,
  // Align with existing Postgres column name (lowercase) to avoid quoted identifier mismatch
  field: 'expiresat',
  },
}, {
  tableName: 'blacklisted_tokens',
  timestamps: false,
});

module.exports = BlacklistedToken;