const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const BlacklistedToken = sequelize.define('BlacklistedToken', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  token: {
    type: DataTypes.TEXT,
    allowNull: false,
    unique: true,
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false,
  },
}, {
  tableName: 'blacklisted_tokens',
  timestamps: false,
});

module.exports = BlacklistedToken;