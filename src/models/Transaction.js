const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Transaction = sequelize.define('Transaction', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  senderId: {
    type: DataTypes.UUID,
    allowNull: true,
  },
  receiverId: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  encrypted_data: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  type: {
    type: DataTypes.ENUM('deposit', 'withdrawal', 'transfer'),
    allowNull: false,
  },
  txId: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  status: {
    type: DataTypes.ENUM('pending', 'confirmed'),
    defaultValue: 'pending',
  },
  confirmations: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  },
});

module.exports = Transaction;