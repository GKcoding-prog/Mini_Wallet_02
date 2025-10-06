const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Transaction = sequelize.define('Transaction', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  wallet_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    field: 'wallet_id'
  },
  senderId: {
    type: DataTypes.INTEGER,
    field: 'senderid'
  },
  receiverId: {
    type: DataTypes.INTEGER,
    field: 'receiverid'
  },
  encrypted_data: {
    type: DataTypes.TEXT,
    field: 'encrypted_data'
  },
  type: {
    type: DataTypes.STRING
  },
  txid: {
    type: DataTypes.STRING
  },
  status: {
    type: DataTypes.STRING
  },
  confirmations: {
    type: DataTypes.INTEGER
  },
  created_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
    field: 'created_at'
  }
}, {
  tableName: 'transactions',
  timestamps: false
});

module.exports = Transaction;
