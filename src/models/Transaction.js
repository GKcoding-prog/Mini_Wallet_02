// models/Transaction.js
const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Transaction = sequelize.define('Transaction', {
  id: {
    type: DataTypes.UUID,
    primaryKey: true,
    defaultValue: DataTypes.UUIDV4,
  },
  wallet_id: {
    type: DataTypes.UUID,
    allowNull: false,
    field: 'wallet_id',
    references: {
      model: 'wallets',
      key: 'wallet_id',
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
  },
  senderId: {
    type: DataTypes.UUID,
    field: 'senderid',
    references: {
      model: 'users',
      key: 'id',
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
  },
  receiverId: {
    type: DataTypes.UUID,
    field: 'receiverid',
    references: {
      model: 'users',
      key: 'id',
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
  },
  encrypted_data: {
    type: DataTypes.TEXT,
    field: 'encrypted_data',
    allowNull: false,
  },
  type: {
    type: DataTypes.ENUM('deposit', 'withdrawal', 'transfer'),
    allowNull: false,
  },
  txid: {
    type: DataTypes.STRING(64),
    unique: true,
    field: 'txid',
  },
  status: {
    type: DataTypes.ENUM('pending', 'confirmed', 'failed'),
    allowNull: false,
    defaultValue: 'pending',
  },
  confirmations: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
  },
  created_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
    field: 'created_at',
  },
}, {
  tableName: 'transactions',
  timestamps: false,
});

Transaction.associate = function (models) {
  Transaction.belongsTo(models.User, { as: 'Sender', foreignKey: 'senderid' });
  Transaction.belongsTo(models.User, { as: 'Receiver', foreignKey: 'receiverid' });
  Transaction.belongsTo(models.Wallet, { foreignKey: 'wallet_id' });
};

module.exports = Transaction;