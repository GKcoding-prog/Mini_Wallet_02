const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Transaction = sequelize.define('Transaction', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  wallet_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'wallets',
      key: 'wallet_id',
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
  },
  senderId: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
    field: 'senderid', // Mappe senderId à la colonne senderid
  },
  receiverId: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id',
    },
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE',
    field: 'receiverid', // Mappe receiverId à la colonne receiverid
  },
  encrypted_data: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  type: {
    type: DataTypes.ENUM('deposit', 'withdrawal'),
    allowNull: false,
  },
  txId: {
    type: DataTypes.STRING(64),
    allowNull: true,
  },
  status: {
    type: DataTypes.ENUM('pending', 'confirmed', 'failed'),
    allowNull: false,
    defaultValue: 'pending',
  },
  confirmations: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  },
  created_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
}, {
  tableName: 'transactions',
  timestamps: false,
});

// Optionnel : méthode associate
Transaction.associate = function (models) {
  Transaction.belongsTo(models.User, { as: 'Sender', foreignKey: 'senderId' });
  Transaction.belongsTo(models.User, { as: 'Receiver', foreignKey: 'receiverId' });
};

module.exports = Transaction;