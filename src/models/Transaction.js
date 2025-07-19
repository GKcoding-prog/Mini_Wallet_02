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
    type: DataTypes.JSON, // { iv, content }
    allowNull: false,
  },
  type: {
    type: DataTypes.ENUM('deposit', 'transfer'),
    allowNull: false,
  },
});

module.exports = Transaction;
