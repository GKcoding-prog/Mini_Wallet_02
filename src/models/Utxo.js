const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Utxo = sequelize.define('Utxo', {
  utxo_id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
    field: 'utxo_id'
  },
  wallet_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    field: 'wallet_id'
  },
  tx_hash: {
    type: DataTypes.STRING,
    allowNull: false,
    field: 'tx_hash'
  },
  output_index: {
    type: DataTypes.INTEGER,
    allowNull: false,
    field: 'output_index'
  },
  amount: {
    type: DataTypes.FLOAT,
    allowNull: false,
    field: 'amount'
  },
  used: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    field: 'used'
  }
}, {
  tableName: 'utxos',
  timestamps: false
});

module.exports = Utxo;
