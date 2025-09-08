const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const Wallet = require('./Wallet');

const Utxo = sequelize.define('Utxo', {
  utxo_id: {
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
  tx_hash: {
    type: DataTypes.STRING(64),
    allowNull: false,
  },
  output_index: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  amount: {
    type: DataTypes.BIGINT,
    allowNull: false,
  },
  used: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
}, {
  tableName: 'utxos',
  timestamps: false,
});

Utxo.associate = function (models) {
  Utxo.belongsTo(models.Wallet, { foreignKey: 'wallet_id' });
};

module.exports = Utxo;