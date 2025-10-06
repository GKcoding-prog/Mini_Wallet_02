const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Wallet = sequelize.define('Wallet', {
  wallet_id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  user_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id',
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
  },
  address: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
  },
  private_key: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  server_encrypted_private_key: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  created_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
}, {
  tableName: 'wallets',
  timestamps: false,
});

Wallet.associate = function (models) {
  Wallet.hasMany(models.Utxo, { foreignKey: 'wallet_id' });
  Wallet.hasMany(models.Transaction, { foreignKey: 'wallet_id' });
};

module.exports = Wallet;