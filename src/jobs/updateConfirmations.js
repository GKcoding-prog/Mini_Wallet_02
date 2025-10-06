const axios = require('axios');
const { models } = require('../models');

async function updateConfirmations() {
  try {
    const transactions = await models.Transaction.findAll({
      where: { status: 'pending' },
    });

    for (const tx of transactions) {
      try {
        const response = await axios.get(
          `https://api.blockcypher.com/v1/btc/test3/txs/${tx.txid}`
        );
        const confirmations = response.data.confirmations || 0;
        if (confirmations >= 6) {
          await tx.update({ status: 'confirmed', confirmations });
        } else {
          await tx.update({ confirmations });
        }
      } catch (error) {
        console.error(`Erreur lors de la mise à jour de la transaction ${tx.txid}:`, error.message);
      }
    }
    console.log('Mise à jour des confirmations terminée.');
  } catch (error) {
    console.error('Erreur dans updateConfirmations:', error);
  }
}

module.exports = updateConfirmations;