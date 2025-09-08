const cron = require('node-cron');
const axios = require('axios');
const { models } = require('../models');

cron.schedule('*/10 * * * *', async () => {
  try {
    const transactions = await models.Transaction.findAll({ where: { status: 'pending' } });
    for (const tx of transactions) {
      const response = await axios.get(`https://api.blockcypher.com/v1/btc/test3/txs/${tx.txId}`);
      const confirmations = response.data.confirmations || 0;
      await tx.update({
        confirmations,
        status: confirmations >= 6 ? 'confirmed' : 'pending',
      });
    }
  } catch (error) {
    console.error('Erreur lors de la mise à jour des confirmations:', error);
  }
});