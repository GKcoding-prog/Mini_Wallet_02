const cron = require('node-cron');
const axios = require('axios');
const { models } = require('../models');

cron.schedule('*/10 * * * *', async () => {
  try {
    console.log('Début synchronisation cron ');

    // Mettre à jour les confirmations des transactions
    const transactions = await models.Transaction.findAll({ where: { status: 'pending' } });
    for (const tx of transactions) {
      if (!tx.txid) { 
        console.warn(`Transaction ${tx.id} n'a pas de txid valide, skipping (peut-être un dépôt en attente)`);
        continue;
      }
      try {
        const response = await axios.get(`https://api.blockcypher.com/v1/btc/test3/txs/${tx.txid}`); // Changé txId à txid
        const confirmations = response.data.confirmations || 0;
        await tx.update({
          confirmations,
          status: confirmations >= 6 ? 'confirmed' : 'pending',
        });
        console.log(`Transaction ${tx.txid} mise à jour: ${confirmations} confirmations, statut: ${tx.status}`);
      } catch (apiError) {
        console.error(`Erreur API pour ${tx.txid}:`, apiError.message);
      }
    }

    // Synchroniser les UTXOs pour toutes les adresses des wallets
    const wallets = await models.Wallet.findAll();
    for (const wallet of wallets) {
      console.log(`Synchronisation UTXOs pour ${wallet.address} (wallet_id: ${wallet.wallet_id})`);
      const utxoResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/addrs/${wallet.address}?unspentOnly=true`);
      const utxos = utxoResponse.data.txrefs || [];

      for (const utxo of utxos) {
        if (!utxo.tx_hash || !utxo.tx_output_n || !utxo.value) {
          console.error(`UTXO invalide ignoré pour ${wallet.address}:`, JSON.stringify(utxo));
          continue;
        }

        const existingUtxo = await models.Utxo.findOne({
          where: { tx_hash: utxo.tx_hash, output_index: utxo.tx_output_n }
        });

        if (!existingUtxo) {
          await models.Utxo.create({
            wallet_id: wallet.wallet_id,
            tx_hash: utxo.tx_hash,
            output_index: utxo.tx_output_n,
            amount: utxo.value,
            used: false,
          });
          console.log(`UTXO créé pour ${wallet.address}: ${utxo.tx_hash} (montant: ${utxo.value})`);
        } else {
          console.log(`UTXO déjà existant pour ${wallet.address}: ${utxo.tx_hash}`);
        }
      }

      const totalBalance = utxos.reduce((sum, utxo) => sum + utxo.value, 0);
      console.log(`Solde total pour ${wallet.address}: ${totalBalance} satoshis (${totalBalance / 100000000} tBTC)`);
    }

    console.log('Fin synchronisation cron');
  } catch (error) {
    console.error('Erreur globale lors de la synchronisation:', error.message);
  }
});

console.log('Cron job de synchronisation lancé (toutes les 10 min)');