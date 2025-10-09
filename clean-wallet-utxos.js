// Script pour nettoyer les UTXOs invalides après régénération des wallets
// Supprime tous les UTXOs qui ne correspondent pas à l'adresse actuelle du wallet
// À lancer avec: node clean-wallet-utxos.js

require('dotenv').config();
const { models } = require('./src/models');

async function cleanWalletUtxos() {
  const wallets = await models.Wallet.findAll();
  let deleted = 0;

  for (const wallet of wallets) {
    // Récupère tous les UTXOs du wallet
    const utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id } });
    for (const utxo of utxos) {
      // Vérifie si le champ address existe et supprime si différent de l'adresse actuelle
      if (utxo.address && utxo.address !== wallet.address) {
        await utxo.destroy();
        deleted++;
        console.log(`UTXO ${utxo.tx_hash}:${utxo.output_index} supprimé (adresse différente)`);
      }
      // Si le champ address n'existe pas, on vérifie via BlockCypher
      else if (!utxo.address) {
        // On vérifie l'adresse de sortie via l'API BlockCypher
        try {
          const axios = require('axios');
          const txResponse = await axios.get(`https://api.blockcypher.com/v1/btc/test3/txs/${utxo.tx_hash}`);
          const output = txResponse.data.outputs[utxo.output_index];
          if (output && output.addresses && !output.addresses.includes(wallet.address)) {
            await utxo.destroy();
            deleted++;
            console.log(`UTXO ${utxo.tx_hash}:${utxo.output_index} supprimé (adresse différente via API)`);
          }
        } catch (e) {
          console.log(`Erreur lors de la vérification de l'UTXO ${utxo.tx_hash}:${utxo.output_index} : ${e.message}`);
        }
      }
    }
  }
  console.log(`Nettoyage terminé. ${deleted} anciens UTXOs supprimés.`);
}

cleanWalletUtxos().catch(console.error);
