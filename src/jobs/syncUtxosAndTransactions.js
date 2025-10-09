const axios = require('axios');
const { Op } = require('sequelize');
const { models } = require('../models');
const { encryptData } = require('../services/encryption');

const MIN_CONFIRMATIONS = Number(process.env.MIN_CONFIRMATIONS || 6);
const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY || '', 'hex');

const BLOCKCYPHER_BASE = 'https://api.blockcypher.com/v1/btc/test3';
const BLOCKSTREAM_BASE = 'https://blockstream.info/testnet/api';
const BLOCKCYPHER_TOKEN = process.env.BLOCKCYPHER_TOKEN || '';
const SYNC_TX_LIMIT = Number(process.env.SYNC_TX_LIMIT || 50);
const MEMPOOL_BASE = 'https://mempool.space/testnet/api';
const AXIOS_TIMEOUT_MS = Number(process.env.AXIOS_TIMEOUT_MS || 8000);
const PER_WALLET_DELAY_MS = Number(process.env.SYNC_PER_WALLET_DELAY_MS || 400);
const RATE_LIMIT_SLEEP_MS = Number(process.env.SYNC_RATE_LIMIT_SLEEP_MS || 2500);

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function refreshWalletUtxos(wallet) {
  const url = `${BLOCKCYPHER_BASE}/addrs/${wallet.address}?unspentOnly=true`;
  let res;
  try {
    res = await axios.get(url, { timeout: AXIOS_TIMEOUT_MS });
  } catch (err) {
    if (err.response && err.response.status === 429) {
      console.warn(`sync: rate-limited on UTXO list for ${wallet.wallet_id}, sleeping before retry...`);
      await sleep(RATE_LIMIT_SLEEP_MS + Math.floor(Math.random() * 500));
    } else {
      console.warn(`sync: BlockCypher UTXO fetch failed for ${wallet.wallet_id}: ${err.message}`);
    }
    // Fallback to Blockstream
    try {
      const bs = await axios.get(`${BLOCKSTREAM_BASE}/address/${wallet.address}/utxo`, { timeout: AXIOS_TIMEOUT_MS });
      // Normalize to BlockCypher-like shape
      const txrefs = (bs.data || []).map(u => ({ tx_hash: u.txid, tx_output_n: u.vout, value: Number(u.value || 0) }));
      res = { data: { txrefs } };
    } catch (bsErr) {
      console.warn(`sync: Blockstream UTXO fallback failed for ${wallet.wallet_id}: ${bsErr.message}`);
      // Fallback to mempool.space
      const mp = await axios.get(`${MEMPOOL_BASE}/address/${wallet.address}/utxo`, { timeout: AXIOS_TIMEOUT_MS });
      const txrefs = (mp.data || []).map(u => ({ tx_hash: u.txid, tx_output_n: u.vout, value: Number(u.value || 0) }));
      res = { data: { txrefs } };
    }
  }
  const apiUtxos = res.data.txrefs || [];
  const liveSet = new Set(apiUtxos.map(u => `${u.tx_hash}:${u.tx_output_n}`));

  // Marquer comme used les UTXOs non présents côté API
  const existing = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
  for (const e of existing) {
    const key = `${e.tx_hash}:${e.output_index}`;
    if (!liveSet.has(key)) {
      await e.update({ used: true });
    }
  }

  // Insérer / mettre à jour les UTXOs actifs
  for (const u of apiUtxos) {
    const found = await models.Utxo.findOne({ where: { wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n } });
    if (!found) {
      await models.Utxo.create({ wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n, amount: u.value, used: false });
    } else if (found.used || found.amount !== u.value) {
      await found.update({ used: false, amount: u.value });
    }
  }
}

async function upsertTransactionsForAddress(wallet) {
  // Récupère les dernières tx pour l'adresse et upsert côté DB
  const url = `${BLOCKCYPHER_BASE}/addrs/${wallet.address}?limit=${SYNC_TX_LIMIT}${BLOCKCYPHER_TOKEN ? `&token=${encodeURIComponent(BLOCKCYPHER_TOKEN)}` : ''}`;
  let txrefs = [];
  try {
    const res = await axios.get(url, { timeout: AXIOS_TIMEOUT_MS });
    const confirmed = res.data.txrefs || [];
    const unconfirmed = res.data.unconfirmed_txrefs || [];
    txrefs = confirmed.concat(unconfirmed);
  } catch (err) {
    if (err.response && err.response.status === 429) {
      console.warn(`sync: rate-limited on tx list for ${wallet.wallet_id}, sleeping before retry...`);
      await sleep(RATE_LIMIT_SLEEP_MS + Math.floor(Math.random() * 500));
    } else {
      console.warn(`sync: BlockCypher tx list failed for ${wallet.wallet_id}: ${err.message}`);
    }
    // Fallback Blockstream: /address/:addr/txs (recent, includes mempool)
    try {
      const bs = await axios.get(`${BLOCKSTREAM_BASE}/address/${wallet.address}/txs`, { timeout: AXIOS_TIMEOUT_MS });
      const txs = Array.isArray(bs.data) ? bs.data : [];
      // Convert to a shape similar to txrefs for grouping
      txrefs = txs.map(tx => ({
        tx_hash: tx.txid,
        tx_output_n: -1, // we'll compute type later
        value: 0,
        _bs: tx,
      }));
    } catch (bsErr) {
      console.warn(`sync: Blockstream tx list fallback failed for ${wallet.wallet_id}: ${bsErr.message}`);
      return; // skip this wallet this run
    }
  }

  // Dédupliquer par txid (plusieurs entrées possibles pour la même tx)
  const byTx = new Map();
  for (const t of txrefs) {
    const key = t.tx_hash;
    if (!byTx.has(key)) byTx.set(key, []);
    byTx.get(key).push(t);
  }

  for (const [txid, entries] of byTx.entries()) {
    let type = 'deposit';
    let amountSat = 0;
    let confirmations = (entries[0] && entries[0].confirmations) ? Number(entries[0].confirmations) : 0;
    let status = confirmations >= MIN_CONFIRMATIONS ? 'confirmed' : 'pending';

    // If Blockstream provided data, compute type/amount from tx vouts
    const bsEntry = entries.find(e => e._bs);
    if (bsEntry && bsEntry._bs) {
      const tx = bsEntry._bs;
      const vouts = Array.isArray(tx.vout) ? tx.vout : (Array.isArray(tx.outputs) ? tx.outputs : []);
      const outputsToAddr = vouts.filter(o => (o.scriptpubkey_address || o.address) === wallet.address);
      amountSat = outputsToAddr.reduce((s, o) => s + Number(o.value || 0), 0);
      type = outputsToAddr.length > 0 ? 'deposit' : 'withdrawal';
      const st = tx.status || {};
      status = st.confirmed ? 'confirmed' : 'pending';
      confirmations = 0; // updateConfirmations job mettra à jour précisément
    } else {
      // BlockCypher path: use txrefs shapes
      const hasOutput = entries.some(e => e.tx_output_n !== -1);
      const hasInput = entries.some(e => e.tx_input_n !== -1);
      type = hasOutput ? 'deposit' : (hasInput ? 'withdrawal' : 'deposit');
      amountSat = hasOutput
        ? entries.filter(e => e.tx_output_n !== -1).reduce((s, e) => s + (e.value || 0), 0)
        : entries.reduce((s, e) => s + (e.value || 0), 0);
      status = confirmations >= MIN_CONFIRMATIONS ? 'confirmed' : 'pending';
    }

    // Données chiffrées minimales
    let encrypted_data;
    try {
      const payload = { txid, address: wallet.address, type, amountSat };
      encrypted_data = JSON.stringify(encryptData(JSON.stringify(payload), serverKey));
    } catch (e) {
      // Si chiffrement impossible, on évite de planter le job
      encrypted_data = JSON.stringify({ iv: '', encryptedData: '' });
      console.warn('sync: chiffrement manqué pour tx', txid, e.message);
    }

  const existing = await models.Transaction.findOne({ where: { txid, wallet_id: wallet.wallet_id } });
    if (!existing) {
      await models.Transaction.create({
        wallet_id: wallet.wallet_id,
    senderId: type === 'withdrawal' ? wallet.user_id : null,
    receiverId: type === 'deposit' ? wallet.user_id : null,
        encrypted_data,
        type,
        txid,
        status,
        confirmations,
      });
    } else {
      await existing.update({ status, confirmations, encrypted_data });
    }
  }
}

async function syncUtxosAndTransactions() {
  try {
    const wallets = await models.Wallet.findAll();
    if (!wallets.length) return;

    for (const wallet of wallets) {
      try {
        await refreshWalletUtxos(wallet);
        await upsertTransactionsForAddress(wallet);
        if (PER_WALLET_DELAY_MS > 0) {
          await sleep(PER_WALLET_DELAY_MS + Math.floor(Math.random() * 150));
        }
      } catch (e) {
        console.warn(`sync: échec pour wallet ${wallet.wallet_id}:`, e.message);
      }
    }
  } catch (error) {
    console.error('Erreur syncUtxosAndTransactions:', error.message);
  }
}

module.exports = syncUtxosAndTransactions;
