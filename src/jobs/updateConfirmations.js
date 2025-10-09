const axios = require('axios');
const { Op } = require('sequelize');
const { models } = require('../models');

// Config
const MIN_CONFIRMATIONS = Number(process.env.MIN_CONFIRMATIONS || 6);
const BLOCKCYPHER_BASE = 'https://api.blockcypher.com/v1/btc/test3';
const BLOCKSTREAM_BASE = 'https://blockstream.info/testnet/api';
const BLOCKCYPHER_TOKEN = process.env.BLOCKCYPHER_TOKEN || '';
const AXIOS_TIMEOUT_MS = Number(process.env.AXIOS_TIMEOUT_MS || 8000);
const MEMPOOL_BASE = 'https://mempool.space/testnet/api';
const PER_TX_DELAY_MS = Number(process.env.CONFIRMATIONS_PER_TX_DELAY_MS || 500);
const RATE_LIMIT_SLEEP_MS = Number(process.env.CONFIRMATIONS_RATE_LIMIT_SLEEP_MS || 3000);
const MAX_FALLBACK_RETRIES = Number(process.env.CONFIRMATIONS_MAX_FALLBACK_RETRIES || 2);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getConfirmationsFromBlockcypher(txid) {
  const url = `${BLOCKCYPHER_BASE}/txs/${txid}${BLOCKCYPHER_TOKEN ? `?token=${encodeURIComponent(BLOCKCYPHER_TOKEN)}` : ''}`;
  const res = await axios.get(url, { timeout: AXIOS_TIMEOUT_MS });
  return res.data.confirmations || 0;
}

async function getConfirmationsFromBlockstream(txid) {
  // Use lightweight status endpoint first
  // GET /tx/:txid/status -> { confirmed: boolean, block_height?: number }
  const statusRes = await axios.get(`${BLOCKSTREAM_BASE}/tx/${txid}/status`, { timeout: AXIOS_TIMEOUT_MS });
  const status = statusRes.data;
  if (!status || !status.confirmed) return 0;
  const tipRes = await axios.get(`${BLOCKSTREAM_BASE}/blocks/tip/height`, { timeout: AXIOS_TIMEOUT_MS });
  const tipHeight = Number(tipRes.data);
  const confs = tipHeight - Number(status.block_height) + 1;
  return isNaN(confs) ? 0 : Math.max(0, confs);
}

async function getConfirmationsFromMempool(txid) {
  // GET /tx/:id/status -> { confirmed, block_height? }
  const statusRes = await axios.get(`${MEMPOOL_BASE}/tx/${txid}/status`, { timeout: AXIOS_TIMEOUT_MS });
  const status = statusRes.data;
  if (!status || !status.confirmed) return 0;
  const tipRes = await axios.get(`${MEMPOOL_BASE}/blocks/tip/height`, { timeout: AXIOS_TIMEOUT_MS });
  const tipHeight = Number(tipRes.data);
  const confs = tipHeight - Number(status.block_height) + 1;
  return isNaN(confs) ? 0 : Math.max(0, confs);
}

async function getConfirmations(txid) {
  try {
    return await getConfirmationsFromBlockcypher(txid);
  } catch (err) {
    // Rate limited or other errors -> fallback to Blockstream
    if (err.response && err.response.status === 429) {
      console.warn(`Rate limited by BlockCypher for ${txid}, waiting before fallback...`);
      const jitter = Math.floor(Math.random() * 700);
      await sleep(RATE_LIMIT_SLEEP_MS + jitter);
    } else if (err.response && err.response.status === 404) {
      console.warn(`Tx ${txid} not found on BlockCypher (404). Trying fallback...`);
    } else {
      console.warn(`BlockCypher error for ${txid}:`, err.message);
    }

    // Try fallback with a couple of retries + small jitter to be resilient
    for (let attempt = 0; attempt <= MAX_FALLBACK_RETRIES; attempt++) {
      try {
        return await getConfirmationsFromBlockstream(txid);
      } catch (fallbackErr) {
        console.error(`Fallback error on Blockstream for ${txid} (attempt ${attempt + 1}):`, fallbackErr.message);
        // Try mempool.space in the same attempt before backoff
        try {
          return await getConfirmationsFromMempool(txid);
        } catch (memErr) {
          const last = attempt === MAX_FALLBACK_RETRIES;
          console.error(`Fallback error on Mempool for ${txid} (attempt ${attempt + 1}):`, memErr.message);
          if (last) return null;
          const backoff = 500 * Math.pow(2, attempt) + Math.floor(Math.random() * 300);
          await sleep(backoff);
        }
      }
    }
    return null;
  }
}

async function updateConfirmations() {
  try {
    const transactions = await models.Transaction.findAll({
      where: {
        status: 'pending',
        txid: { [Op.ne]: null },
      },
      order: [['created_at', 'ASC']],
      limit: Number(process.env.CONFIRMATION_BATCH_LIMIT || 25),
    });

    if (!transactions.length) {
      console.log('updateConfirmations: aucune transaction en attente.');
      return;
    }

    console.log(`updateConfirmations: ${transactions.length} tx à vérifier (minConfirmations=${MIN_CONFIRMATIONS}).`);

    for (const tx of transactions) {
      try {
        if (!tx.txid) {
          console.warn(`Transaction ${tx.id} sans txid, ignorée.`);
          continue;
        }
        const confirmations = await getConfirmations(tx.txid);
        if (confirmations === null) {
          console.warn(`Impossible d'obtenir les confirmations pour ${tx.txid}, on réessaiera plus tard.`);
          continue;
        }
        if (confirmations >= MIN_CONFIRMATIONS) {
          await tx.update({ status: 'confirmed', confirmations });
          console.log(`Tx ${tx.txid} confirmée (${confirmations}).`);
        } else {
          // Mettre à jour uniquement si changé pour limiter les writes
          if (tx.confirmations !== confirmations) {
            await tx.update({ confirmations });
            console.log(`Tx ${tx.txid} confirmations mises à jour -> ${confirmations}.`);
          }
        }
        // Throttle a bit between tx checks to avoid bursts
        if (PER_TX_DELAY_MS > 0) {
          const jitter = Math.floor(Math.random() * 150);
          await sleep(PER_TX_DELAY_MS + jitter);
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