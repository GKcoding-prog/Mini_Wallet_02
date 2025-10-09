const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const ECPairFactory = require('ecpair').ECPairFactory;
const tinysecp = require('tiny-secp256k1');
const axios = require('axios');
const { Op } = require('sequelize');
const { models } = require('../models');
const { encryptData, decryptData } = require('../services/encryption');

const network = bitcoin.networks.testnet;
const ECPair = ECPairFactory(tinysecp);
const BLOCKCYPHER_BASE = 'https://api.blockcypher.com/v1/btc/test3';
const BLOCKSTREAM_BASE = 'https://blockstream.info/testnet/api';
const MEMPOOL_BASE = 'https://mempool.space/testnet/api';
const SOCHAIN_BASE = 'https://sochain.com/api/v2';
const BLOCKCYPHER_TOKEN = process.env.BLOCKCYPHER_TOKEN || '';

// Simple helpers
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
const rawTxCache = new Map(); // txid -> raw hex

// Helper: solde externe avec fallback
async function getAddressFinalBalance(address) {
  try {
    const res = await axios.get(`${BLOCKCYPHER_BASE}/addrs/${address}/balance`);
    return Number(res.data.final_balance || 0);
  } catch (e) {
    try {
      const r2 = await axios.get(`${BLOCKSTREAM_BASE}/address/${address}`);
      const cs = r2.data.chain_stats || {};
      const ms = r2.data.mempool_stats || {};
      const bal = (cs.funded_txo_sum || 0) - (cs.spent_txo_sum || 0) + (ms.funded_txo_sum || 0) - (ms.spent_txo_sum || 0);
      return Number(bal);
    } catch (e2) {
      return null;
    }
  }
}

// Vérifie si un UTXO est déjà dépensé via BlockCypher puis fallback Blockstream
async function isUtxoSpent(txid, vout) {
  try {
    const r = await axios.get(`${BLOCKCYPHER_BASE}/txs/${txid}`);
    const out = r.data && r.data.outputs && r.data.outputs[vout];
    if (out && (out.spent_by || out.spent)) return true;
    if (out && out.spent === false) return false;
  } catch (e) {}
  try {
    const r2 = await axios.get(`${BLOCKSTREAM_BASE}/tx/${txid}/outspend/${vout}`);
    if (r2.data && typeof r2.data.spent === 'boolean') return r2.data.spent;
  } catch (e2) {}
  return false;
}

// Récupère les données nécessaires pour un UTXO (rawTx + script/value) avec fallback Blockstream
async function fetchUtxoData(txid, vout) {
  // Use cache first to avoid repeated network fetches for the same prevout
  if (rawTxCache.has(txid)) {
    return { rawTx: rawTxCache.get(txid), outputScript: null, valueSat: null };
  }
  // Essai BlockCypher (inclut hex + outputs.script)
    try {
      const url = `${BLOCKCYPHER_BASE}/txs/${txid}?includeHex=true${BLOCKCYPHER_TOKEN ? `&token=${encodeURIComponent(BLOCKCYPHER_TOKEN)}` : ''}`;
      const res = await axios.get(url);
    const rawTx = res.data.hex;
    if (rawTx) rawTxCache.set(txid, rawTx);
    const out = res.data && res.data.outputs ? res.data.outputs[vout] : null;
    return {
      rawTx,
      outputScript: out && out.script ? out.script : null,
      valueSat: out && typeof out.value === 'number' ? out.value : null,
    };
  } catch (e) {
    // fallback Blockstream puis Mempool
    const tryBlockstream = async () => {
      const results = await Promise.allSettled([
        axios.get(`${BLOCKSTREAM_BASE}/tx/${txid}/hex`),
        axios.get(`${BLOCKSTREAM_BASE}/tx/${txid}`),
      ]);
      const hexRes = results[0].status === 'fulfilled' ? results[0].value : null;
      const jsonRes = results[1].status === 'fulfilled' ? results[1].value : null;
      if (!hexRes && !jsonRes) return null;
  const rawTx = hexRes ? hexRes.data : null;
  if (rawTx) rawTxCache.set(txid, rawTx);
      const out = jsonRes && jsonRes.data && Array.isArray(jsonRes.data.vout)
        ? jsonRes.data.vout[vout]
        : null;
      return {
        rawTx,
        outputScript: out && out.scriptpubkey ? out.scriptpubkey : null,
        valueSat: out && typeof out.value === 'number' ? out.value : null,
      };
    };
    const tryMempool = async () => {
      const results = await Promise.allSettled([
        axios.get(`${MEMPOOL_BASE}/tx/${txid}/hex`),
        axios.get(`${MEMPOOL_BASE}/tx/${txid}`),
      ]);
      const hexRes = results[0].status === 'fulfilled' ? results[0].value : null;
      const jsonRes = results[1].status === 'fulfilled' ? results[1].value : null;
      if (!hexRes && !jsonRes) return null;
  const rawTx = hexRes ? hexRes.data : null;
  if (rawTx) rawTxCache.set(txid, rawTx);
      const out = jsonRes && jsonRes.data && Array.isArray(jsonRes.data.vout)
        ? jsonRes.data.vout[vout]
        : null;
      return {
        rawTx,
        outputScript: out && out.scriptpubkey ? out.scriptpubkey : null,
        valueSat: out && typeof out.value === 'number' ? out.value : null,
      };
    };
    const bs = await tryBlockstream();
    if (bs) return bs;
    const mp = await tryMempool();
    if (mp) return mp;
    throw e;
  }
}

// Synchronise les UTXOs du wallet avec l'API (marque used ceux absents et insère les nouveaux)
async function refreshWalletUtxos(wallet) {
  try {
  // 1) BlockCypher
    const url = `${BLOCKCYPHER_BASE}/addrs/${wallet.address}?unspentOnly=true${BLOCKCYPHER_TOKEN ? `&token=${encodeURIComponent(BLOCKCYPHER_TOKEN)}` : ''}`;
    const res = await axios.get(url);
  const apiUtxos = (res.data && res.data.txrefs) || [];
    const liveSet = new Set(apiUtxos.map(u => `${u.tx_hash}:${u.tx_output_n}`));

    // Marquer comme used les UTXOs qui n'apparaissent plus en unspent
    const existing = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
    for (const e of existing) {
      const key = `${e.tx_hash}:${e.output_index}`;
      if (!liveSet.has(key)) {
        await e.update({ used: true });
      }
    }

    // Insérer/assurer les UTXOs en base
    for (const u of apiUtxos) {
      const found = await models.Utxo.findOne({ where: { wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n } });
      if (!found) {
        await models.Utxo.create({ wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n, amount: u.value, used: false });
      } else if (found.used) {
        await found.update({ used: false, amount: u.value });
      }
    }
  } catch (e) {
    console.warn('refreshWalletUtxos: échec BlockCypher:', e.message);
    // Fallback Blockstream -> normalize to BlockCypher-like { txrefs }
    try {
      const bs = await axios.get(`${BLOCKSTREAM_BASE}/address/${wallet.address}/utxo`);
      const txrefs = (bs.data || []).map(u => ({ tx_hash: u.txid, tx_output_n: u.vout, value: Number(u.value || 0) }));
      const liveSet = new Set(txrefs.map(u => `${u.tx_hash}:${u.tx_output_n}`));
      const existing = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
      for (const e of existing) {
        const key = `${e.tx_hash}:${e.output_index}`;
        if (!liveSet.has(key)) {
          await e.update({ used: true });
        }
      }
      for (const u of txrefs) {
        const found = await models.Utxo.findOne({ where: { wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n } });
        if (!found) {
          await models.Utxo.create({ wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n, amount: u.value, used: false });
        } else if (found.used || Number(found.amount) !== Number(u.value)) {
          await found.update({ used: false, amount: u.value });
        }
      }
      return;
    } catch (bsErr) {
      console.warn('refreshWalletUtxos: fallback Blockstream échoué:', bsErr.message);
    }
    // Fallback Mempool
    try {
      const mp = await axios.get(`${MEMPOOL_BASE}/address/${wallet.address}/utxo`);
      const txrefs = (mp.data || []).map(u => ({ tx_hash: u.txid, tx_output_n: u.vout, value: Number(u.value || 0) }));
      const liveSet = new Set(txrefs.map(u => `${u.tx_hash}:${u.tx_output_n}`));
      const existing = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
      for (const e of existing) {
        const key = `${e.tx_hash}:${e.output_index}`;
        if (!liveSet.has(key)) {
          await e.update({ used: true });
        }
      }
      for (const u of txrefs) {
        const found = await models.Utxo.findOne({ where: { wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n } });
        if (!found) {
          await models.Utxo.create({ wallet_id: wallet.wallet_id, tx_hash: u.tx_hash, output_index: u.tx_output_n, amount: u.value, used: false });
        } else if (found.used || Number(found.amount) !== Number(u.value)) {
          await found.update({ used: false, amount: u.value });
        }
      }
      return;
    } catch (mpErr) {
      console.warn('refreshWalletUtxos: fallback Mempool échoué:', mpErr.message);
    }
  }
}

async function listUsers(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== 'admin') {
      return res.status(403).json({ message: 'Accès refusé: Admin seulement' });
    }

    const users = await models.User.findAll({
      attributes: ['id', 'email', 'role'],
      include: [{ model: models.Wallet, attributes: ['address'] }],
    });
    res.json(users);
  } catch (error) {
    console.error('Erreur lors de la liste des utilisateurs:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function getBalance(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token requis' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const wallet = await models.Wallet.findOne({ where: { user_id: payload.id } });
    if (!wallet) return res.status(404).json({ message: 'Portefeuille non trouvé' });

    // Synchroniser les UTXOs locaux avec l'état on-chain
    try { await refreshWalletUtxos(wallet); } catch (e) { console.warn('getBalance: sync UTXO échouée:', e.message); }

    // Solde externe (avec fallback Blockstream pour éviter 429)
    const externalFinalBalanceSat = await getAddressFinalBalance(wallet.address);

    // Solde dépensable d'après la DB locale (UTXOs non utilisés)
    const utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
    const spendableSat = utxos.reduce((s, u) => s + Number(u.amount || 0), 0);

    return res.json({
      address: wallet.address,
      spendable_sats: spendableSat,
      spendable: spendableSat / 1e8,
      external_final_balance_sats: externalFinalBalanceSat,
      external_final_balance: (externalFinalBalanceSat ?? 0) / 1e8,
      utxo_count: utxos.length,
    });
  } catch (error) {
    console.error('Erreur lors de la récupération du solde:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

// walletController.js (partie pertinente pour sendBitcoin)
async function sendBitcoin(req, res) {
  console.log('Log: Entrée dans sendBitcoin - Requête reçue', new Date().toISOString());
  console.log('Log: Méthode:', req.method, 'URL:', req.url);
  try {
    // L'utilisateur est déjà injecté par verify2FAMiddleware
    const user = req.user;
    if (!user) {
      console.log('Log: Utilisateur non authentifié');
      return res.status(401).json({ message: 'Utilisateur non authentifié' });
    }
    console.log('Log: Utilisateur trouvé:', user.id);

    // Vérifier les paramètres de la requête
    const { fromAddress, toAddress, amount } = req.body;
    if (!fromAddress || !toAddress || !amount) {
      console.log('Log: Paramètres manquants');
      return res.status(400).json({ message: 'Adresse d\'envoi, adresse de destination et montant requis' });
    }

    // Convertir le montant en satoshis (toujours un entier)
    const amountSat = Math.round(Number(amount) * 1e8);
    if (isNaN(amountSat) || amountSat <= 0) {
      console.log('Log: Montant invalide:', amount);
      return res.status(400).json({ message: 'Montant invalide' });
    }

    // Log pour debug
    console.log('Log: amount:', amount, 'amountSat:', amountSat);

    // Vérifier les adresses Bitcoin
    try {
      bitcoin.address.toOutputScript(fromAddress, network);
      bitcoin.address.toOutputScript(toAddress, network);
    } catch (e) {
      console.log('Log: Adresse invalide:', e.message);
      return res.status(400).json({ message: 'Adresse d\'envoi ou de destination invalide' });
    }

    // Trouver le portefeuille
    const wallet = await models.Wallet.findOne({ where: { user_id: user.id, address: fromAddress } });
    if (!wallet) {
      console.log('Log: Portefeuille non trouvé pour', fromAddress);
      return res.status(404).json({ message: 'Portefeuille non trouvé pour cette adresse d\'envoi' });
    }

    console.log('Log: Portefeuille trouvé:', wallet.wallet_id, wallet.address);

    // Décrypter la clé privée
    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const encryptedPrivateKeyObject = JSON.parse(wallet.server_encrypted_private_key || wallet.private_key);
    let privateKey;
    try {
      privateKey = decryptData(encryptedPrivateKeyObject, serverKey);
      console.log('Log: Clé privée décryptée');
    } catch (error) {
      console.log('Log: Échec du déchiffrement:', error.message);
      return res.status(400).json({ message: 'Erreur de déchiffrement de la clé privée' });
    }

    // Vérifier la clé privée
    let keyPair;
    try {
      keyPair = ECPair.fromWIF(privateKey, network);
      console.log('Log: Clé WIF valide');
    } catch (wifError) {
      console.log('Log: WIF invalide:', wifError.message);
      return res.status(400).json({ message: 'Clé privée invalide' });
    }

    // Récupérer les UTXOs
    let utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
    if (!utxos || utxos.length === 0) {
      console.log('Log: Aucun UTXO local, synchronisation on-chain multi-fournisseurs...');
      try { await refreshWalletUtxos(wallet); } catch (e) { console.log('Log: refreshWalletUtxos erreur:', e.message); }
      utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
      console.log('Log: UTXOs mis à jour:', utxos.length);
    }

    if (utxos.length === 0) {
      console.log('Log: Aucun UTXO disponible');
      return res.status(400).json({ error: 'Aucun UTXO disponible' });
    }

    // Construire la transaction PSBT
    const psbt = new bitcoin.Psbt({ network });
  let totalInput = 0;

    for (const utxo of utxos) {
      try {
        // Skip UTXO déjà dépensé
        const spent = await isUtxoSpent(utxo.tx_hash, utxo.output_index);
        if (spent) {
          console.log('Log: UTXO déjà dépensé, on le marque used et on saute:', utxo.tx_hash, utxo.output_index);
          await utxo.update({ used: true });
          continue;
        }
        // Fetch with small retry/backoff to ride out transient 429s
        let utxoData;
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            utxoData = await fetchUtxoData(utxo.tx_hash, utxo.output_index);
            break;
          } catch (fe) {
            if (attempt === 2) throw fe;
            const back = 300 * Math.pow(2, attempt) + Math.floor(Math.random() * 200);
            await sleep(back);
          }
        }
        const rawTx = utxoData.rawTx;
        if (!rawTx) {
          console.log('Log: Données UTXO manquantes pour', utxo.tx_hash);
          return res.status(500).json({ message: 'Impossible de récupérer les données de la transaction UTXO' });
        }
        // Détection du type d'adresse (SegWit ou legacy)
        let inputConfig = {
          hash: utxo.tx_hash,
          index: utxo.output_index,
        };
        const scriptPubKey = utxoData.outputScript;
        // Si l'adresse commence par 'tb1' ou le script est witness, on utilise witnessUtxo
        if (fromAddress.startsWith('tb1') || (scriptPubKey && scriptPubKey.startsWith('0014'))) {
          inputConfig.witnessUtxo = {
            script: Buffer.from(scriptPubKey, 'hex'),
            value: Math.round(Number(utxo.amount || utxoData.valueSat)),
          };
        } else {
          inputConfig.nonWitnessUtxo = Buffer.from(rawTx, 'hex');
        }
        psbt.addInput(inputConfig);
        // S'assurer que le montant est un entier
        const utxoAmount = Math.round(Number(utxo.amount || utxoData.valueSat || 0));
        totalInput += utxoAmount;
        console.log('Log: UTXO ajouté:', utxo.tx_hash, 'montant:', utxoAmount);
      } catch (error) {
        console.log('Log: Erreur UTXO', utxo.tx_hash, ':', error.message);
        continue;
      }
    }

    // Vérifier les fonds
    if (totalInput < amountSat) {
      console.log('Log: Fonds insuffisants:', totalInput, '<', amountSat);
      return res.status(400).json({ error: 'Fonds insuffisants' });
    }

    // Ajouter la sortie pour le destinataire
    psbt.addOutput({
      address: toAddress,
      value: amountSat,
    });

    // Gérer les frais et le changement
    const DUST = 546;
    let fee = 1500; // frais fixes augmentés à 1500 sats
    let change = Math.round(totalInput - amountSat - fee);
    // Éviter une sortie de change en dust: on ajoute au fee et on supprime la sortie de change
    if (change > 0 && change < DUST) {
      fee += change;
      change = 0;
    }
    console.log('Log: totalInput:', totalInput, 'amountSat:', amountSat, 'fee:', fee, 'change:', change);

    if (change < 0) {
      console.log('Log: Changement négatif:', change);
      return res.status(400).json({ error: 'Fonds insuffisants après frais' });
    }
    // Ajout d'un log pour l'output destinataire
    console.log('Output destinataire:', toAddress, amountSat);
    if (change > 0) {
      // Ajout d'un log pour l'output change
      console.log('Output change:', fromAddress, change);
      psbt.addOutput({
        address: fromAddress,
        value: change,
      });
      console.log('Log: Changement ajouté:', change);
    }

    // Signer les inputs
    for (let i = 0; i < utxos.length; i++) {
      try {
        psbt.signInput(i, keyPair);
        console.log('Log: Input signé:', i);
      } catch (error) {
        console.log('Log: Échec de la signature pour input', i, ':', error.message);
        return res.status(500).json({ message: 'Erreur de signature' });
      }
    }

    // Finaliser et extraire la transaction
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();

    console.log('Log: Transaction construite, envoi à BlockCypher...');
    let txid;
    try {
      const pushUrl = BLOCKCYPHER_TOKEN
        ? `https://api.blockcypher.com/v1/btc/test3/txs/push?token=${encodeURIComponent(BLOCKCYPHER_TOKEN)}`
        : 'https://api.blockcypher.com/v1/btc/test3/txs/push';
      const bcRes = await axios.post(pushUrl, { tx: txHex });
      txid = bcRes.data.tx.hash;
      console.log('Log: Transaction envoyée (BlockCypher), txid:', txid);
    } catch (err) {
      const status = err.response?.status;
      const data = err.response?.data;
      console.error('Diffusion BlockCypher échouée:', { status, data });
  // Petite pause pour éviter d'enchaîner sur un autre service en cas de saturation
  await sleep(600 + Math.floor(Math.random() * 400));
  console.log('Tentative de fallback via Blockstream...');
      try {
        const bsRes = await axios.post(`${BLOCKSTREAM_BASE}/tx`, txHex, { headers: { 'Content-Type': 'text/plain' } });
        txid = bsRes.data;
        console.log('Log: Transaction envoyée (Blockstream), txid:', txid);
      } catch (err2) {
        const status2 = err2.response?.status;
        const data2 = err2.response?.data;
        console.error('Diffusion Blockstream échouée:', { status: status2, data: data2 });
  await sleep(600 + Math.floor(Math.random() * 400));
  console.log('Tentative de fallback via Mempool...');
        try {
          const mpRes = await axios.post(`${MEMPOOL_BASE}/tx`, txHex, { headers: { 'Content-Type': 'text/plain' } });
          txid = typeof mpRes.data === 'string' ? mpRes.data : (mpRes.data?.txid || mpRes.data?.id);
          if (!txid) throw new Error('Réponse mempool.space inattendue');
          console.log('Log: Transaction envoyée (Mempool), txid:', txid);
        } catch (err3) {
          const status3 = err3.response?.status;
          const data3 = err3.response?.data;
          console.error('Diffusion Mempool échouée:', { status: status3, data: data3 });
          return res.status(500).json({
            message: 'Diffusion échouée (BlockCypher+Blockstream+Mempool)',
            details: {
              blockcypher: { status, data },
              blockstream: { status: status2, data: data2 },
              mempool: { status: status3, data: data3 },
            },
          });
        }
      }
    }

    // Enregistrer la transaction
    const receiverWallet = await models.Wallet.findOne({ where: { address: toAddress } });
    const receiverId = receiverWallet ? receiverWallet.user_id : null;

    const txData = { txid, amount, fromAddress, toAddress };
    const encryptedTxData = JSON.stringify(encryptData(JSON.stringify(txData), serverKey));
    // Upsert idempotent par txid (txid unique au niveau de la table)
    const existingTx = await models.Transaction.findOne({ where: { txid } });
    if (!existingTx) {
      await models.Transaction.create({
        wallet_id: wallet.wallet_id,
        senderId: user.id,
        receiverId,
        encrypted_data: encryptedTxData,
        type: 'withdrawal',
        txid,
        status: 'pending',
        confirmations: 0,
      });
    } else {
      await existingTx.update({ receiverId: existingTx.receiverId || receiverId, encrypted_data: encryptedTxData });
    }

    for (const utxo of utxos) { await utxo.update({ used: true }); }
    return res.json({ txid, fee: fee / 100000000 + ' tBTC' });
  } catch (error) {
    console.error('Log: Erreur lors de l\'envoi de la transaction:', error.message, error.stack);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

module.exports = sendBitcoin;
async function getTransactionHistory(req, res) {
  try {
    process.stdout.write('Log: Fonction getTransactionHistory appelée\n');
    process.stdout.write('Log: En-tête Authorization: ' + JSON.stringify(req.headers.authorization) + '\n');
    process.stdout.write('Log: Corps de la requête: ' + JSON.stringify(req.body) + '\n');

    const token = req.headers.authorization?.split(' ')[1] || req.body.token;
    if (!token) {
      process.stdout.write('Log: Aucun token trouvé\n');
      return res.status(401).json({ message: 'Token requis' });
    }

    process.stdout.write('Log: Token extrait: ' + token + '\n');

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    process.stdout.write('Log: Payload décodé: ' + JSON.stringify(payload) + '\n');

    const user = await models.User.findByPk(payload.id);
    if (!user) {
      process.stdout.write('Log: Utilisateur non trouvé\n');
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }

    process.stdout.write('Log: Utilisateur trouvé: ' + user.id + ', ' + user.email + '\n');

    const wallet = await models.Wallet.findOne({ where: { user_id: user.id } });
    if (!wallet) {
      process.stdout.write('Log: Portefeuille non trouvé\n');
      return res.status(404).json({ message: 'Portefeuille non trouvé' });
    }

    process.stdout.write('Log: Portefeuille trouvé: ' + wallet.wallet_id + ', ' + wallet.address + '\n');

    const transactions = await models.Transaction.findAll({
      where: {
        [Op.or]: [
          { wallet_id: wallet.wallet_id },
          { senderId: user.id },
          { receiverId: user.id },
        ],
      },
      order: [['created_at', 'DESC']],
      attributes: ['id', 'type', 'txid', 'status', 'confirmations', 'created_at', 'encrypted_data'],
      include: [
        {
          model: models.User,
          as: 'Sender',
          attributes: ['email'],
          include: [{ model: models.Wallet, attributes: ['address'] }],
        },
        {
          model: models.User,
          as: 'Receiver',
          attributes: ['email'],
          include: [{ model: models.Wallet, attributes: ['address'] }],
        },
      ],
    });

    process.stdout.write('Log: Transactions récupérées: ' + transactions.length + '\n');

    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const decryptedTransactions = transactions.map(tx => {
      let decryptedData = {};
      try {
        process.stdout.write('Log: Début déchiffrement pour transaction ' + tx.id + '\n');
        process.stdout.write('Log: encrypted_data brute: ' + JSON.stringify(tx.encrypted_data) + '\n');
        if (tx.encrypted_data) {
          const encryptedData = JSON.parse(tx.encrypted_data);
          process.stdout.write('Log: encryptedData après parse: ' + JSON.stringify(encryptedData) + '\n');
          const rawDecryptedData = decryptData(encryptedData, serverKey);
          process.stdout.write('Log: rawDecryptedData: ' + rawDecryptedData + '\n');
          decryptedData = JSON.parse(rawDecryptedData);
        }
      } catch (error) {
        process.stdout.write('Log: Échec du déchiffrement pour transaction ' + tx.id + ': ' + error.message + '\n');
        decryptedData = { error: 'Données corrompues' };
      }
      return {
        id: tx.id,
        type: tx.type,
        txid: tx.txid,
        status: tx.status,
        confirmations: tx.confirmations,
        created_at: tx.created_at,
        senderEmail: tx.Sender?.email || null,
        senderAddress: tx.Sender?.Wallet?.address || null,
        receiverEmail: tx.Receiver?.email || null,
        receiverAddress: tx.Receiver?.Wallet?.address || null,
        ...decryptedData,
      };
    });

    process.stdout.write('Log: Transactions décryptées: ' + JSON.stringify(decryptedTransactions) + '\n');

    res.json(decryptedTransactions);
  } catch (error) {
    process.stdout.write('Log: Erreur lors de la récupération de l\'historique: ' + error.message + '\n');
    res.status(500).json({ message: 'Erreur serveur' });
  }
}

async function sendPayment(req, res) {
  try {
    console.log('Log: Entrée dans sendPayment - Requête reçue', new Date().toISOString());
    const { fromAddress, toAddress, amount } = req.body;
    const user = req.user;
    if (!fromAddress || !toAddress || !amount) {
      console.log('Log: Paramètres manquants');
      return res.status(400).json({ message: "Adresse d'envoi, adresse de destination et montant requis" });
    }
    // Conversion montant en satoshis (toujours entier)
    const amountSat = Math.round(Number(amount) * 1e8);
    if (isNaN(amountSat) || amountSat <= 0) {
      console.log('Log: Montant invalide:', amount);
      return res.status(400).json({ message: 'Montant invalide' });
    }
    try {
      bitcoin.address.toOutputScript(fromAddress, network);
      bitcoin.address.toOutputScript(toAddress, network);
    } catch (e) {
      console.log('Log: Adresse invalide:', e.message);
      return res.status(400).json({ message: "Adresse d'envoi ou de destination invalide" });
    }
    const wallet = await models.Wallet.findOne({ where: { user_id: user.id, address: fromAddress } });
    if (!wallet) {
      console.log('Log: Portefeuille non trouvé pour', fromAddress);
      return res.status(404).json({ message: "Portefeuille non trouvé pour cette adresse d'envoi" });
    }
    const serverKey = Buffer.from(process.env.SERVER_MASTER_KEY, 'hex');
    const encryptedPrivateKeyObject = JSON.parse(wallet.server_encrypted_private_key || wallet.private_key);
    let privateKey;
    let keyPair;
    try {
      privateKey = decryptData(encryptedPrivateKeyObject, serverKey);
      keyPair = ECPair.fromWIF(privateKey, network);
      console.log('Log: Clé privée décryptée et WIF valide');
    } catch (error) {
      console.log('Log: Échec du déchiffrement ou WIF:', error.message);
      return res.status(400).json({ message: 'Erreur de déchiffrement ou clé privée invalide' });
    }
    let utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
    if (!utxos || utxos.length === 0) {
      console.log('Log: Aucun UTXO local, synchronisation multi-fournisseurs...');
      try { await refreshWalletUtxos(wallet); } catch (e) { console.log('Log: refreshWalletUtxos erreur:', e.message); }
      utxos = await models.Utxo.findAll({ where: { wallet_id: wallet.wallet_id, used: false } });
      console.log('Log: UTXOs mis à jour:', utxos.length);
    }
    if (utxos.length === 0) {
      console.log('Log: Aucun UTXO disponible');
      return res.status(400).json({ error: 'Aucun UTXO disponible' });
    }
    const psbt = new bitcoin.Psbt({ network });
    let totalInput = 0;
    for (const utxo of utxos) {
      try {
        // Skip UTXO déjà dépensé
        const spent = await isUtxoSpent(utxo.tx_hash, utxo.output_index);
        if (spent) {
          console.log('Log: UTXO déjà dépensé, on le marque used et on saute:', utxo.tx_hash, utxo.output_index);
          await utxo.update({ used: true });
          continue;
        }
        const utxoData = await fetchUtxoData(utxo.tx_hash, utxo.output_index);
        const rawTx = utxoData.rawTx;
        if (!rawTx) {
          console.log('Log: Données UTXO manquantes pour', utxo.tx_hash);
          return res.status(500).json({ message: 'Impossible de récupérer les données de la transaction UTXO' });
        }
        // Détection du type d'adresse (SegWit ou legacy)
        let inputConfig = {
          hash: utxo.tx_hash,
          index: utxo.output_index,
        };
        const scriptPubKey = utxoData.outputScript;
        if (fromAddress.startsWith('tb1') || (scriptPubKey && scriptPubKey.startsWith('0014'))) {
          inputConfig.witnessUtxo = {
            script: Buffer.from(scriptPubKey, 'hex'),
            value: Math.round(Number(utxo.amount || utxoData.valueSat)),
          };
        } else {
          inputConfig.nonWitnessUtxo = Buffer.from(rawTx, 'hex');
        }
        psbt.addInput(inputConfig);
        const utxoAmount = Math.round(Number(utxo.amount || utxoData.valueSat));
        totalInput += utxoAmount;
        console.log('Log: UTXO ajouté:', utxo.tx_hash, 'montant:', utxoAmount);
      } catch (error) {
        console.log('Log: Erreur UTXO', utxo.tx_hash, ':', error.message);
        continue;
      }
    }
    if (totalInput < amountSat) {
      console.log('Log: Fonds insuffisants:', totalInput, '<', amountSat);
      return res.status(400).json({ error: 'Fonds insuffisants' });
    }
    psbt.addOutput({
      address: toAddress,
      value: amountSat,
    });
    // Gérer les frais et le changement
    const DUST = 546;
  let fee = 2500; // frais fixes augmentés pour éviter les refus de relais
    let change = Math.round(totalInput - amountSat - fee);
    // Éviter une sortie de change en dust: on ajoute au fee et on supprime la sortie de change
    if (change > 0 && change < DUST) {
      fee += change;
      change = 0;
    }
    console.log('Log: totalInput:', totalInput, 'amountSat:', amountSat, 'fee:', fee, 'change:', change);
    if (change < 0) {
      console.log('Log: Changement négatif:', change);
      return res.status(400).json({ error: 'Fonds insuffisants après frais' });
    }
    if (change > 0) {
      console.log('Output change:', fromAddress, change);
      psbt.addOutput({
        address: fromAddress,
        value: change,
      });
      console.log('Log: Changement ajouté:', change);
    }
    for (let i = 0; i < utxos.length; i++) {
      try {
        psbt.signInput(i, keyPair);
        console.log('Log: Input signé:', i);
      } catch (error) {
        console.log('Log: Échec de la signature pour input', i, ':', error.message);
        return res.status(500).json({ message: 'Erreur de signature' });
      }
    }
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();
    console.log('Log: Transaction construite, envoi à Blockcypher...');
    let txid;
    try {
      const bcRes = await axios.post('https://api.blockcypher.com/v1/btc/test3/txs/push', { tx: txHex });
      txid = bcRes.data.tx.hash;
      console.log('Log: Transaction envoyée (BlockCypher), txid:', txid);
    } catch (err) {
      const status = err.response?.status;
      const data = err.response?.data;
      console.error('Diffusion BlockCypher échouée:', { status, data });
      console.log('Tentative de fallback via Blockstream...');
      try {
        const bsRes = await axios.post('https://blockstream.info/testnet/api/tx', txHex, { headers: { 'Content-Type': 'text/plain' } });
        txid = bsRes.data;
        console.log('Log: Transaction envoyée (Blockstream), txid:', txid);
      } catch (err2) {
        const status2 = err2.response?.status;
        const data2 = err2.response?.data;
        console.error('Diffusion Blockstream échouée:', { status: status2, data: data2 });
        return res.status(500).json({ message: `Diffusion échouée (BlockCypher+Blockstream)`, details: { blockcypher: { status, data }, blockstream: { status: status2, data: data2 } } });
      }
    }

    // Enregistrer la transaction
    const receiverWallet = await models.Wallet.findOne({ where: { address: toAddress } });
    const receiverId = receiverWallet ? receiverWallet.user_id : null;

    const txData = { txid, amount, fromAddress, toAddress };
    const encryptedTxData = JSON.stringify(encryptData(JSON.stringify(txData), serverKey));
    // Upsert idempotent par txid (txid unique au niveau de la table)
    const existingTx = await models.Transaction.findOne({ where: { txid } });
    if (!existingTx) {
      await models.Transaction.create({
        wallet_id: wallet.wallet_id,
        senderId: user.id,
        receiverId,
        encrypted_data: encryptedTxData,
        type: 'withdrawal',
        txid,
        status: 'pending',
        confirmations: 0,
      });
    } else {
      await existingTx.update({ receiverId: existingTx.receiverId || receiverId, encrypted_data: encryptedTxData });
    }

    for (const utxo of utxos) { await utxo.update({ used: true }); }
    return res.json({ txid, fee: fee / 100000000 + ' tBTC' });
  } catch (error) {
    console.error("Log: Erreur lors de l'envoi du paiement:", error.message, error.stack);
    res.status(500).json({ message: 'Erreur serveur: ' + error.message });
  }
}

module.exports = {
  listUsers,
  getBalance,
  sendBitcoin,
  getTransactionHistory,
  sendPayment,
};