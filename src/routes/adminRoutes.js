const express = require('express');
const router = express.Router();
const adminSecret = require('../middlewares/adminSecret');
const updateConfirmations = require('../jobs/updateConfirmations');

// Trigger confirmations sync on demand (protected)
router.post('/sync-confirmations', adminSecret, async (req, res) => {
  try {
    await updateConfirmations();
    res.json({ message: 'Synchronisation des confirmations lancée.' });
  } catch (error) {
    console.error('Erreur /sync-confirmations:', error);
    res.status(500).json({ message: 'Echec de la synchronisation', error: error.message });
  }
});

module.exports = router;
