const express = require('express');
const router = express.Router();
const walletController = require('../controllers/walletController'); // Changé de userController à walletController

router.get('/list', walletController.listUsers);
router.get('/balance', walletController.getBalance);
router.post('/send-bitcoin', walletController.sendBitcoin);
router.post('/transactions', walletController.getTransactionHistory);

module.exports = router;