const express = require('express');
const router = express.Router();
const walletController = require('../controllers/walletController');
const verify2FAMiddleware = require('../middlewares/verify2FAMiddleware');
const apiKeyAuth = require('../middlewares/apiKeyAuth');

router.get('/list', walletController.listUsers);
router.get('/balance', walletController.getBalance);
router.post('/send-bitcoin', verify2FAMiddleware, walletController.sendBitcoin);
router.post('/transactions', verify2FAMiddleware, walletController.getTransactionHistory);
router.post('/send-payment', apiKeyAuth, walletController.sendPayment);

module.exports = router;