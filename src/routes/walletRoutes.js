const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/list', userController.listUsers);
router.get('/balance', userController.getBalance);
router.post('/send-bitcoin', userController.sendBitcoin);
router.post('/transactions', userController.getTransactionHistory);

module.exports = router;