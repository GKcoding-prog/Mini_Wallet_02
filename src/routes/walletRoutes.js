const express = require('express');
const { deposit, withdraw, transfer, getHistory } = require('../controllers/walletController');
const authenticate = require('../middlewares/authenticate');
const router = express.Router();

router.post('/deposit', authenticate, deposit);
router.post('/withdraw', authenticate, withdraw);
router.post('/transfer', authenticate, transfer);
router.get('/history', authenticate, getHistory);

module.exports = router;