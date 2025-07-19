const express = require('express');
const { deposit, transfer, getHistory } = require('../controllers/walletController');
const authenticate = require('../middlewares/authenticate');
const router = express.Router();

router.post('/deposit', authenticate, deposit);
router.post('/transfer', authenticate, transfer);
router.get('/history', authenticate, getHistory);

module.exports = router;
