const express = require('express');
const router = express.Router();
const walletController = require('../controllers/walletController');
const verify2FAMiddleware = require('../middlewares/verify2FAMiddleware');
const authenticate = require('../middlewares/authenticate');
const apiKeyAuth = require('../middlewares/apiKeyAuth');

router.get('/list', walletController.listUsers);
router.get('/balance', walletController.getBalance);
router.post('/send-bitcoin', verify2FAMiddleware, walletController.sendBitcoin);
router.get('/transactions/history', walletController.getTransactionHistory);
router.post('/send-payment', apiKeyAuth, walletController.sendPayment);

// Nouveau: profil utilisateur + adresse BTC
router.get('/me', authenticate, async (req, res) => {
	try {
		const { models } = require('../models');
		const user = await models.User.findByPk(req.user.id, { attributes: ['id', 'email'] });
		if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé' });
		const wallet = await models.Wallet.findOne({ where: { user_id: user.id }, attributes: ['address'] });
		return res.json({ email: user.email, address: wallet ? wallet.address : null });
	} catch (e) {
		return res.status(500).json({ message: 'Erreur serveur' });
	}
});

module.exports = router;