const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const adminSecret = require('../middlewares/adminSecret');

router.post('/register', userController.register);
router.post('/verify-otp', userController.verifyOtp);
router.post('/login', userController.login);
router.post('/refresh-token', userController.refreshToken);
router.post('/logout', userController.logout);
router.post('/create-admin', adminSecret, userController.createAdmin);

module.exports = router;