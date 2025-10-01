const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController'); // Changé de userController à authController
const adminSecret = require('../middlewares/adminSecret');

router.post('/register', authController.register);
router.post('/verify-otp', authController.verifyOtp);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);
router.post('/create-admin', adminSecret, authController.createAdmin);

module.exports = router;