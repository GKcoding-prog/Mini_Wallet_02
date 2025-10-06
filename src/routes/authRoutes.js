const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const authController = require('../controllers/authController');
const adminController = require('../controllers/adminController');
const twoFAController = require('../controllers/twoFAController');
const apiKeyController = require('../controllers/apiKeyController');
const adminSecret = require('../middlewares/adminSecret');

// Middleware pour gérer les erreurs de validation
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Routes d'authentification
router.post(
  '/register',
  [
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    validate,
  ],
  authController.register
);

router.post(
  '/verify-otp',
  [
    body('email').isEmail(),
    body('otp').isLength({ min: 6, max: 6 }),
    body('password').isLength({ min: 6 }),
    validate,
  ],
  authController.verifyOtp
);

router.post(
  '/login',
  [
    body('email').isEmail(),
    body('password').notEmpty(),
    body('emailOtp').optional().isLength({ min: 6, max: 6 }),
    body('totpCode').optional().isLength({ min: 6, max: 6 }),
    validate,
  ],
  authController.login
);

router.post(
  '/refresh-token',
  [
    body('refreshToken').notEmpty(),
    validate,
  ],
  authController.refreshToken
);

router.post(
  '/logout',
  [
    body('refreshToken').notEmpty(),
    body('accessToken').optional().notEmpty(),
    validate,
  ],
  authController.logout
);

// Routes pour la gestion des administrateurs
router.post(
  '/create-admin',
  adminSecret,
  [
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    validate,
  ],
  adminController.createAdmin
);

// Routes pour la double authentification (2FA)
router.post(
  '/enable-email-2fa',
  [
    body('password').notEmpty(),
    validate,
  ],
  twoFAController.enableEmail2FA
);

router.post(
  '/disable-email-2fa',
  [
    body('password').notEmpty(),
    validate,
  ],
  twoFAController.disableEmail2FA
);

router.post(
  '/enable-totp-2fa',
  [
    body('password').notEmpty(),
    validate,
  ],
  twoFAController.enableTotp2FA
);

router.post(
  '/disable-totp-2fa',
  [
    body('password').notEmpty(),
    validate,
  ],
  twoFAController.disableTotp2FA
);

router.post(
  '/verify-2fa-email',
  [
    body('email').isEmail(),
    validate,
  ],
  twoFAController.verify2FAEmail
);

router.post(
  '/verify-2fa-totp',
  [
    body('totpCode').isLength({ min: 6, max: 6 }),
    validate,
  ],
  twoFAController.verify2FATotp
);

// Routes pour la gestion des clés API
router.post(
  '/generate-api-key',
  [
    body('description').optional().isString(),
    validate,
  ],
  apiKeyController.generateApiKey
);

module.exports = router;