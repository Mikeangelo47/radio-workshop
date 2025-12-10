const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const userController = require('../controllers/userController');

// Get all users
router.get('/', userController.getAllUsers);

router.post(
  '/',
  [
    body('displayName').notEmpty().trim().isLength({ min: 2, max: 100 }),
    body('email').optional().isEmail().normalizeEmail()
  ],
  userController.createUser
);

// Search user by displayName (for auth logging)
router.get('/search/by-name', userController.searchUserByDisplayName);

router.get('/:userId', userController.getUser);

router.patch(
  '/:userId',
  [
    body('displayName').optional().trim().isLength({ min: 2, max: 100 }),
    body('email').optional().isEmail().normalizeEmail(),
    body('phoneNumber').optional().isMobilePhone('any'),
    body('paymentMethod').optional().isString()
  ],
  userController.updateUser
);

router.post(
  '/:userId/auth-log',
  [
    body('deviceType').notEmpty().isString(),
    body('location').optional().isString(),
    body('success').optional().isBoolean()
  ],
  userController.logAuthentication
);

router.get('/:userId/auth-history', userController.getAuthenticationHistory);

// Card routes
router.post(
  '/:userId/cards',
  [
    body('type').notEmpty().isString().isIn(['gym', 'loyalty', 'transit', 'membership', 'other']),
    body('name').notEmpty().trim().isLength({ min: 1, max: 100 }),
    body('cardNumber').notEmpty().trim(),
    body('barcodeData').optional().isString(),
    body('color').optional().isHexColor(),
    body('notes').optional().isString()
  ],
  userController.createCard
);

router.get('/:userId/cards', userController.getUserCards);

router.patch(
  '/cards/:cardId',
  [
    body('type').optional().isString().isIn(['gym', 'loyalty', 'transit', 'membership', 'other']),
    body('name').optional().trim().isLength({ min: 1, max: 100 }),
    body('cardNumber').optional().trim(),
    body('barcodeData').optional().isString(),
    body('color').optional().isHexColor(),
    body('notes').optional().isString()
  ],
  userController.updateCard
);

router.delete('/cards/:cardId', userController.deleteCard);

module.exports = router;
