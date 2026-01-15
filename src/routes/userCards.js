const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const userCardController = require('../controllers/userCardController');

// Get user's campaign cards
router.get('/:userId/cards', userCardController.getUserCards);

// Add campaign card to user wallet
router.post(
  '/:userId/cards',
  [
    body('campaignId').notEmpty().isString()
  ],
  userCardController.addCardToWallet
);

// Remove card from user wallet
router.delete('/:userId/cards/:cardId', userCardController.removeCardFromWallet);

module.exports = router;
