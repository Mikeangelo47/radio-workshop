const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const multer = require('multer');
const userCardController = require('../controllers/userCardController');

// Configure multer for memory storage (for image uploads)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
  },
  fileFilter: (req, file, cb) => {
    // Accept only images
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

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

// Upload cover image for a card
router.post(
  '/cards/:cardId/cover',
  upload.single('image'),
  userCardController.uploadCardCoverImage
);

// Remove cover image from a card
router.delete(
  '/cards/:cardId/cover',
  userCardController.removeCardCoverImage
);

module.exports = router;
