const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const palmController = require('../controllers/palmController');

router.post(
  '/enroll',
  [
    body('userId').notEmpty().isUUID(),
    body('leftRgbFeature').optional().isBase64(),
    body('leftIrFeature').optional().isBase64(),
    body('rightRgbFeature').optional().isBase64(),
    body('rightIrFeature').optional().isBase64(),
    body('sdkVendor').optional().isString(),
    body('featureVersion').optional().isString()
  ],
  palmController.enrollPalm
);

router.get('/template/:userId', palmController.getPalmTemplate);

router.post(
  '/verify',
  [
    body('leftRgbFeature').optional().isBase64(),
    body('leftIrFeature').optional().isBase64(),
    body('rightRgbFeature').optional().isBase64(),
    body('rightIrFeature').optional().isBase64(),
    body('sdkVendor').optional().isString(),
    body('featureVersion').optional().isString()
  ],
  palmController.verifyPalm
);

// Log authentication attempts from palm devices
router.post('/auth-log', palmController.logAuthAttempt);

module.exports = router;
