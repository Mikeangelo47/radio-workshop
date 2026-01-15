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

// Report successful palm match (logs to user's authentication history)
router.post('/report-match', palmController.reportMatch);

// Log authentication attempts from palm devices
router.post('/auth-log', palmController.logAuthAttempt);

// Get all device authentication logs
router.get('/device-logs', palmController.getDeviceLogs);

// Palm device pending verifications endpoint
// Called by palm device to check for pending verification requests
router.get('/:deviceId/pending-verifications', async (req, res) => {
  try {
    const { deviceId } = req.params;
    // Return empty for now - this endpoint is polled by palm device
    res.json({ pending: false, verifications: [] });
  } catch (error) {
    console.error('Error fetching pending verifications:', error);
    res.status(500).json({ error: 'Failed to fetch verifications' });
  }
});

// Log successful palm scan from palm device
// This is called when palm device successfully authenticates a user
router.post('/:deviceId/log-scan', async (req, res) => {
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient();
  
  try {
    const { deviceId } = req.params;
    const { userId, success, location } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    
    // Log to user's authentication history
    const authLog = await prisma.authenticationLog.create({
      data: {
        userId,
        deviceType: 'palm',
        location: location || 'Palm Device',
        success: success !== false
      }
    });
    
    console.log(`[Palm Device] ✅ Scan logged for user ${userId}`);
    res.status(201).json({ success: true, log: authLog });
  } catch (error) {
    console.error('[Palm Device] Error logging scan:', error);
    res.status(500).json({ error: 'Failed to log scan' });
  }
});

module.exports = router;
