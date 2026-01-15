const { PrismaClient } = require('@prisma/client');
const { validationResult } = require('express-validator');

const prisma = new PrismaClient();

exports.enrollPalm = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      userId,
      leftRgbFeature,
      leftIrFeature,
      rightRgbFeature,
      rightIrFeature,
      sdkVendor = 'veinshine',
      featureVersion = '1.0'
    } = req.body;

    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'User not found'
      });
    }

    await prisma.palmTemplate.updateMany({
      where: { userId, active: true },
      data: { active: false }
    });

    const palmTemplate = await prisma.palmTemplate.create({
      data: {
        userId,
        sdkVendor,
        featureVersion,
        leftRgbFeature,
        leftIrFeature,
        rightRgbFeature,
        rightIrFeature,
        active: true
      }
    });

    res.status(201).json({
      message: 'Palm template enrolled successfully',
      template: {
        id: palmTemplate.id,
        userId: palmTemplate.userId,
        sdkVendor: palmTemplate.sdkVendor,
        featureVersion: palmTemplate.featureVersion,
        enrolledAt: palmTemplate.enrolledAt
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getPalmTemplate = async (req, res, next) => {
  try {
    const { userId } = req.params;

    const template = await prisma.palmTemplate.findFirst({
      where: {
        userId,
        active: true
      }
    });

    if (!template) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'No active palm template found for this user'
      });
    }

    res.json({ template });
  } catch (error) {
    next(error);
  }
};

/**
 * Verify palm features against all stored templates
 * Returns matching user if found
 */
exports.verifyPalm = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { 
    leftRgbFeature, 
    leftIrFeature, 
    rightRgbFeature, 
    rightIrFeature,
    sdkVendor,
    featureVersion 
  } = req.body;

  try {
    // Get all active templates with the same SDK vendor and version
    const templates = await prisma.palmTemplate.findMany({
      where: {
        active: true,
        sdkVendor: sdkVendor || 'veinshine',
        featureVersion: featureVersion || '1.0'
      },
      include: {
        user: {
          select: {
            id: true,
            displayName: true,
            email: true
          }
        }
      }
    });

    // Return templates for client-side verification
    // In production, you'd do server-side comparison with SDK
    res.json({
      success: true,
      templateCount: templates.length,
      templates: templates.map(t => ({
        id: t.id,
        userId: t.userId,
        user: t.user,
        leftRgbFeature: t.leftRgbFeature,
        leftIrFeature: t.leftIrFeature,
        rightRgbFeature: t.rightRgbFeature,
        rightIrFeature: t.rightIrFeature
      }))
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Palm verification failed',
      error: error.message
    });
  }
};

/**
 * Report successful palm match from palm device
 * Called after palm device successfully matches a user
 */
exports.reportMatch = async (req, res) => {
  try {
    const { userId, location, deviceId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }
    
    // Log to user's authentication history
    const authLog = await prisma.authenticationLog.create({
      data: {
        userId,
        deviceType: 'palm',
        location: location || 'Palm Device',
        success: true
      }
    });
    
    console.log(`[Palm] ✅ Match logged for user ${userId}`);
    res.status(201).json({ success: true, log: authLog });
  } catch (error) {
    console.error('[Palm] Error logging match:', error);
    res.status(500).json({ error: 'Failed to log match' });
  }
};

/**
 * Log authentication attempt from palm device
 * For tracking failed/successful scans
 */
/**
 * Get all device authentication logs
 */
exports.getDeviceLogs = async (req, res, next) => {
  try {
    const logs = await prisma.deviceAuthenticationLog.findMany({
      include: {
        palmDevice: {
          select: {
            name: true,
            location: true
          }
        }
      },
      orderBy: {
        timestamp: 'desc'
      },
      take: 1000 // Limit to last 1000 logs
    });
    
    // Format logs for frontend
    const formattedLogs = logs.map(log => ({
      id: log.id,
      deviceType: log.deviceType,
      location: log.palmDevice?.location || log.location,
      success: log.success,
      reason: log.reason,
      timestamp: log.timestamp,
      palmDeviceId: log.palmDeviceId,
      deviceName: log.palmDevice?.name
    }));
    
    res.json(formattedLogs);
  } catch (error) {
    console.error('Error fetching device logs:', error);
    next(error);
  }
};

/**
 * Log authentication attempt from palm device
 * For tracking failed/successful scans
 */
exports.logAuthAttempt = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const apiToken = authHeader.substring(7);
    const device = await prisma.palmDevice.findUnique({ 
      where: { apiToken } 
    });
    
    if (!device) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const { deviceType, location, success, reason, userId } = req.body;
    
    // Log the device-level auth attempt
    const authLog = await prisma.deviceAuthenticationLog.create({
      data: {
        palmDeviceId: device.id,
        deviceType: deviceType || 'palm',
        location: location || device.location || 'Unknown',
        success: success || false,
        reason: reason || 'Authentication failed',
        timestamp: new Date()
      }
    });

    // If successful and userId provided, also log to user's authentication history
    if (success && userId) {
      try {
        await prisma.authenticationLog.create({
          data: {
            userId: userId,
            deviceType: deviceType || 'palm',
            location: device.location || location || 'Palm Device',
            success: true
          }
        });
        console.log(`[Palm] ✅ Logged authentication for user ${userId}`);
      } catch (userLogError) {
        console.error(`[Palm] ⚠️ Failed to log user authentication:`, userLogError);
        // Don't fail the request if user log fails
      }
    }

    res.json({ success: true, log: authLog });
  } catch (error) {
    console.error('Error logging auth attempt:', error);
    next(error);
  }
};
