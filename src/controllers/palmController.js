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
