const { PrismaClient } = require('@prisma/client');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();

exports.getAllUsers = async (req, res, next) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        displayName: true,
        email: true,
        createdAt: true
      },
      orderBy: {
        displayName: 'asc'
      }
    });
    res.json(users);
  } catch (error) {
    next(error);
  }
};

exports.createUser = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { displayName, email } = req.body;

    const user = await prisma.user.create({
      data: {
        displayName,
        email: email || null
      }
    });

    const token = jwt.sign(
      { userId: user.id, displayName: user.displayName },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      user: {
        id: user.id,
        displayName: user.displayName,
        email: user.email,
        createdAt: user.createdAt
      },
      token
    });
  } catch (error) {
    next(error);
  }
};

exports.getUser = async (req, res, next) => {
  try {
    const { userId } = req.params;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        palmTemplates: {
          where: { active: true },
          select: {
            id: true,
            sdkVendor: true,
            featureVersion: true,
            enrolledAt: true,
            active: true
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'User not found'
      });
    }

    res.json({ user });
  } catch (error) {
    next(error);
  }
};

exports.searchUserByDisplayName = async (req, res, next) => {
  try {
    const { displayName } = req.query;

    if (!displayName) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'displayName query parameter is required'
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        displayName: {
          equals: displayName,
          mode: 'insensitive'
        }
      },
      select: {
        id: true,
        displayName: true,
        email: true
      }
    });

    if (!user) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'User not found'
      });
    }

    res.json({ user });
  } catch (error) {
    next(error);
  }
};

exports.updateUser = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { displayName, email, phoneNumber, paymentMethod } = req.body;

    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        ...(displayName && { displayName }),
        ...(email !== undefined && { email }),
        ...(phoneNumber !== undefined && { phoneNumber }),
        ...(paymentMethod !== undefined && { paymentMethod })
      }
    });

    res.json({ user });
  } catch (error) {
    next(error);
  }
};

exports.logAuthentication = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { deviceType, location, success } = req.body;

    const log = await prisma.authenticationLog.create({
      data: {
        userId,
        deviceType: deviceType || 'unknown',
        location: location || null,
        success: success !== undefined ? success : true
      }
    });

    res.status(201).json({ log });
  } catch (error) {
    next(error);
  }
};

exports.getAuthenticationHistory = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const logs = await prisma.authenticationLog.findMany({
      where: { userId },
      orderBy: { authenticatedAt: 'desc' },
      take: limit,
      skip: offset
    });

    const total = await prisma.authenticationLog.count({
      where: { userId }
    });

    res.json({ 
      logs,
      total,
      limit,
      offset
    });
  } catch (error) {
    next(error);
  }
};

// Card Management
exports.createCard = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { userId } = req.params;
    const { type, name, cardNumber, barcodeData, color, notes } = req.body;

    const card = await prisma.card.create({
      data: {
        userId,
        type,
        name,
        cardNumber,
        barcodeData: barcodeData || null,
        color: color || '#3B82F6',
        notes: notes || null
      }
    });

    res.status(201).json({ card });
  } catch (error) {
    next(error);
  }
};

exports.getUserCards = async (req, res, next) => {
  try {
    const { userId } = req.params;

    const cards = await prisma.card.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' }
    });

    res.json({ cards });
  } catch (error) {
    next(error);
  }
};

exports.updateCard = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { cardId } = req.params;
    const { type, name, cardNumber, barcodeData, color, notes } = req.body;

    const card = await prisma.card.update({
      where: { id: cardId },
      data: {
        type,
        name,
        cardNumber,
        barcodeData,
        color,
        notes
      }
    });

    res.json({ card });
  } catch (error) {
    next(error);
  }
};

exports.deleteCard = async (req, res, next) => {
  try {
    const { cardId } = req.params;

    await prisma.card.delete({
      where: { id: cardId }
    });

    res.json({ message: 'Card deleted successfully' });
  } catch (error) {
    next(error);
  }
};

// Get user redemptions
exports.getUserRedemptions = async (req, res, next) => {
  try {
    const { userId } = req.params;

    const redemptions = await prisma.redemption.findMany({
      where: { userId },
      orderBy: { redeemedAt: 'desc' },
      take: 50
    });

    res.json({ redemptions });
  } catch (error) {
    next(error);
  }
};
