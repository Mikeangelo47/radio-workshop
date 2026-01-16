const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;

// Campaign API URL for fetching campaign details
const CAMPAIGN_API_URL = process.env.CAMPAIGN_API_URL || 'https://biopia-campaigns.vercel.app/api';

// Base URL for uploaded images
const UPLOAD_BASE_URL = process.env.UPLOAD_BASE_URL || 'https://palm-payment-api-production.up.railway.app';

// Get user's campaign cards
exports.getUserCards = async (req, res, next) => {
  try {
    const { userId } = req.params;

    const cards = await prisma.userCard.findMany({
      where: { userId, active: true },
      orderBy: { addedAt: 'desc' }
    });

    // Format response to match iOS app expectations
    const formattedCards = cards.map(card => formatUserCard(card));

    res.json({ cards: formattedCards });
  } catch (error) {
    console.error('Error getting user cards:', error);
    next(error);
  }
};

// Add campaign card to user wallet
exports.addCardToWallet = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { campaignId } = req.body;

    if (!campaignId) {
      return res.status(400).json({ error: 'campaignId is required' });
    }

    console.log(`[UserCard] Adding card for user ${userId}, campaign ${campaignId}`);

    // Check if user already has this card
    const existingCard = await prisma.userCard.findUnique({
      where: {
        userId_campaignId: { userId, campaignId }
      }
    });

    if (existingCard) {
      console.log(`[UserCard] Card already exists for user ${userId}`);
      // Return existing card
      const formattedCard = formatUserCard(existingCard);
      return res.json({
        userCard: formattedCard,
        alreadyAdded: true
      });
    }

    // Fetch campaign details from BIOPIA Campaign Portal
    let campaignData = null;
    try {
      const response = await fetch(`${CAMPAIGN_API_URL}/campaigns/${campaignId}/public`);
      if (response.ok) {
        const data = await response.json();
        campaignData = data.campaign;
      }
    } catch (fetchError) {
      console.log(`[UserCard] Could not fetch campaign from portal: ${fetchError.message}`);
    }

    // Create card with campaign data or defaults
    const cardName = campaignData?.displayName || 'Campaign Card';
    const cardDescription = campaignData?.description || null;
    const backgroundColor = campaignData?.design?.backgroundColor || '#1a1a2e';
    const textColor = campaignData?.design?.textColor || '#ffffff';
    const discountType = campaignData?.discountType || 'PERCENTAGE';
    const discountValue = campaignData?.discountValue || 0;
    const vendorName = campaignData?.business?.name || 'BIOPIA Partner';
    // Use campaign design logo first, fall back to business logo
    const vendorLogo = campaignData?.design?.logoUrl || campaignData?.business?.logo || null;
    const cardImageUrl = campaignData?.design?.coverImageUrl || null;

    const newCard = await prisma.userCard.create({
      data: {
        userId,
        campaignId,
        cardName,
        cardDescription,
        cardImageUrl,
        backgroundColor,
        textColor,
        discountType,
        discountValue,
        vendorName,
        vendorLogo
      }
    });

    console.log(`[UserCard] Created new card ${newCard.id} for user ${userId}`);

    const formattedCard = formatUserCard(newCard);
    res.status(201).json({
      userCard: formattedCard,
      alreadyAdded: false
    });
  } catch (error) {
    console.error('Error adding card to wallet:', error);
    next(error);
  }
};

// Helper function to format UserCard for iOS app
function formatUserCard(card) {
  return {
    id: card.id,
    userId: card.userId,
    campaignId: card.campaignId,
    cardName: card.cardName,
    cardDescription: card.cardDescription,
    cardImageUrl: card.cardImageUrl,
    backgroundColor: card.backgroundColor,
    textColor: card.textColor,
    active: card.active,
    addedAt: card.addedAt.toISOString(),
    lastUsedAt: card.lastUsedAt ? card.lastUsedAt.toISOString() : null,
    // New fields for iOS app
    businessLogoURL: card.vendorLogo,
    userCoverImageURL: card.userCoverImageURL,
    campaign: {
      id: card.campaignId,
      name: card.cardName,
      description: card.cardDescription,
      type: 'loyalty',
      imageUrl: card.cardImageUrl,
      backgroundColor: card.backgroundColor,
      textColor: card.textColor,
      startDate: card.addedAt.toISOString(),
      endDate: null,
      discountType: card.discountType,
      discountValue: card.discountValue,
      vendor: {
        name: card.vendorName,
        logo: card.vendorLogo
      }
    },
    _count: {
      redemptions: 0
    }
  };
}

// Remove card from user wallet
exports.removeCardFromWallet = async (req, res, next) => {
  try {
    const { userId, cardId } = req.params;

    const card = await prisma.userCard.findFirst({
      where: { id: cardId, userId }
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    await prisma.userCard.update({
      where: { id: cardId },
      data: { active: false }
    });

    res.json({ success: true, message: 'Card removed from wallet' });
  } catch (error) {
    console.error('Error removing card from wallet:', error);
    next(error);
  }
};

// Upload cover image for a card
exports.uploadCardCoverImage = async (req, res, next) => {
  try {
    const { cardId } = req.params;
    
    console.log(`[UserCard] Uploading cover image for card ${cardId}`);

    // Check if card exists
    const card = await prisma.userCard.findUnique({
      where: { id: cardId }
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Generate unique filename
    const ext = path.extname(req.file.originalname) || '.jpg';
    const filename = `card-cover-${cardId}-${uuidv4()}${ext}`;
    
    // Ensure uploads directory exists
    const uploadsDir = path.join(process.cwd(), 'public', 'uploads', 'cards');
    await fs.mkdir(uploadsDir, { recursive: true });
    
    // Save file
    const filepath = path.join(uploadsDir, filename);
    await fs.writeFile(filepath, req.file.buffer);
    
    // Generate public URL
    const imageUrl = `${UPLOAD_BASE_URL}/uploads/cards/${filename}`;
    
    // Update card with new cover image URL
    const updatedCard = await prisma.userCard.update({
      where: { id: cardId },
      data: { userCoverImageURL: imageUrl }
    });

    console.log(`[UserCard] Cover image uploaded: ${imageUrl}`);

    res.json({ 
      url: imageUrl,
      card: formatUserCard(updatedCard)
    });
  } catch (error) {
    console.error('Error uploading card cover image:', error);
    next(error);
  }
};

// Remove cover image from a card
exports.removeCardCoverImage = async (req, res, next) => {
  try {
    const { cardId } = req.params;

    const card = await prisma.userCard.findUnique({
      where: { id: cardId }
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Update card to remove cover image URL
    const updatedCard = await prisma.userCard.update({
      where: { id: cardId },
      data: { userCoverImageURL: null }
    });

    console.log(`[UserCard] Cover image removed for card ${cardId}`);

    res.json({ 
      success: true,
      card: formatUserCard(updatedCard)
    });
  } catch (error) {
    console.error('Error removing card cover image:', error);
    next(error);
  }
};
