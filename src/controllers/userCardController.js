const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Campaign API URL for fetching campaign details
const CAMPAIGN_API_URL = process.env.CAMPAIGN_API_URL || 'https://biopia-campaigns.vercel.app/api';

// Get user's campaign cards
exports.getUserCards = async (req, res, next) => {
  try {
    const { userId } = req.params;

    const cards = await prisma.userCard.findMany({
      where: { userId, active: true },
      orderBy: { addedAt: 'desc' }
    });

    // Format response to match iOS app expectations
    const formattedCards = cards.map(card => ({
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
      campaign: {
        id: card.campaignId,
        name: card.cardName,
        description: card.cardDescription,
        discountType: card.discountType,
        discountValue: card.discountValue,
        vendor: {
          name: card.vendorName,
          logo: card.vendorLogo
        }
      },
      _count: {
        redemptions: 0 // TODO: Count actual redemptions
      }
    }));

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
    const vendorLogo = campaignData?.business?.logo || null;
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
    campaign: {
      id: card.campaignId,
      name: card.cardName,
      description: card.cardDescription,
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
