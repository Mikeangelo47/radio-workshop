const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Campaign API URL for fetching campaign details from BIOPIA Campaign Portal
const CAMPAIGN_PORTAL_URL = process.env.CAMPAIGN_PORTAL_URL || 'https://biopia-campaigns.vercel.app/api';

// Resolve campaign from QR token (campaignId)
// GET /api/v1/q/:token
router.get('/q/:token', async (req, res, next) => {
  try {
    const { token } = req.params;
    console.log(`[Campaign] Resolving token: ${token}`);

    // The token is the campaignId from the QR code
    // Try to parse it as JSON first (new QR format)
    let campaignId = token;
    try {
      const parsed = JSON.parse(decodeURIComponent(token));
      if (parsed.campaignId) {
        campaignId = parsed.campaignId;
      }
    } catch (e) {
      // Token is not JSON, use as-is (direct campaignId)
    }

    console.log(`[Campaign] Looking up campaignId: ${campaignId}`);

    // First check if we have this campaign in local UserCard records
    const existingCard = await prisma.userCard.findFirst({
      where: { campaignId }
    });

    if (existingCard) {
      // Return campaign data from existing card
      const campaign = {
        id: existingCard.campaignId,
        name: existingCard.cardName,
        description: existingCard.cardDescription,
        type: 'loyalty',
        imageUrl: existingCard.cardImageUrl,
        backgroundColor: existingCard.backgroundColor,
        textColor: existingCard.textColor,
        startDate: new Date().toISOString(),
        endDate: null,
        discountType: existingCard.discountType,
        discountValue: existingCard.discountValue,
        vendor: {
          name: existingCard.vendorName || 'BIOPIA Partner',
          logo: existingCard.vendorLogo
        }
      };

      console.log(`[Campaign] Found in local DB: ${campaign.name}`);
      return res.json({ campaign });
    }

    // Try to fetch from BIOPIA Campaign Portal
    try {
      const response = await fetch(`${CAMPAIGN_PORTAL_URL}/campaigns/${campaignId}/public`);
      if (response.ok) {
        const data = await response.json();
        const portalCampaign = data.campaign;

        const campaign = {
          id: portalCampaign.id,
          name: portalCampaign.displayName,
          description: portalCampaign.description,
          type: 'loyalty',
          imageUrl: portalCampaign.design?.coverImageUrl,
          backgroundColor: portalCampaign.design?.backgroundColor || '#1a1a2e',
          textColor: portalCampaign.design?.textColor || '#ffffff',
          startDate: portalCampaign.startsAt || new Date().toISOString(),
          endDate: portalCampaign.endsAt,
          discountType: portalCampaign.discountType,
          discountValue: portalCampaign.discountValue,
          vendor: {
            name: portalCampaign.business?.name || 'BIOPIA Partner',
            logo: portalCampaign.business?.logo
          }
        };

        console.log(`[Campaign] Found in portal: ${campaign.name}`);
        return res.json({ campaign });
      }
    } catch (fetchError) {
      console.log(`[Campaign] Could not fetch from portal: ${fetchError.message}`);
    }

    // Return a default campaign if not found anywhere
    // This allows the user to still add the card
    const defaultCampaign = {
      id: campaignId,
      name: 'Campaign Card',
      description: 'Discount campaign',
      type: 'loyalty',
      imageUrl: null,
      backgroundColor: '#1a1a2e',
      textColor: '#ffffff',
      startDate: new Date().toISOString(),
      endDate: null,
      discountType: 'PERCENTAGE',
      discountValue: 0,
      vendor: {
        name: 'BIOPIA Partner',
        logo: null
      }
    };

    console.log(`[Campaign] Using default campaign for: ${campaignId}`);
    return res.json({ campaign: defaultCampaign });

  } catch (error) {
    console.error('[Campaign] Error resolving token:', error);
    next(error);
  }
});

module.exports = router;
