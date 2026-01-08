const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Get all products
router.get('/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { active: true },
      orderBy: { name: 'asc' }
    });
    res.json({ products });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Create product
router.post('/products', async (req, res) => {
  try {
    const { name, description, price, imageUrl, stock } = req.body;
    const product = await prisma.product.create({
      data: {
        name,
        description,
        price: parseFloat(price),
        imageUrl,
        stock: parseInt(stock) || 0
      }
    });
    res.json({ product });
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// Update product
router.put('/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, imageUrl, stock, active } = req.body;
    const product = await prisma.product.update({
      where: { id },
      data: {
        name,
        description,
        price: parseFloat(price),
        imageUrl,
        stock: parseInt(stock),
        active
      }
    });
    res.json({ product });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Delete product
router.delete('/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.product.update({
      where: { id },
      data: { active: false }
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Create order
router.post('/orders', async (req, res) => {
  try {
    const { customerName, items } = req.body;
    
    // Calculate total
    let totalAmount = 0;
    const orderItems = [];
    
    for (const item of items) {
      const product = await prisma.product.findUnique({
        where: { id: item.productId }
      });
      
      if (!product) {
        return res.status(404).json({ error: `Product ${item.productId} not found` });
      }
      
      const itemTotal = product.price * item.quantity;
      totalAmount += parseFloat(itemTotal);
      
      orderItems.push({
        productId: item.productId,
        quantity: item.quantity,
        price: product.price
      });
    }
    
    // Create order with items
    const order = await prisma.order.create({
      data: {
        customerName,
        status: 'pending',
        totalAmount,
        items: {
          create: orderItems
        }
      },
      include: {
        items: {
          include: {
            product: true
          }
        }
      }
    });
    
    res.json({ order });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Get all orders
router.get('/orders', async (req, res) => {
  try {
    const { status } = req.query;
    const where = status ? { status } : {};
    
    const orders = await prisma.order.findMany({
      where,
      include: {
        items: {
          include: {
            product: true
          }
        },
        customer: true
      },
      orderBy: { createdAt: 'desc' }
    });
    
    res.json({ orders });
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order
router.get('/orders/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const order = await prisma.order.findUnique({
      where: { id },
      include: {
        items: {
          include: {
            product: true
          }
        }
      }
    });
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json({ order });
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Complete order (from palm device)
router.post('/orders/:id/complete', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const order = await prisma.order.update({
      where: { id },
      data: {
        status: status || 'completed',
        completedAt: new Date()
      },
      include: {
        items: {
          include: {
            product: true
          }
        }
      }
    });
    
    res.json({ order });
  } catch (error) {
    console.error('Error completing order:', error);
    res.status(500).json({ error: 'Failed to complete order' });
  }
});

// CAMPAIGN VERIFICATIONS - Palm device polls for pending verifications
// Mounted at /api/verifications so this handles GET /api/verifications
router.get('/', async (req, res) => {
  try {
    const { status, palmDeviceId } = req.query;
    
    // Query the campaign API for pending verifications
    const campaignAPI = process.env.CAMPAIGN_API_URL || 'https://palm-payment-api-production-cc5c.up.railway.app/api/v1';
    
    if (status === 'pending' && palmDeviceId) {
      // Fetch from campaign API
      const response = await fetch(`${campaignAPI}/palm-devices/${palmDeviceId}/pending-verifications`);
      const data = await response.json();
      
      if (data.pending) {
        // Format like orders for consistency
        res.json({ 
          verifications: [{
            id: data.verification.id,
            challengeCode: data.verification.challengeCode,
            userId: data.verification.userId,
            userName: data.verification.userName,
            campaign: data.verification.campaign,
            type: 'campaign_redemption',
            status: 'pending',
            expiresAt: data.verification.expiresAt
          }]
        });
      } else {
        res.json({ verifications: [] });
      }
    } else {
      res.json({ verifications: [] });
    }
  } catch (error) {
    console.error('Error fetching verifications:', error);
    res.status(500).json({ error: 'Failed to fetch verifications', verifications: [] });
  }
});

// Complete order from Palm device (workshop dashboard orders)
router.post('/palm/complete-order/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, customerId, customerName } = req.body;
    
    const order = await prisma.order.update({
      where: { id },
      data: {
        status,
        customerId,
        customerName,
        completedAt: new Date()
      },
      include: {
        items: {
          include: {
            product: true
          }
        }
      }
    });
    
    res.json({ order });
  } catch (error) {
    console.error('Error completing order from palm device:', error);
    res.status(500).json({ error: 'Failed to complete order' });
  }
});

// Get user redemption history (mounted at /api/redemptions)
router.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit } = req.query;
    
    const redemptions = await prisma.redemption.findMany({
      where: { userId },
      orderBy: { redeemedAt: 'desc' },
      take: limit ? parseInt(limit) : undefined,
      include: {
        card: true
      }
    });
    
    res.json({ redemptions });
  } catch (error) {
    console.error('Error fetching redemptions:', error);
    res.status(500).json({ error: 'Failed to fetch redemptions' });
  }
});

// Complete verification (from palm device)
router.post('/verifications/:id/complete', async (req, res) => {
  try {
    const { id } = req.params;
    const { palmVerified, userId, location } = req.body;
    
    const campaignAPI = process.env.CAMPAIGN_API_URL || 'https://palm-payment-api-production-cc5c.up.railway.app/api/v1';
    
    // Forward to campaign API
    const response = await fetch(`${campaignAPI}/verification/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sessionId: id,
        palmVerified,
        userId,
        location
      })
    });
    
    const data = await response.json();
    
    // If verification succeeded, create redemption record
    if (data.success && data.session?.status === 'verified' && data.redemption) {
      const redemption = data.redemption;
      await prisma.redemption.create({
        data: {
          userId: redemption.userId,
          userName: redemption.userName,
          cardId: redemption.userCardId,
          campaignName: redemption.campaignName,
          campaignVendor: redemption.vendorName,
          palmDeviceId: req.body.palmDeviceId,
          location: location || 'Unknown',
          status: 'verified'
        }
      });
      console.log(`✓ Redemption logged for ${redemption.userName}: ${redemption.campaignName}`);
    }
    
    res.json(data);
  } catch (error) {
    console.error('Error completing verification from palm device:', error);
    res.status(500).json({ error: 'Failed to complete verification' });
  }
});

module.exports = router;
