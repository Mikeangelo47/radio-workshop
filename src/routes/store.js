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

module.exports = router;
