require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const crypto = require('crypto');

// Routes
const userRoutes = require('./routes/users');
const userCardRoutes = require('./routes/userCards');
const campaignRoutes = require('./routes/campaigns');
const palmRoutes = require('./routes/palm');
const storeRoutes = require('./routes/store');
const authRoutes = require('./routes/auth');
const authFullRoutes = require('./routes/auth-full');
const oauthRoutes = require('./routes/oauth');
const deviceContentRoutes = require('./routes/deviceContent');
const biopiatDisplayRoutes = require('./routes/biopiatDisplay');

// Middleware
const errorHandler = require('./middleware/errorHandler');
const { corsOptions, strictCors } = require('./middleware/cors');
const { defaultLimiter, authLimiter } = require('./middleware/rateLimiter');
const { requireHttps } = require('./middleware/security');

const app = express();
const PORT = process.env.PORT || 3000;

// Generate request ID for tracing
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// HTTPS enforcement in production
if (process.env.NODE_ENV === 'production') {
  app.use(requireHttps);
}

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://palmauth-api-production.up.railway.app", "https://palm-payment-api-production-cc5c.up.railway.app"]
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// CORS with domain whitelist
app.use(cors(corsOptions));

// Request logging
app.use(morgan('combined'));

// Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Global rate limiting
app.use('/api', defaultLimiter);

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../public')));

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Redirect root to admin dashboard
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

// Password reset page
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/reset-password.html'));
});

// Email verification page
app.get('/verify-email', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/verify-email.html'));
});

// OAuth 2.0 / OpenID Connect endpoints
app.use('/oauth', oauthRoutes);
app.use('/.well-known', oauthRoutes);

// API v1 routes
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/users', userCardRoutes);  // Campaign card routes (same base path)
app.use('/api/v1', campaignRoutes);  // Campaign resolution routes (/api/v1/q/:token)
app.use('/api/v1/palm', palmRoutes);
app.use('/api/v1/store', storeRoutes);
app.use('/api/v1/auth', authLimiter, authRoutes);
app.use('/api/v2/auth', authLimiter, authFullRoutes);

// Legacy API routes for web-admin compatibility
app.get('/api/orders', async (req, res) => {
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient();
  try {
    const { status } = req.query;
    const where = status ? { status } : {};
    const orders = await prisma.order.findMany({
      where,
      include: {
        items: { include: { product: true } },
        customer: true
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json({ orders });
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders', orders: [] });
  }
});
app.use('/api/products', storeRoutes);
app.use('/api/verifications', storeRoutes);  // Campaign verifications - same pattern as orders
app.use('/api/palm-devices', palmRoutes);
app.use('/api/v1/palm-devices', palmRoutes);  // Palm device endpoints (v1 path)
app.use('/api/palm', storeRoutes);  // Palm device order completion
app.use('/api/redemptions', storeRoutes);  // Redemption history

// Device Content API (ads, announcements, media for palm devices)
app.use('/api/device-content/v1', deviceContentRoutes);

// BIOPIAT Display System API (bottom-half display panel)
app.use('/api/biopiat-display/v1', biopiatDisplayRoutes);

// 404 handler for API routes only
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`🚀 Palm Auth Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV}`);
  console.log(`🗄️  Database: ${process.env.DATABASE_URL?.split('@')[1] || 'Not configured'}`);
});

module.exports = app;

// Force redeploy
