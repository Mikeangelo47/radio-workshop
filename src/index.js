require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const crypto = require('crypto');

// Routes
const userRoutes = require('./routes/users');
const palmRoutes = require('./routes/palm');
const storeRoutes = require('./routes/store');
const authRoutes = require('./routes/auth');
const authFullRoutes = require('./routes/auth-full');
const oauthRoutes = require('./routes/oauth');

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

// OAuth 2.0 / OpenID Connect endpoints
app.use('/oauth', oauthRoutes);
app.use('/.well-known', oauthRoutes);

// API v1 routes
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/palm', palmRoutes);
app.use('/api/v1/store', storeRoutes);
app.use('/api/v1/auth', authLimiter, authRoutes);
app.use('/api/v2/auth', authLimiter, authFullRoutes);

// Legacy API routes for web-admin compatibility
app.use('/api/orders', storeRoutes);
app.use('/api/products', storeRoutes);
app.use('/api/verifications', storeRoutes);  // Campaign verifications - same pattern as orders
app.use('/api/palm-devices', palmRoutes);
app.use('/api/palm', storeRoutes);  // Palm device order completion
app.use('/api/redemptions', storeRoutes);  // Redemption history

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
