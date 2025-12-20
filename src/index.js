require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');

const userRoutes = require('./routes/users');
const palmRoutes = require('./routes/palm');
const storeRoutes = require('./routes/store');
const authRoutes = require('./routes/auth');
const errorHandler = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure helmet to allow inline scripts for admin dashboard
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../public')));

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Redirect root to admin dashboard
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

app.use('/api/v1/users', userRoutes);
app.use('/api/v1/palm', palmRoutes);
app.use('/api/v1/store', storeRoutes);
app.use('/api/v1/auth', authRoutes);

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
