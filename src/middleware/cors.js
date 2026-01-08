/**
 * CORS Configuration
 * Implements strict CORS with domain whitelist for production security
 */

/**
 * Allowed origins whitelist
 * Add your production domains here
 */
const ALLOWED_ORIGINS = [
  // Production domains
  'https://palmauth.app',
  'https://www.palmauth.app',
  'https://api.palmauth.app',
  'https://admin.palmauth.app',
  
  // Railway deployment URLs
  'https://palmauth-api-production.up.railway.app',
  'https://palm-payment-api-production-cc5c.up.railway.app',
  
  // iOS app (uses custom URL scheme, but API calls come from these)
  'capacitor://localhost',
  'ionic://localhost',
  
  // Android app WebView
  'http://localhost',
  
  // Development (only in non-production)
  ...(process.env.NODE_ENV !== 'production' ? [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173',
    'http://localhost:8080',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173'
  ] : [])
];

// Add custom origins from environment variable
if (process.env.ALLOWED_ORIGINS) {
  const customOrigins = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
  ALLOWED_ORIGINS.push(...customOrigins);
}

/**
 * CORS options configuration
 */
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) {
      return callback(null, true);
    }

    // Check if origin is in whitelist
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    // Check for wildcard subdomains (e.g., *.palmauth.app)
    const isAllowedSubdomain = ALLOWED_ORIGINS.some(allowed => {
      if (allowed.startsWith('*.')) {
        const domain = allowed.substring(2);
        return origin.endsWith(domain);
      }
      return false;
    });

    if (isAllowedSubdomain) {
      return callback(null, true);
    }

    // Log blocked origin for monitoring
    console.warn(`[CORS] Blocked request from origin: ${origin}`);
    
    // In development, allow all origins with a warning
    if (process.env.NODE_ENV !== 'production') {
      console.warn(`[CORS] Allowing in development mode`);
      return callback(null, true);
    }

    return callback(new Error('Not allowed by CORS'));
  },

  // Allowed HTTP methods
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

  // Allowed headers
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Request-ID',
    'X-Device-ID',
    'Accept',
    'Origin'
  ],

  // Headers exposed to the client
  exposedHeaders: [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'X-Request-ID'
  ],

  // Allow credentials (cookies, authorization headers)
  credentials: true,

  // Preflight cache duration (24 hours)
  maxAge: 86400,

  // Success status for legacy browsers
  optionsSuccessStatus: 200
};

/**
 * Strict CORS middleware - rejects non-whitelisted origins
 */
function strictCors(req, res, next) {
  const origin = req.headers.origin;

  // Set Vary header for caching
  res.setHeader('Vary', 'Origin');

  if (!origin) {
    // No origin header (server-to-server, mobile apps)
    return next();
  }

  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Request-ID, X-Device-ID');
    res.setHeader('Access-Control-Expose-Headers', 'X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Handle preflight
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    return next();
  }

  // Block non-whitelisted origins in production
  if (process.env.NODE_ENV === 'production') {
    console.warn(`[CORS] Blocked origin: ${origin}`);
    return res.status(403).json({
      error: 'cors_error',
      error_description: 'Origin not allowed'
    });
  }

  // Allow in development with warning
  console.warn(`[CORS] Non-whitelisted origin allowed in dev: ${origin}`);
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Request-ID, X-Device-ID');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  next();
}

/**
 * Add origin to whitelist dynamically
 */
function addAllowedOrigin(origin) {
  if (!ALLOWED_ORIGINS.includes(origin)) {
    ALLOWED_ORIGINS.push(origin);
    console.log(`[CORS] Added origin to whitelist: ${origin}`);
  }
}

/**
 * Remove origin from whitelist
 */
function removeAllowedOrigin(origin) {
  const index = ALLOWED_ORIGINS.indexOf(origin);
  if (index > -1) {
    ALLOWED_ORIGINS.splice(index, 1);
    console.log(`[CORS] Removed origin from whitelist: ${origin}`);
  }
}

module.exports = {
  corsOptions,
  strictCors,
  addAllowedOrigin,
  removeAllowedOrigin,
  ALLOWED_ORIGINS
};
