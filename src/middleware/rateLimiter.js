/**
 * Rate Limiting Middleware
 * Implements per-IP and per-API-key rate limiting to protect against abuse
 */

// In-memory store for rate limiting (use Redis in production for distributed systems)
const rateLimitStore = new Map();
const apiKeyStore = new Map();

// Clean up expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now > data.resetTime) {
      rateLimitStore.delete(key);
    }
  }
  for (const [key, data] of apiKeyStore.entries()) {
    if (now > data.resetTime) {
      apiKeyStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

/**
 * Get client IP address
 */
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection?.remoteAddress ||
         req.socket?.remoteAddress ||
         'unknown';
}

/**
 * Rate limiter configuration
 */
const RATE_LIMITS = {
  // General API limits per IP
  default: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5000,
    message: 'Too many requests from this IP, please try again later'
  },
  // Auth endpoints - generous limits for registration/login
  auth: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxRequests: 500,
    message: 'Too many authentication attempts, please try again later'
  },
  // Palm device endpoints (higher limits for devices)
  palmDevice: {
    windowMs: 1 * 60 * 1000, // 1 minute
    maxRequests: 600,
    message: 'Rate limit exceeded for palm device'
  },
  // API key limits (per key)
  apiKey: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 1000,
    message: 'API key rate limit exceeded'
  }
};

/**
 * Create rate limiter middleware
 * @param {string} type - Rate limit type: 'default', 'auth', 'palmDevice', 'apiKey'
 */
function createRateLimiter(type = 'default') {
  const config = RATE_LIMITS[type] || RATE_LIMITS.default;

  return (req, res, next) => {
    const clientIP = getClientIP(req);
    const apiKey = req.headers['x-api-key'];
    const now = Date.now();

    // Check API key rate limit if provided
    if (apiKey && type === 'apiKey') {
      const keyData = apiKeyStore.get(apiKey) || {
        count: 0,
        resetTime: now + config.windowMs
      };

      if (now > keyData.resetTime) {
        keyData.count = 0;
        keyData.resetTime = now + config.windowMs;
      }

      keyData.count++;
      apiKeyStore.set(apiKey, keyData);

      // Set rate limit headers
      res.set({
        'X-RateLimit-Limit': config.maxRequests,
        'X-RateLimit-Remaining': Math.max(0, config.maxRequests - keyData.count),
        'X-RateLimit-Reset': Math.ceil(keyData.resetTime / 1000)
      });

      if (keyData.count > config.maxRequests) {
        console.warn(`[RateLimit] API key rate limit exceeded: ${apiKey.substring(0, 8)}...`);
        return res.status(429).json({
          error: 'Too Many Requests',
          message: config.message,
          retryAfter: Math.ceil((keyData.resetTime - now) / 1000)
        });
      }
    }

    // Check IP rate limit
    const ipKey = `${type}:${clientIP}`;
    const ipData = rateLimitStore.get(ipKey) || {
      count: 0,
      resetTime: now + config.windowMs
    };

    if (now > ipData.resetTime) {
      ipData.count = 0;
      ipData.resetTime = now + config.windowMs;
    }

    ipData.count++;
    rateLimitStore.set(ipKey, ipData);

    // Set rate limit headers
    res.set({
      'X-RateLimit-Limit': config.maxRequests,
      'X-RateLimit-Remaining': Math.max(0, config.maxRequests - ipData.count),
      'X-RateLimit-Reset': Math.ceil(ipData.resetTime / 1000)
    });

    if (ipData.count > config.maxRequests) {
      console.warn(`[RateLimit] IP rate limit exceeded: ${clientIP} on ${type}`);
      return res.status(429).json({
        error: 'Too Many Requests',
        message: config.message,
        retryAfter: Math.ceil((ipData.resetTime - now) / 1000)
      });
    }

    next();
  };
}

// Pre-configured rate limiters
const defaultLimiter = createRateLimiter('default');
const authLimiter = createRateLimiter('auth');
const palmDeviceLimiter = createRateLimiter('palmDevice');
const apiKeyLimiter = createRateLimiter('apiKey');

module.exports = {
  createRateLimiter,
  defaultLimiter,
  authLimiter,
  palmDeviceLimiter,
  apiKeyLimiter,
  getClientIP
};
