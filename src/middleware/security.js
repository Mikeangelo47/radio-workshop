/**
 * Security Middleware
 * Implements OAuth 2.0 / OpenID Connect authentication and role-based access control
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_ISSUER = process.env.JWT_ISSUER || 'palm-auth-api';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'palm-auth-clients';
const ACCESS_TOKEN_EXPIRY = '15m';  // Short-lived access tokens
const REFRESH_TOKEN_EXPIRY = '7d';  // Longer-lived refresh tokens

/**
 * User roles and their permissions (Principle of Least Privilege)
 */
const ROLES = {
  // End users - can only access their own data
  user: {
    permissions: [
      'read:own_profile',
      'update:own_profile',
      'read:own_cards',
      'create:own_cards',
      'update:own_cards',
      'delete:own_cards',
      'read:own_auth_history',
      'read:own_redemptions',
      'create:palm_enrollment'
    ]
  },
  // Palm devices - can verify palms and complete transactions
  device: {
    permissions: [
      'read:palm_templates',
      'verify:palm',
      'read:pending_orders',
      'complete:orders',
      'read:pending_verifications',
      'complete:verifications',
      'create:auth_log'
    ]
  },
  // Store operators - can manage products and view orders
  operator: {
    permissions: [
      'read:products',
      'create:products',
      'update:products',
      'read:orders',
      'create:orders',
      'update:orders',
      'read:verifications'
    ]
  },
  // Administrators - full access
  admin: {
    permissions: [
      'read:users',
      'create:users',
      'update:users',
      'delete:users',
      'read:all_cards',
      'read:all_auth_history',
      'read:all_redemptions',
      'read:products',
      'create:products',
      'update:products',
      'delete:products',
      'read:orders',
      'create:orders',
      'update:orders',
      'delete:orders',
      'read:palm_templates',
      'manage:devices',
      'read:access_logs',
      'manage:system'
    ]
  }
};

/**
 * Generate access token (OAuth 2.0 compatible)
 */
function generateAccessToken(payload) {
  return jwt.sign(
    {
      ...payload,
      iss: JWT_ISSUER,
      aud: JWT_AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      token_type: 'access_token'
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
}

/**
 * Generate refresh token
 */
function generateRefreshToken(payload) {
  const refreshToken = jwt.sign(
    {
      sub: payload.sub,
      iss: JWT_ISSUER,
      aud: JWT_AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      token_type: 'refresh_token',
      jti: crypto.randomUUID() // Unique token ID for revocation
    },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
  return refreshToken;
}

/**
 * Generate ID token (OpenID Connect)
 */
function generateIdToken(user) {
  return jwt.sign(
    {
      iss: JWT_ISSUER,
      sub: user.id,
      aud: JWT_AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      auth_time: Math.floor(Date.now() / 1000),
      // Standard OIDC claims
      name: user.displayName,
      email: user.email,
      email_verified: user.emailVerified || false,
      // Custom claims
      role: user.role || 'user'
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
}

/**
 * Verify and decode JWT token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE
    });
  } catch (error) {
    return null;
  }
}

/**
 * Authentication middleware - validates Bearer token
 */
function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Missing or invalid authorization header'
      });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Token is invalid or expired'
      });
    }

    if (decoded.token_type !== 'access_token') {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid token type'
      });
    }

    // Attach user info to request
    req.user = {
      id: decoded.sub,
      role: decoded.role || 'user',
      permissions: ROLES[decoded.role]?.permissions || ROLES.user.permissions,
      deviceId: decoded.device_id,
      apiKeyId: decoded.api_key_id
    };

    next();
  } catch (error) {
    console.error('[Security] Authentication error:', error);
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Token verification failed'
    });
  }
}

/**
 * Optional authentication - doesn't fail if no token, but attaches user if present
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);

    if (decoded && decoded.token_type === 'access_token') {
      req.user = {
        id: decoded.sub,
        role: decoded.role || 'user',
        permissions: ROLES[decoded.role]?.permissions || ROLES.user.permissions
      };
    }
  }

  next();
}

/**
 * Authorization middleware - checks if user has required permission
 * @param {string} permission - Required permission (e.g., 'read:users')
 */
function authorize(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
    }

    const userPermissions = req.user.permissions || [];

    // Check for exact permission or wildcard
    const hasPermission = userPermissions.includes(permission) ||
                          userPermissions.includes('manage:system');

    if (!hasPermission) {
      console.warn(`[Security] Access denied: ${req.user.id} lacks permission ${permission}`);
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Missing required permission: ${permission}`
      });
    }

    next();
  };
}

/**
 * Resource ownership check - ensures user can only access their own resources
 * @param {string} paramName - Request parameter containing resource owner ID
 */
function requireOwnership(paramName = 'userId') {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
    }

    const resourceOwnerId = req.params[paramName];
    const isAdmin = req.user.role === 'admin';
    const isOwner = req.user.id === resourceOwnerId;

    if (!isAdmin && !isOwner) {
      return res.status(403).json({
        error: 'access_denied',
        error_description: 'You can only access your own resources'
      });
    }

    next();
  };
}

/**
 * API Key authentication for palm devices and external integrations
 */
async function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'API key required'
    });
  }

  try {
    // Hash the API key to compare with stored hash
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    // Look up API key in database (you'll need to add ApiKey model to Prisma)
    // For now, check against environment variable for device tokens
    const validDeviceToken = process.env.PALM_DEVICE_API_KEY;

    if (apiKey === validDeviceToken) {
      req.user = {
        id: 'palm-device',
        role: 'device',
        permissions: ROLES.device.permissions,
        apiKeyId: 'device-key'
      };
      return next();
    }

    // Check for admin API key
    const adminApiKey = process.env.ADMIN_API_KEY;
    if (apiKey === adminApiKey) {
      req.user = {
        id: 'admin',
        role: 'admin',
        permissions: ROLES.admin.permissions,
        apiKeyId: 'admin-key'
      };
      return next();
    }

    return res.status(401).json({
      error: 'invalid_api_key',
      error_description: 'API key is invalid or revoked'
    });
  } catch (error) {
    console.error('[Security] API key authentication error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Authentication failed'
    });
  }
}

/**
 * Combined auth - accepts either Bearer token or API key
 */
function authenticateAny(req, res, next) {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authenticate(req, res, next);
  } else if (apiKey) {
    return authenticateApiKey(req, res, next);
  } else {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Authentication required (Bearer token or API key)'
    });
  }
}

/**
 * Require specific roles
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'access_denied',
        error_description: `Required role: ${roles.join(' or ')}`
      });
    }

    next();
  };
}

/**
 * HTTPS enforcement middleware
 */
function requireHttps(req, res, next) {
  // Check various headers that indicate HTTPS
  const isHttps = req.secure ||
                  req.headers['x-forwarded-proto'] === 'https' ||
                  req.headers['x-forwarded-ssl'] === 'on';

  // Allow in development
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }

  if (!isHttps) {
    return res.status(403).json({
      error: 'https_required',
      error_description: 'HTTPS is required for this endpoint'
    });
  }

  next();
}

module.exports = {
  // Token generation
  generateAccessToken,
  generateRefreshToken,
  generateIdToken,
  verifyToken,

  // Authentication middleware
  authenticate,
  optionalAuth,
  authenticateApiKey,
  authenticateAny,

  // Authorization middleware
  authorize,
  requireOwnership,
  requireRole,

  // Security
  requireHttps,

  // Constants
  ROLES,
  JWT_SECRET,
  JWT_ISSUER,
  JWT_AUDIENCE
};
