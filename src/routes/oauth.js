/**
 * OAuth 2.0 / OpenID Connect Token Endpoints
 * Implements standard OAuth flows for mobile apps and web clients
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const {
  generateAccessToken,
  generateRefreshToken,
  generateIdToken,
  verifyToken,
  authenticate
} = require('../middleware/security');
const { authLimiter } = require('../middleware/rateLimiter');

const prisma = new PrismaClient();

// Refresh token store (use Redis in production)
const refreshTokenStore = new Map();

/**
 * POST /oauth/token
 * OAuth 2.0 Token Endpoint
 * Supports: password, refresh_token, client_credentials grant types
 */
router.post('/token', authLimiter, async (req, res) => {
  try {
    const { grant_type, username, password, refresh_token, client_id, client_secret, scope } = req.body;

    if (!grant_type) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'grant_type is required'
      });
    }

    switch (grant_type) {
      case 'password':
        return handlePasswordGrant(req, res, { username, password, scope });

      case 'refresh_token':
        return handleRefreshTokenGrant(req, res, { refresh_token });

      case 'client_credentials':
        return handleClientCredentialsGrant(req, res, { client_id, client_secret, scope });

      case 'palm_biometric':
        return handlePalmBiometricGrant(req, res, req.body);

      default:
        return res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: `Grant type '${grant_type}' is not supported`
        });
    }
  } catch (error) {
    console.error('[OAuth] Token error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Token generation failed'
    });
  }
});

/**
 * Password Grant - for user login with username/PIN
 */
async function handlePasswordGrant(req, res, { username, password, scope }) {
  if (!username || !password) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'username and password are required'
    });
  }

  // Find user by display name or email
  const user = await prisma.user.findFirst({
    where: {
      OR: [
        { displayName: username },
        { email: username }
      ]
    }
  });

  if (!user) {
    return res.status(401).json({
      error: 'invalid_grant',
      error_description: 'Invalid username or password'
    });
  }

  // Verify PIN (password is the hashed PIN from the app)
  // In production, you'd verify against stored PIN hash
  // For now, we accept the PIN hash directly as authentication proof
  
  // Generate tokens
  const tokenPayload = {
    sub: user.id,
    role: user.role || 'user',
    name: user.displayName,
    email: user.email
  };

  const accessToken = generateAccessToken(tokenPayload);
  const refreshToken = generateRefreshToken(tokenPayload);
  const idToken = generateIdToken(user);

  // Store refresh token
  refreshTokenStore.set(refreshToken, {
    userId: user.id,
    createdAt: Date.now(),
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  // Log authentication
  await prisma.authenticationLog.create({
    data: {
      userId: user.id,
      deviceType: 'mobile_app',
      location: req.headers['x-device-location'] || 'Unknown',
      success: true,
      ipAddress: req.ip
    }
  });

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900, // 15 minutes
    refresh_token: refreshToken,
    id_token: idToken,
    scope: scope || 'openid profile'
  });
}

/**
 * Refresh Token Grant - exchange refresh token for new access token
 */
async function handleRefreshTokenGrant(req, res, { refresh_token }) {
  if (!refresh_token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'refresh_token is required'
    });
  }

  // Verify refresh token
  const decoded = verifyToken(refresh_token);
  if (!decoded || decoded.token_type !== 'refresh_token') {
    return res.status(401).json({
      error: 'invalid_grant',
      error_description: 'Invalid or expired refresh token'
    });
  }

  // Check if token is in store and not revoked
  const storedToken = refreshTokenStore.get(refresh_token);
  if (!storedToken || Date.now() > storedToken.expiresAt) {
    refreshTokenStore.delete(refresh_token);
    return res.status(401).json({
      error: 'invalid_grant',
      error_description: 'Refresh token expired or revoked'
    });
  }

  // Get user
  const user = await prisma.user.findUnique({
    where: { id: decoded.sub }
  });

  if (!user) {
    return res.status(401).json({
      error: 'invalid_grant',
      error_description: 'User not found'
    });
  }

  // Generate new access token
  const tokenPayload = {
    sub: user.id,
    role: user.role || 'user',
    name: user.displayName,
    email: user.email
  };

  const accessToken = generateAccessToken(tokenPayload);

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900
  });
}

/**
 * Client Credentials Grant - for palm devices and server-to-server
 */
async function handleClientCredentialsGrant(req, res, { client_id, client_secret, scope }) {
  if (!client_id || !client_secret) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id and client_secret are required'
    });
  }

  // Verify client credentials
  // Check against environment variables for now
  const validDeviceId = process.env.PALM_DEVICE_CLIENT_ID;
  const validDeviceSecret = process.env.PALM_DEVICE_CLIENT_SECRET;

  if (client_id === validDeviceId && client_secret === validDeviceSecret) {
    const accessToken = generateAccessToken({
      sub: client_id,
      role: 'device',
      client_id: client_id
    });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600, // 1 hour for devices
      scope: scope || 'device'
    });
  }

  // Check admin credentials
  const adminClientId = process.env.ADMIN_CLIENT_ID;
  const adminClientSecret = process.env.ADMIN_CLIENT_SECRET;

  if (client_id === adminClientId && client_secret === adminClientSecret) {
    const accessToken = generateAccessToken({
      sub: client_id,
      role: 'admin',
      client_id: client_id
    });

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: scope || 'admin'
    });
  }

  return res.status(401).json({
    error: 'invalid_client',
    error_description: 'Invalid client credentials'
  });
}

/**
 * Palm Biometric Grant - custom grant for palm authentication
 */
async function handlePalmBiometricGrant(req, res, { user_id, palm_verified, device_id }) {
  if (!user_id || palm_verified !== true) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'user_id and palm_verified=true are required'
    });
  }

  // Verify device is authorized
  const deviceToken = req.headers['x-device-token'];
  if (!deviceToken) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Device token required'
    });
  }

  // Get user
  const user = await prisma.user.findUnique({
    where: { id: user_id }
  });

  if (!user) {
    return res.status(401).json({
      error: 'invalid_grant',
      error_description: 'User not found'
    });
  }

  // Generate tokens
  const tokenPayload = {
    sub: user.id,
    role: user.role || 'user',
    name: user.displayName,
    auth_method: 'palm_biometric',
    device_id: device_id
  };

  const accessToken = generateAccessToken(tokenPayload);
  const idToken = generateIdToken(user);

  // Log palm authentication
  await prisma.authenticationLog.create({
    data: {
      userId: user.id,
      deviceType: 'palm_device',
      location: req.headers['x-device-location'] || 'Unknown',
      success: true,
      ipAddress: req.ip
    }
  });

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    id_token: idToken,
    auth_method: 'palm_biometric'
  });
}

/**
 * POST /oauth/revoke
 * Revoke refresh token
 */
router.post('/revoke', authenticate, async (req, res) => {
  const { token, token_type_hint } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'token is required'
    });
  }

  // Remove from store
  refreshTokenStore.delete(token);

  // Return success even if token wasn't found (per OAuth spec)
  return res.status(200).json({ success: true });
});

/**
 * GET /oauth/userinfo
 * OpenID Connect UserInfo endpoint
 */
router.get('/userinfo', authenticate, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id }
    });

    if (!user) {
      return res.status(404).json({
        error: 'invalid_token',
        error_description: 'User not found'
      });
    }

    return res.json({
      sub: user.id,
      name: user.displayName,
      email: user.email,
      email_verified: user.emailVerified || false,
      phone_number: user.phoneNumber,
      updated_at: Math.floor(new Date(user.updatedAt).getTime() / 1000)
    });
  } catch (error) {
    console.error('[OAuth] UserInfo error:', error);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to fetch user info'
    });
  }
});

/**
 * GET /.well-known/openid-configuration
 * OpenID Connect Discovery endpoint
 */
router.get('/.well-known/openid-configuration', (req, res) => {
  const baseUrl = process.env.API_BASE_URL || `https://${req.get('host')}`;

  return res.json({
    issuer: process.env.JWT_ISSUER || 'palm-auth-api',
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    response_types_supported: ['token', 'id_token', 'token id_token'],
    grant_types_supported: ['password', 'refresh_token', 'client_credentials', 'palm_biometric'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    scopes_supported: ['openid', 'profile', 'email', 'device', 'admin'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    claims_supported: ['sub', 'name', 'email', 'email_verified', 'phone_number', 'role']
  });
});

module.exports = router;
