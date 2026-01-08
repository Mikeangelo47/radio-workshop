# Palm Auth API - Security Documentation

## Overview

This document describes the security measures implemented in the Palm Auth API to protect customer data and ensure secure access to the service.

## Security Features

### 1. HTTPS Encryption (TLS)

All data is encrypted in transit using HTTPS/TLS:

- **Enforcement**: HTTPS is required in production mode
- **HSTS**: HTTP Strict Transport Security enabled with 1-year max-age
- **Preload**: HSTS preload enabled for browser security lists

```javascript
// Automatic HTTPS enforcement in production
if (process.env.NODE_ENV === 'production') {
  app.use(requireHttps);
}
```

### 2. OAuth 2.0 + OpenID Connect (OIDC)

Standard OAuth 2.0 authentication with OIDC extensions:

#### Supported Grant Types

| Grant Type | Use Case |
|------------|----------|
| `password` | Mobile app login with username/PIN |
| `refresh_token` | Token refresh without re-authentication |
| `client_credentials` | Palm devices and server-to-server |
| `palm_biometric` | Custom grant for palm authentication |

#### Token Endpoints

- `POST /oauth/token` - Obtain access tokens
- `POST /oauth/revoke` - Revoke refresh tokens
- `GET /oauth/userinfo` - Get authenticated user info (OIDC)
- `GET /.well-known/openid-configuration` - OIDC Discovery

#### Token Types

| Token | Expiry | Purpose |
|-------|--------|---------|
| Access Token | 15 minutes | API authorization |
| Refresh Token | 7 days | Obtain new access tokens |
| ID Token | 15 minutes | User identity (OIDC) |

### 3. Role-Based Access Control (RBAC)

Implements the **Principle of Least Privilege** - users can only access exactly what they need.

#### Roles and Permissions

**User Role** (End Users)
- `read:own_profile`, `update:own_profile`
- `read:own_cards`, `create:own_cards`, `update:own_cards`, `delete:own_cards`
- `read:own_auth_history`, `read:own_redemptions`
- `create:palm_enrollment`

**Device Role** (Palm Devices)
- `read:palm_templates`, `verify:palm`
- `read:pending_orders`, `complete:orders`
- `read:pending_verifications`, `complete:verifications`
- `create:auth_log`

**Operator Role** (Store Staff)
- `read:products`, `create:products`, `update:products`
- `read:orders`, `create:orders`, `update:orders`
- `read:verifications`

**Admin Role** (Full Access)
- All permissions including `manage:system`

#### Usage

```javascript
const { authenticate, authorize, requireOwnership } = require('./middleware/security');

// Require authentication
router.get('/profile', authenticate, (req, res) => { ... });

// Require specific permission
router.get('/users', authenticate, authorize('read:users'), (req, res) => { ... });

// Require resource ownership
router.get('/users/:userId/cards', authenticate, requireOwnership('userId'), (req, res) => { ... });
```

### 4. CORS Configuration

Strict Cross-Origin Resource Sharing with domain whitelist:

#### Allowed Origins

Production domains are explicitly whitelisted:
- `https://palmauth.app`
- `https://api.palmauth.app`
- Railway deployment URLs
- Mobile app origins (capacitor://, ionic://)

#### Configuration

```javascript
// Add custom origins via environment variable
ALLOWED_ORIGINS=https://your-domain.com,https://admin.your-domain.com
```

Non-whitelisted origins are blocked in production with logged warnings.

### 5. Rate Limiting

Protection against abuse with per-IP and per-API-key limits:

#### Rate Limit Tiers

| Tier | Window | Max Requests | Use Case |
|------|--------|--------------|----------|
| Default | 15 min | 100 | General API |
| Auth | 15 min | 10 | Login/verification |
| Palm Device | 1 min | 60 | Device polling |
| API Key | 1 hour | 1000 | Per API key |

#### Response Headers

All responses include rate limit headers:
- `X-RateLimit-Limit` - Maximum requests allowed
- `X-RateLimit-Remaining` - Requests remaining
- `X-RateLimit-Reset` - Unix timestamp when limit resets

#### 429 Response

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded",
  "retryAfter": 300
}
```

### 6. Security Headers (Helmet)

Comprehensive security headers via Helmet.js:

- **Content-Security-Policy**: Restricts resource loading
- **X-Content-Type-Options**: Prevents MIME sniffing
- **X-Frame-Options**: Prevents clickjacking
- **X-XSS-Protection**: XSS filter
- **Referrer-Policy**: Controls referrer information
- **HSTS**: Forces HTTPS

### 7. Request Tracing

Every request receives a unique ID for debugging and audit:

```
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

## Environment Variables

Required security configuration:

```bash
# JWT Configuration
JWT_SECRET=<256-bit-secret>          # Generate: openssl rand -hex 32
JWT_ISSUER=palm-auth-api
JWT_AUDIENCE=palm-auth-clients

# OAuth Client Credentials
PALM_DEVICE_CLIENT_ID=palm-device
PALM_DEVICE_CLIENT_SECRET=<secret>
PALM_DEVICE_API_KEY=<api-key>

ADMIN_CLIENT_ID=admin
ADMIN_CLIENT_SECRET=<secret>
ADMIN_API_KEY=<api-key>

# CORS
ALLOWED_ORIGINS=https://your-domain.com

# Environment
NODE_ENV=production
```

## Mobile App Security (iOS)

### Secure Token Storage

Tokens are stored in iOS Keychain with:
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` - Only accessible when device unlocked
- Automatic token refresh before expiry
- Secure deletion on logout

### Certificate Pinning (Recommended)

For production, implement certificate pinning:

```swift
// Add to URLSession configuration
let pinnedCertificates = [SecCertificate]()
// Load your server's certificate
```

## Android App Security

### Secure Token Storage

Use Android Keystore for token storage:
- EncryptedSharedPreferences for API < 23
- Android Keystore for API >= 23

## API Key Management

### For Palm Devices

1. Generate unique API key per device
2. Store in device's secure storage
3. Include in requests: `X-API-Key: <key>`
4. Rotate keys periodically

### For Admin Access

1. Generate admin API key
2. Store securely (never in code)
3. Use for server-to-server communication
4. Monitor usage and rotate regularly

## Audit Logging

All authentication attempts are logged:

```javascript
{
  userId: "uuid",
  deviceType: "mobile_app | palm_device",
  location: "Device Location",
  success: true | false,
  ipAddress: "x.x.x.x",
  timestamp: "ISO-8601"
}
```

## Security Checklist for Production

- [ ] Set `NODE_ENV=production`
- [ ] Generate strong `JWT_SECRET` (256-bit)
- [ ] Configure `ALLOWED_ORIGINS` with production domains
- [ ] Set up SSL/TLS certificate
- [ ] Configure API keys for devices
- [ ] Enable database connection encryption
- [ ] Set up monitoring and alerting
- [ ] Implement log aggregation
- [ ] Regular security audits
- [ ] Penetration testing

## Incident Response

1. **Token Compromise**: Revoke all refresh tokens, force re-authentication
2. **API Key Compromise**: Rotate affected keys immediately
3. **Data Breach**: Follow data breach notification procedures

## Contact

For security concerns, contact: security@palmauth.app
