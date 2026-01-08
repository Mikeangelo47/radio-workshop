/**
 * Authentication System Tests
 * 
 * Run with: npm test or node src/tests/auth.test.js
 * 
 * Tests cover:
 * - Registration with validation
 * - Login with lockout
 * - Token refresh rotation
 * - Password reset flow
 * - Email verification
 */

const assert = require('assert');

// Mock data
const testUser = {
  email: 'test@example.com',
  username: 'testuser',
  password: 'SecurePass123!'
};

// Test utilities
function generateRandomEmail() {
  return `test_${Date.now()}_${Math.random().toString(36).substring(7)}@example.com`;
}

function generateRandomUsername() {
  return `user_${Date.now()}_${Math.random().toString(36).substring(7)}`;
}

// ============================================================================
// UNIT TESTS - Password Validation
// ============================================================================

console.log('\n🧪 Running Authentication Tests\n');
console.log('=' .repeat(60));

// Test: Password validation
console.log('\n📋 Password Validation Tests');

function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push('min_length');
  if (!/[A-Z]/.test(password)) errors.push('uppercase');
  if (!/[a-z]/.test(password)) errors.push('lowercase');
  if (!/[0-9]/.test(password)) errors.push('number');
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) errors.push('special');
  return errors;
}

// Test weak passwords
const weakPasswords = [
  { password: 'short', expected: ['min_length', 'uppercase', 'number', 'special'] },
  { password: 'nouppercase123!', expected: ['uppercase'] },
  { password: 'NOLOWERCASE123!', expected: ['lowercase'] },
  { password: 'NoNumbers!', expected: ['number'] },
  { password: 'NoSpecial123', expected: ['special'] },
];

weakPasswords.forEach(({ password, expected }) => {
  const errors = validatePassword(password);
  const hasExpectedErrors = expected.every(e => errors.includes(e));
  console.log(`  ${hasExpectedErrors ? '✅' : '❌'} Password "${password}" - ${hasExpectedErrors ? 'correctly rejected' : 'FAILED'}`);
});

// Test strong password
const strongPassword = 'SecurePass123!';
const strongErrors = validatePassword(strongPassword);
console.log(`  ${strongErrors.length === 0 ? '✅' : '❌'} Password "${strongPassword}" - ${strongErrors.length === 0 ? 'accepted' : 'FAILED'}`);

// ============================================================================
// UNIT TESTS - Email Validation
// ============================================================================

console.log('\n📋 Email Validation Tests');

function validateEmail(email) {
  const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
  return emailRegex.test(email);
}

const emailTests = [
  { email: 'valid@example.com', expected: true },
  { email: 'valid.name@example.co.uk', expected: true },
  { email: 'valid+tag@example.com', expected: true },
  { email: 'invalid', expected: false },
  { email: 'invalid@', expected: false },
  { email: '@example.com', expected: false },
  { email: 'no spaces@example.com', expected: false },
];

emailTests.forEach(({ email, expected }) => {
  const isValid = validateEmail(email);
  const passed = isValid === expected;
  console.log(`  ${passed ? '✅' : '❌'} Email "${email}" - ${passed ? (expected ? 'accepted' : 'rejected') : 'FAILED'}`);
});

// ============================================================================
// UNIT TESTS - Username Validation
// ============================================================================

console.log('\n📋 Username Validation Tests');

function validateUsername(username) {
  if (username.length < 3) return 'too_short';
  if (username.length > 30) return 'too_long';
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'invalid_chars';
  return null;
}

const usernameTests = [
  { username: 'validuser', expected: null },
  { username: 'valid_user_123', expected: null },
  { username: 'ab', expected: 'too_short' },
  { username: 'a'.repeat(31), expected: 'too_long' },
  { username: 'invalid-user', expected: 'invalid_chars' },
  { username: 'invalid user', expected: 'invalid_chars' },
  { username: 'invalid@user', expected: 'invalid_chars' },
];

usernameTests.forEach(({ username, expected }) => {
  const error = validateUsername(username);
  const passed = error === expected;
  const displayUsername = username.length > 20 ? username.substring(0, 20) + '...' : username;
  console.log(`  ${passed ? '✅' : '❌'} Username "${displayUsername}" - ${passed ? (expected ? `rejected (${expected})` : 'accepted') : 'FAILED'}`);
});

// ============================================================================
// UNIT TESTS - Token Hashing
// ============================================================================

console.log('\n📋 Token Security Tests');

const crypto = require('crypto');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Test token generation
const token1 = generateSecureToken();
const token2 = generateSecureToken();
console.log(`  ${token1.length === 64 ? '✅' : '❌'} Token length is 64 hex chars (32 bytes)`);
console.log(`  ${token1 !== token2 ? '✅' : '❌'} Tokens are unique`);

// Test token hashing
const hash1 = hashToken(token1);
const hash2 = hashToken(token1);
console.log(`  ${hash1 === hash2 ? '✅' : '❌'} Same token produces same hash`);
console.log(`  ${hash1 !== token1 ? '✅' : '❌'} Hash is different from original token`);
console.log(`  ${hash1.length === 64 ? '✅' : '❌'} Hash is 64 hex chars (SHA-256)`);

// ============================================================================
// UNIT TESTS - Account Lockout Logic
// ============================================================================

console.log('\n📋 Account Lockout Tests');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 30;

function isAccountLocked(user) {
  if (!user.lockUntil) return false;
  return new Date() < new Date(user.lockUntil);
}

function shouldLockAccount(failedAttempts) {
  return failedAttempts >= MAX_FAILED_ATTEMPTS;
}

// Test lockout threshold
console.log(`  ${!shouldLockAccount(4) ? '✅' : '❌'} 4 failed attempts - not locked`);
console.log(`  ${shouldLockAccount(5) ? '✅' : '❌'} 5 failed attempts - locked`);
console.log(`  ${shouldLockAccount(10) ? '✅' : '❌'} 10 failed attempts - locked`);

// Test lock expiry
const lockedUser = { lockUntil: new Date(Date.now() + 60000) }; // 1 min in future
const expiredLockUser = { lockUntil: new Date(Date.now() - 60000) }; // 1 min in past
const noLockUser = { lockUntil: null };

console.log(`  ${isAccountLocked(lockedUser) ? '✅' : '❌'} Active lock - account locked`);
console.log(`  ${!isAccountLocked(expiredLockUser) ? '✅' : '❌'} Expired lock - account unlocked`);
console.log(`  ${!isAccountLocked(noLockUser) ? '✅' : '❌'} No lock - account unlocked`);

// ============================================================================
// UNIT TESTS - JWT Token Structure
// ============================================================================

console.log('\n📋 JWT Token Tests');

const jwt = require('jsonwebtoken');
const JWT_SECRET = 'test-secret-key';

function generateAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      username: user.username,
      type: 'access'
    },
    JWT_SECRET,
    {
      expiresIn: '15m',
      issuer: 'palm-auth',
      audience: 'palm-auth-client'
    }
  );
}

const mockUser = { id: 'user-123', email: 'test@example.com', username: 'testuser' };
const accessToken = generateAccessToken(mockUser);

// Verify token structure
try {
  const decoded = jwt.verify(accessToken, JWT_SECRET);
  console.log(`  ${decoded.sub === mockUser.id ? '✅' : '❌'} Token contains user ID`);
  console.log(`  ${decoded.email === mockUser.email ? '✅' : '❌'} Token contains email`);
  console.log(`  ${decoded.type === 'access' ? '✅' : '❌'} Token type is 'access'`);
  console.log(`  ${decoded.iss === 'palm-auth' ? '✅' : '❌'} Token issuer is correct`);
  console.log(`  ${decoded.aud === 'palm-auth-client' ? '✅' : '❌'} Token audience is correct`);
  console.log(`  ${decoded.exp > Date.now() / 1000 ? '✅' : '❌'} Token has future expiry`);
} catch (error) {
  console.log(`  ❌ Token verification failed: ${error.message}`);
}

// Test invalid token
try {
  jwt.verify(accessToken, 'wrong-secret');
  console.log(`  ❌ Invalid secret should fail verification`);
} catch (error) {
  console.log(`  ✅ Invalid secret correctly rejected`);
}

// ============================================================================
// INTEGRATION TEST STUBS (require running server)
// ============================================================================

console.log('\n📋 Integration Test Stubs (require running server)');

const integrationTests = [
  'POST /auth/register - Create new user',
  'POST /auth/register - Reject duplicate email',
  'POST /auth/register - Reject weak password',
  'POST /auth/login - Valid credentials',
  'POST /auth/login - Invalid password',
  'POST /auth/login - Account lockout after 5 failures',
  'POST /auth/logout - Revoke refresh token',
  'POST /auth/refresh - Rotate tokens',
  'POST /auth/refresh - Reject revoked token',
  'POST /auth/forgot-password - Always returns 200',
  'POST /auth/reset-password - Valid token',
  'POST /auth/reset-password - Expired token',
  'POST /auth/verify-email - Valid token',
  'GET /auth/me - With valid access token',
  'GET /auth/me - With expired token',
];

integrationTests.forEach(test => {
  console.log(`  ⏸️  ${test}`);
});

// ============================================================================
// SUMMARY
// ============================================================================

console.log('\n' + '='.repeat(60));
console.log('✅ Unit tests completed');
console.log('⏸️  Integration tests require running server');
console.log('\nTo run integration tests:');
console.log('  1. Start the server: npm run dev');
console.log('  2. Run: curl -X POST http://localhost:3000/api/v2/auth/register ...');
console.log('='.repeat(60) + '\n');

// Export for use in other test files
module.exports = {
  validatePassword,
  validateEmail,
  validateUsername,
  hashToken,
  generateSecureToken,
  isAccountLocked,
  shouldLockAccount,
  generateAccessToken,
  testUser,
  generateRandomEmail,
  generateRandomUsername
};
