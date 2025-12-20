const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// In-memory store for verification codes (in production, use Redis or database)
const verificationCodes = new Map();

// Email transporter configuration
// Using environment variables for email service
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Generate 6-digit code
function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// Send verification code
router.post('/send-verification', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    // Generate code
    const code = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    // Store code
    verificationCodes.set(email.toLowerCase(), { code, expiresAt });
    
    // Check if email service is configured
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      // Development mode - log code to console
      console.log(`[Auth] 📧 Verification code for ${email}: ${code}`);
      return res.json({ 
        success: true, 
        message: 'Verification code sent (dev mode - check server logs)',
        // In dev mode, return code for testing
        ...(process.env.NODE_ENV !== 'production' && { devCode: code })
      });
    }
    
    // Send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Palm Auth - Verification Code',
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
          <div style="text-align: center; margin-bottom: 30px;">
            <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #0f766e, #14b8a6); border-radius: 20px; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center;">
              <span style="font-size: 40px;">🖐</span>
            </div>
            <h1 style="color: #0f172a; margin: 0; font-size: 24px;">Palm Auth</h1>
            <p style="color: #64748b; margin: 8px 0 0;">Secure Biometric Authentication</p>
          </div>
          
          <div style="background: #f8fafc; border-radius: 16px; padding: 30px; text-align: center;">
            <p style="color: #334155; font-size: 16px; margin: 0 0 20px;">Your verification code is:</p>
            <div style="background: #0f172a; color: white; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 20px 30px; border-radius: 12px; display: inline-block;">
              ${code}
            </div>
            <p style="color: #64748b; font-size: 14px; margin: 20px 0 0;">This code expires in 10 minutes</p>
          </div>
          
          <p style="color: #94a3b8; font-size: 12px; text-align: center; margin-top: 30px;">
            If you didn't request this code, you can safely ignore this email.
          </p>
        </div>
      `
    };
    
    await transporter.sendMail(mailOptions);
    console.log(`[Auth] 📧 Verification code sent to ${email}`);
    
    res.json({ success: true, message: 'Verification code sent' });
  } catch (error) {
    console.error('[Auth] Error sending verification code:', error);
    res.status(500).json({ success: false, message: 'Failed to send verification code' });
  }
});

// Verify code
router.post('/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({ success: false, verified: false, message: 'Email and code are required' });
    }
    
    const stored = verificationCodes.get(email.toLowerCase());
    
    if (!stored) {
      return res.json({ success: true, verified: false, message: 'No verification code found' });
    }
    
    if (Date.now() > stored.expiresAt) {
      verificationCodes.delete(email.toLowerCase());
      return res.json({ success: true, verified: false, message: 'Verification code expired' });
    }
    
    if (stored.code !== code) {
      return res.json({ success: true, verified: false, message: 'Invalid verification code' });
    }
    
    // Code is valid - remove it
    verificationCodes.delete(email.toLowerCase());
    console.log(`[Auth] ✅ Email verified: ${email}`);
    
    res.json({ success: true, verified: true, message: 'Email verified successfully' });
  } catch (error) {
    console.error('[Auth] Error verifying code:', error);
    res.status(500).json({ success: false, verified: false, message: 'Verification failed' });
  }
});

module.exports = router;
