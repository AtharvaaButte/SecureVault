const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const { validateStrongPassword } = require('../utils/validation');
const rbacService = require('../services/rbacService');
const auditService = require('../services/auditService');
const geoService = require('../services/geoService');

const router = express.Router();

function generateToken(payload) {
  const secret = process.env.JWT_SECRET;
  const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
  return jwt.sign(payload, secret, { expiresIn });
}

// POST /api/auth/register - Register organization and initial owner user
router.post('/register', async (req, res) => {
  const { orgName, name, email, password } = req.body;

  if (!orgName || !email || !password) {
    return res.status(400).json({ message: 'Organization name, email, and password are required.' });
  }

  const passwordCheck = validateStrongPassword(password);
  if (!passwordCheck.valid) {
    return res.status(400).json({ message: passwordCheck.message });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const userName = name && typeof name === 'string' && name.trim().length > 0 ? name.trim() : normalizedEmail.split('@')[0];
  const location = geoService.extractLocation(req);

  const client = await pool.connect();
  try {
    const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'A user with this email address already exists.' });
    }

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    await client.query('BEGIN');

    // Create organization
    const orgResult = await client.query(
      'INSERT INTO organizations (name) VALUES ($1) RETURNING id, name, created_at',
      [orgName.trim()]
    );
    const org = orgResult.rows[0];

    // Create initial user as Organization Owner (is_owner = true, status = ACTIVE)
    const userResult = await client.query(
      `INSERT INTO users (organization_id, name, email, password_hash, is_owner, is_active, status) 
       VALUES ($1, $2, $3, $4, true, true, 'ACTIVE') 
       RETURNING id, name, email, is_owner, status, created_at`,
      [org.id, userName, normalizedEmail, passwordHash]
    );
    const user = userResult.rows[0];

    // Link owner_id in organizations table
    await client.query(
      'UPDATE organizations SET owner_id = $1 WHERE id = $2',
      [user.id, org.id]
    );

    // Register initial location context in user_devices
    await client.query(
      `INSERT INTO user_devices (user_id, last_ip, last_country, last_state, last_city)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip, last_seen_at = CURRENT_TIMESTAMP`,
      [user.id, location.ip, location.country, location.state, location.city]
    );

    await client.query('COMMIT');

    const userRoles = await rbacService.getUserRoles(user.id);
    const userPermissions = await rbacService.getUserPermissions(user.id);

    // Audit Event Recording
    await auditService.recordAuditEvent({
      organizationId: org.id,
      userId: user.id,
      eventType: 'REGISTER',
      action: 'ALLOW',
      resourceId: org.id,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
    });

    const token = generateToken({
      userId: user.id,
      orgId: org.id,
      name: user.name,
      email: user.email,
      isOwner: true,
    });

    // Auto-provision X25519 public key for Owner user
    const kp = crypto.generateKeyPairSync('x25519');
    const pubKey = kp.publicKey.export({ type: 'spki', format: 'pem' });
    await client.query(
      `INSERT INTO user_keys (user_id, public_key, key_algorithm)
       VALUES ($1, $2, 'X25519') ON CONFLICT (user_id) DO NOTHING`,
      [user.id, pubKey]
    );

    res.status(201).json({
      message: 'Organization and account registered successfully',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isOwner: true,
        publicKey: pubKey,
        publicKeyRegistered: true,
        roles: userRoles,
        permissions: userPermissions,
        createdAt: user.created_at,
      },
      organization: {
        id: org.id,
        name: org.name,
        ownerId: user.id,
        createdAt: org.created_at,
      },
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('[Auth Register Error]:', error.message);
    res.status(500).json({ message: 'Failed to register organization and user account.' });
  } finally {
    client.release();
  }
});

// POST /api/auth/login - Login user with email & password
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const location = geoService.extractLocation(req);

  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.password_hash, u.is_owner, u.is_active, u.status, u.setup_token, u.created_at, 
              o.id as organization_id, o.name as organization_name 
       FROM users u 
       JOIN organizations o ON u.organization_id = o.id 
       WHERE u.email = $1`,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const user = result.rows[0];

    // Check account status lifecycle
    if (user.status === 'DISABLED') {
      return res.status(403).json({ message: 'Account is disabled. Please contact your organization administrator.' });
    }

    if (user.status === 'SETUP_REQUIRED' || !user.is_active || !user.password_hash) {
      return res.status(403).json({
        message: 'Account setup is required before you can log in. Please complete your account setup.',
        setupRequired: true,
        setupToken: user.setup_token || null,
      });
    }

    const isValidPassword = await argon2.verify(user.password_hash, password);
    if (!isValidPassword) {
      await auditService.recordAuditEvent({
        organizationId: user.organization_id,
        userId: user.id,
        eventType: 'LOGIN_FAILED',
        action: 'DENY',
        resourceId: null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
      });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Update location context in user_devices
    await pool.query(
      `INSERT INTO user_devices (user_id, last_ip, last_country, last_state, last_city)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip,
         last_country = EXCLUDED.last_country,
         last_state = EXCLUDED.last_state,
         last_city = EXCLUDED.last_city,
         last_seen_at = CURRENT_TIMESTAMP`,
      [user.id, location.ip, location.country, location.state, location.city]
    );

    const userRoles = await rbacService.getUserRoles(user.id);
    const userPermissions = await rbacService.getUserPermissions(user.id);

    // Audit Successful Login
    await auditService.recordAuditEvent({
      organizationId: user.organization_id,
      userId: user.id,
      eventType: 'LOGIN',
      action: 'ALLOW',
      resourceId: null,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
    });

    // Fetch registered public key
    const keyRes = await pool.query('SELECT public_key FROM user_keys WHERE user_id = $1', [user.id]);
    const pubKey = keyRes.rows.length > 0 ? keyRes.rows[0].public_key : null;

    const token = generateToken({
      userId: user.id,
      orgId: user.organization_id,
      name: user.name,
      email: user.email,
      isOwner: Boolean(user.is_owner),
    });

    res.json({
      message: 'Authentication successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        status: user.status || 'ACTIVE',
        isOwner: Boolean(user.is_owner),
        publicKey: pubKey,
        publicKeyRegistered: Boolean(pubKey),
        roles: userRoles,
        permissions: userPermissions,
        createdAt: user.created_at,
      },
      organization: {
        id: user.organization_id,
        name: user.organization_name,
      },
    });
  } catch (error) {
    console.error('[Auth Login Error]:', error.message);
    res.status(500).json({ message: 'An internal server error occurred during login.' });
  }
});

// POST /api/auth/setup/verify - Verify Email + Setup Token
router.post('/setup/verify', async (req, res) => {
  const { email, setupToken } = req.body;

  if (!email || !setupToken) {
    return res.status(400).json({ message: 'Both Email Address and Setup Token are required.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  let cleanToken = String(setupToken).trim();
  if (cleanToken.includes('/setup/')) {
    cleanToken = cleanToken.split('/setup/').pop();
  }
  cleanToken = decodeURIComponent(cleanToken).split('?')[0].split('#')[0].replace(/\/+$/, '').trim();

  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.status, u.setup_token, u.setup_token_expires, u.is_active, o.name as organization_name
       FROM users u
       JOIN organizations o ON u.organization_id = o.id
       WHERE LOWER(u.email) = $1`,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Email address not found.' });
    }

    const user = result.rows[0];

    if (user.setup_token !== cleanToken) {
      return res.status(400).json({ message: 'Invalid setup token.' });
    }

    if (user.status === 'DISABLED') {
      return res.status(403).json({ message: 'This account has been disabled. Please contact your organization administrator.' });
    }

    if (user.status === 'ACTIVE' || user.is_active) {
      return res.status(400).json({ message: 'This account setup has already been completed. Please log in with your email and password.' });
    }

    if (user.setup_token_expires && new Date(user.setup_token_expires) < new Date()) {
      return res.status(400).json({ message: 'Account setup token has expired. Please contact your organization administrator.' });
    }

    res.json({
      valid: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        setupToken: user.setup_token,
        status: user.status || 'SETUP_REQUIRED',
        organizationName: user.organization_name,
      },
    });
  } catch (error) {
    console.error('[Auth Setup Verify Error]:', error.message);
    res.status(500).json({ message: 'Failed to verify account setup credentials.' });
  }
});

// POST /api/auth/setup/complete - Complete setup with password & key registration
router.post('/setup/complete', async (req, res) => {
  const { email, setupToken, password, publicKey, securityHint } = req.body;

  if (!email || !setupToken || !password) {
    return res.status(400).json({ message: 'Email, Setup Token, and Password are required.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  let cleanToken = String(setupToken).trim();
  if (cleanToken.includes('/setup/')) {
    cleanToken = cleanToken.split('/setup/').pop();
  }
  cleanToken = decodeURIComponent(cleanToken).split('?')[0].split('#')[0].replace(/\/+$/, '').trim();

  const passwordCheck = validateStrongPassword(password);
  if (!passwordCheck.valid) {
    return res.status(400).json({ message: passwordCheck.message });
  }

  const location = geoService.extractLocation(req);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const result = await client.query(
      `SELECT u.id, u.name, u.email, u.setup_token, u.organization_id, u.status, u.setup_token_expires, u.is_active
       FROM users u
       WHERE LOWER(u.email) = $1`,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Email address not found.' });
    }

    const user = result.rows[0];

    if (user.setup_token !== cleanToken) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Invalid setup token.' });
    }

    if (user.status === 'DISABLED') {
      await client.query('ROLLBACK');
      return res.status(403).json({ message: 'This account has been disabled.' });
    }

    if (user.status === 'ACTIVE' || user.is_active) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'This account setup has already been completed.' });
    }

    if (user.setup_token_expires && new Date(user.setup_token_expires) < new Date()) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Account setup token has expired.' });
    }

    // Process Public Key registration
    let registeredPubKey = publicKey ? String(publicKey).trim() : null;
    if (registeredPubKey) {
      await client.query(
        `INSERT INTO user_keys (user_id, public_key, key_algorithm)
         VALUES ($1, $2, 'X25519')
         ON CONFLICT (user_id) DO UPDATE SET
           public_key = EXCLUDED.public_key,
           updated_at = CURRENT_TIMESTAMP`,
        [user.id, registeredPubKey]
      );
    } else {
      const keyCheck = await client.query('SELECT public_key FROM user_keys WHERE user_id = $1', [user.id]);
      if (keyCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Encryption public key registration is required to complete account setup.' });
      }
    }

    const passwordHash = await argon2.hash(password.trim(), { type: argon2.argon2id });
    const hint = securityHint ? securityHint.trim() : null;

    await client.query(
      `UPDATE users 
       SET password_hash = $1, 
           status = 'ACTIVE', 
           is_active = true, 
           setup_token = NULL, 
           setup_token_expires = NULL, 
           security_hint = $2 
       WHERE id = $3`,
      [passwordHash, hint, user.id]
    );

    // Register initial device location context in user_devices
    await client.query(
      `INSERT INTO user_devices (user_id, last_ip, last_country, last_state, last_city)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip,
         last_country = EXCLUDED.last_country,
         last_state = EXCLUDED.last_state,
         last_city = EXCLUDED.last_city,
         last_seen_at = CURRENT_TIMESTAMP`,
      [user.id, location.ip, location.country, location.state, location.city]
    );

    await client.query('COMMIT');

    await auditService.recordAuditEvent({
      organizationId: user.organization_id,
      userId: user.id,
      eventType: 'ACCOUNT_ACTIVATED',
      action: 'ALLOW',
      resourceId: user.id,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
    });

    // Generate JWT Session Token for immediate auto-login
    const userRoles = await rbacService.getUserRoles(user.id);
    const userPermissions = await rbacService.getUserPermissions(user.id);
    const orgRes = await pool.query('SELECT id, name FROM organizations WHERE id = $1', [user.organization_id]);
    const org = orgRes.rows[0];

    const sessionToken = generateToken({
      userId: user.id,
      email: user.email,
      orgId: user.organization_id,
      isOwner: false,
    });

    res.json({
      success: true,
      message: 'Account setup completed successfully! Status updated to ACTIVE.',
      token: sessionToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        status: 'ACTIVE',
        isOwner: false,
        publicKey: registeredPubKey,
        publicKeyRegistered: true,
        roles: userRoles,
        permissions: userPermissions,
      },
      organization: {
        id: org ? org.id : user.organization_id,
        name: org ? org.name : 'SecureVault',
      },
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('[Auth Setup Complete Error]:', error.message);
    res.status(500).json({ message: 'Failed to complete account setup.' });
  } finally {
    client.release();
  }
});

// GET /api/auth/setup/:token - Backward compatible lookup route
router.get('/setup/:token', async (req, res) => {
  let { token } = req.params;
  if (!token) return res.status(400).json({ message: 'Token is required.' });

  if (token.includes('/setup/')) {
    token = token.split('/setup/').pop();
  }
  token = decodeURIComponent(token).split('?')[0].split('#')[0].replace(/\/+$/, '').trim();

  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.status, u.setup_token, u.setup_token_expires, u.is_active, o.name as organization_name
       FROM users u
       JOIN organizations o ON u.organization_id = o.id
       WHERE u.setup_token = $1`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired account setup link.' });
    }

    const user = result.rows[0];

    if (user.status === 'DISABLED') {
      return res.status(403).json({ message: 'This account has been disabled. Please contact your organization administrator.' });
    }

    if (user.status === 'ACTIVE' || user.is_active) {
      return res.status(400).json({ message: 'This account setup has already been completed. Please log in.' });
    }

    if (user.setup_token_expires && new Date(user.setup_token_expires) < new Date()) {
      return res.status(400).json({ message: 'Account setup link has expired. Please contact your organization administrator.' });
    }

    res.json({
      valid: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        setupToken: user.setup_token,
        status: user.status || 'SETUP_REQUIRED',
        organizationName: user.organization_name,
      },
    });
  } catch (error) {
    console.error('[Auth Setup Check Error]:', error.message);
    res.status(500).json({ message: 'Failed to validate account setup token.' });
  }
});

// GET /api/auth/me - Protected endpoint to fetch current authenticated user
router.get('/me', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.is_owner, u.created_at, 
              o.id as organization_id, o.name as organization_name 
       FROM users u 
       JOIN organizations o ON u.organization_id = o.id 
       WHERE u.id = $1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User account not found.' });
    }

    const user = result.rows[0];
    const userRoles = await rbacService.getUserRoles(user.id);
    const userPermissions = await rbacService.getUserPermissions(user.id);
    const keyRes = await pool.query('SELECT public_key FROM user_keys WHERE user_id = $1', [user.id]);
    const pubKey = keyRes.rows.length > 0 ? keyRes.rows[0].public_key : null;

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isOwner: Boolean(user.is_owner),
        publicKey: pubKey,
        publicKeyRegistered: Boolean(pubKey),
        roles: userRoles,
        permissions: userPermissions,
        createdAt: user.created_at,
      },
      organization: {
        id: user.organization_id,
        name: user.organization_name,
      },
    });
  } catch (error) {
    console.error('[Auth Me Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve user profile.' });
  }
});

// POST /api/auth/logout - Logout endpoint (Protected)
router.post('/logout', verifyToken, (_req, res) => {
  res.json({ message: 'Logout successful' });
});

module.exports = router;
