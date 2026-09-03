const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const rbacService = require('../services/rbacService');
const auditService = require('../services/auditService');
const geoService = require('../services/geoService');

const router = express.Router();

function generateToken(payload) {
  const secret = process.env.JWT_SECRET;
  const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
  return jwt.sign(payload, secret, { expiresIn });
}

// POST /api/auth/register - Register organization and initial ADMIN user
router.post('/register', async (req, res) => {
  const { orgName, email, password } = req.body;

  if (!orgName || !email || !password) {
    return res.status(400).json({ message: 'Organization name, email, and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const deviceId = req.headers['x-client-device-id'] || req.body.deviceId || 'electron-default-device';
  const devicePlatform = req.headers['x-client-platform'] || 'Electron-Windows';
  const userAgent = req.headers['user-agent'] || 'SecureVault-Electron-Client';
  const location = geoService.extractLocation(req);

  const client = await pool.connect();
  try {
    // Check if user email already exists
    const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'A user with this email address already exists.' });
    }

    // Hash password with Argon2id
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    await client.query('BEGIN');

    // Create organization
    const orgResult = await client.query(
      'INSERT INTO organizations (name) VALUES ($1) RETURNING id, name, created_at',
      [orgName.trim()]
    );
    const org = orgResult.rows[0];

    // Seed default RBAC roles (Admin & Member) and standard permissions for organization
    const { adminRoleId } = await rbacService.seedOrganizationRoles(client, org.id);

    // Create initial admin user
    const userResult = await client.query(
      'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, role, created_at',
      [org.id, normalizedEmail, passwordHash, 'ADMIN']
    );
    const user = userResult.rows[0];

    // Assign Admin role to initial user in user_roles table
    await rbacService.assignRoleToUser(client, user.id, adminRoleId);

    // Register initial trusted device in user_devices table
    await client.query(
      `INSERT INTO user_devices 
        (user_id, device_id, device_platform, user_agent, last_ip, last_region, last_country, last_state, last_city, is_trusted)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
       ON CONFLICT (user_id, device_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip, last_region = EXCLUDED.last_region, last_seen_at = CURRENT_TIMESTAMP`,
      [user.id, deviceId, devicePlatform, userAgent, location.ip, location.regionLabel, location.country, location.state, location.city]
    );

    await client.query('COMMIT');

    // Audit Event Recording (Cycle 10.6)
    await auditService.recordAuditEvent({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      eventType: 'REGISTER',
      action: 'ALLOW',
      resourceId: org.id,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
      deviceId,
      reason: 'Organization registered and initial Admin account created.',
    });

    const token = generateToken({
      userId: user.id,
      orgId: org.id,
      email: user.email,
      role: user.role,
      deviceId,
    });

    res.status(201).json({
      message: 'Organization and Admin account registered successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
      },
      organization: {
        id: org.id,
        name: org.name,
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
  const deviceId = req.headers['x-client-device-id'] || req.body.deviceId || 'electron-default-device';
  const devicePlatform = req.headers['x-client-platform'] || 'Electron-Windows';
  const userAgent = req.headers['user-agent'] || 'SecureVault-Electron-Client';
  const location = geoService.extractLocation(req);

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.password_hash, u.role, u.created_at, 
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

    // Verify password hash using Argon2id
    const isValidPassword = await argon2.verify(user.password_hash, password);
    if (!isValidPassword) {
      await auditService.recordAuditEvent({
        organizationId: user.organization_id,
        userId: user.id,
        userEmail: user.email,
        eventType: 'LOGIN_FAILED',
        action: 'DENY',
        resourceId: null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
        deviceId,
        reason: 'Invalid email or password.',
      });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Register/update trusted device in user_devices table on successful password authentication
    await pool.query(
      `INSERT INTO user_devices 
        (user_id, device_id, device_platform, user_agent, last_ip, last_region, last_country, last_state, last_city, is_trusted)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
       ON CONFLICT (user_id, device_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip, last_region = EXCLUDED.last_region, last_seen_at = CURRENT_TIMESTAMP`,
      [user.id, deviceId, devicePlatform, userAgent, location.ip, location.regionLabel, location.country, location.state, location.city]
    );

    // Audit Successful Login
    await auditService.recordAuditEvent({
      organizationId: user.organization_id,
      userId: user.id,
      userEmail: user.email,
      eventType: 'LOGIN',
      action: 'ALLOW',
      resourceId: null,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
      deviceId,
      reason: 'User authentication successful.',
    });

    const token = generateToken({
      userId: user.id,
      orgId: user.organization_id,
      email: user.email,
      role: user.role,
      deviceId,
    });

    res.json({
      message: 'Authentication successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
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

// GET /api/auth/me - Protected endpoint to fetch current authenticated user
router.get('/me', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.role, u.created_at, 
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

    res.json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
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
