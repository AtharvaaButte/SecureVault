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

// POST /api/auth/register - Register organization and initial owner user
router.post('/register', async (req, res) => {
  const { orgName, email, password } = req.body;

  if (!orgName || !email || !password) {
    return res.status(400).json({ message: 'Organization name, email, and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
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

    // Create initial Owner role for org
    const ownerRoleId = await rbacService.createInitialOrgRole(client, org.id, 'Owner', 'Organization Owner with full capabilities');

    // Create initial user (without legacy role column)
    const userResult = await client.query(
      'INSERT INTO users (organization_id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, created_at',
      [org.id, normalizedEmail, passwordHash]
    );
    const user = userResult.rows[0];

    // Assign Owner role to initial user
    await rbacService.assignRoleToUser(client, user.id, ownerRoleId);

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
      email: user.email,
    });

    res.status(201).json({
      message: 'Organization and account registered successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        roles: userRoles,
        permissions: userPermissions,
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
  const location = geoService.extractLocation(req);

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.password_hash, u.created_at, 
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

    const token = generateToken({
      userId: user.id,
      orgId: user.organization_id,
      email: user.email,
    });

    res.json({
      message: 'Authentication successful',
      token,
      user: {
        id: user.id,
        email: user.email,
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

// GET /api/auth/me - Protected endpoint to fetch current authenticated user
router.get('/me', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.created_at, 
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

    res.json({
      user: {
        id: user.id,
        email: user.email,
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
