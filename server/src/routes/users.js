const express = require('express');
const argon2 = require('argon2');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') {
    return res.status(403).json({ message: 'Administrator access required.' });
  }
  next();
}

// GET /api/users/members - Admin: list all users in the current organization
router.get('/members', verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, role, public_key, created_at
       FROM users
       WHERE organization_id = $1
       ORDER BY created_at ASC`,
      [req.user.orgId]
    );

    const users = result.rows.map((user) => ({
      id: user.id,
      email: user.email,
      role: user.role,
      hasPublicKey: Boolean(user.public_key),
      createdAt: user.created_at,
    }));

    res.json({ users });
  } catch (error) {
    console.error('[List Org Members Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization users.' });
  }
});

// POST /api/users - Admin: create an additional user in the current organization
router.post('/', verifyToken, requireAdmin, async (req, res) => {
  const { email, password, role } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const assignedRole = role === 'ADMIN' ? 'ADMIN' : 'USER';

  try {
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'A user with this email address already exists.' });
    }

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    const result = await pool.query(
      `INSERT INTO users (organization_id, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, role, created_at`,
      [req.user.orgId, normalizedEmail, passwordHash, assignedRole]
    );

    const user = result.rows[0];
    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
      },
    });
  } catch (error) {
    console.error('[Create User Error]:', error.message);
    res.status(500).json({ message: 'Failed to create organization user.' });
  }
});

// GET /api/users - Retrieve other users in the same organization for file sharing
router.get('/', verifyToken, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const organizationId = req.user.orgId;

    const result = await pool.query(
      `SELECT id, email, public_key 
       FROM users 
       WHERE organization_id = $1 
         AND id != $2 
         AND public_key IS NOT NULL 
       ORDER BY email ASC`,
      [organizationId, currentUserId]
    );

    const users = result.rows.map(user => ({
      id: user.id,
      email: user.email,
      publicKey: user.public_key,
    }));

    res.json({ users });
  } catch (error) {
    console.error('[User Search Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve user directory.' });
  }
});

module.exports = router;
