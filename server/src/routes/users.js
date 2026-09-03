const express = require('express');
const argon2 = require('argon2');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const rbacService = require('../services/rbacService');

const router = express.Router();

// GET /api/users/members - List all users in current organization with assigned roles & effective permissions (Requires USER_MANAGE)
router.get('/members', verifyToken, requirePermission('USER_MANAGE'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, role, public_key, created_at
       FROM users
       WHERE organization_id = $1
       ORDER BY created_at ASC`,
      [req.user.orgId]
    );

    const users = [];
    for (const user of result.rows) {
      const assignedRoles = await rbacService.getUserRoles(user.id);
      const permissions = await rbacService.getUserPermissions(user.id);

      users.push({
        id: user.id,
        email: user.email,
        legacyRole: user.role,
        roles: assignedRoles,
        permissions,
        hasPublicKey: Boolean(user.public_key),
        createdAt: user.created_at,
      });
    }

    res.json({ users });
  } catch (error) {
    console.error('[List Org Members Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization users.' });
  }
});

// POST /api/users - Create an additional user in the current organization (Requires USER_CREATE)
router.post('/', verifyToken, requirePermission('USER_CREATE'), async (req, res) => {
  const { email, password, role, roleIds } = req.body || {};

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

    // Seed default roles if needed
    const { adminRoleId, memberRoleId } = await rbacService.seedOrganizationRoles(pool, req.user.orgId);

    if (Array.isArray(roleIds) && roleIds.length > 0) {
      await rbacService.assignUserRoles(req.user.orgId, user.id, roleIds);
    } else {
      const defaultRoleId = assignedRole === 'ADMIN' ? adminRoleId : memberRoleId;
      await rbacService.assignRoleToUser(pool, user.id, defaultRoleId);
    }

    const assignedRoles = await rbacService.getUserRoles(user.id);
    const permissions = await rbacService.getUserPermissions(user.id);

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.id,
        email: user.email,
        legacyRole: user.role,
        roles: assignedRoles,
        permissions,
        createdAt: user.created_at,
      },
    });
  } catch (error) {
    console.error('[Create User Error]:', error.message);
    res.status(500).json({ message: 'Failed to create organization user.' });
  }
});

// PUT /api/users/:id/roles - Assign or update multiple roles for a user in the organization (Requires ROLE_MANAGE or USER_MANAGE)
router.put('/:id/roles', verifyToken, requirePermission('USER_MANAGE'), async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const { roleIds } = req.body || {};

    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      return res.status(400).json({ message: 'At least one role ID is required.' });
    }

    // Check target user belongs to caller's organization (Organization Boundary Check)
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE id = $1 AND organization_id = $2',
      [targetUserId, req.user.orgId]
    );
    if (userCheck.rows.length === 0) {
      return res.status(403).json({ message: 'Access denied. User does not belong to this organization.' });
    }

    await rbacService.assignUserRoles(req.user.orgId, targetUserId, roleIds);

    const updatedRoles = await rbacService.getUserRoles(targetUserId);
    const updatedPermissions = await rbacService.getUserPermissions(targetUserId);

    res.json({
      message: 'User roles updated successfully.',
      userId: targetUserId,
      roles: updatedRoles,
      permissions: updatedPermissions,
    });
  } catch (error) {
    console.error('[Update User Roles Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to update user roles.' });
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
