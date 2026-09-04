const express = require('express');
const argon2 = require('argon2');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const rbacService = require('../services/rbacService');

const router = express.Router();

// GET /api/users/members - List organization members with assigned roles, effective permissions & user_keys status
router.get('/members', verifyToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;

    const result = await pool.query(
      `SELECT u.id, u.email, u.created_at, uk.public_key
       FROM users u
       LEFT JOIN user_keys uk ON u.id = uk.user_id
       WHERE u.organization_id = $1
       ORDER BY u.created_at ASC`,
      [orgId]
    );

    const users = [];
    for (const u of result.rows) {
      const roles = await rbacService.getUserRoles(u.id);
      const permissions = await rbacService.getUserPermissions(u.id);

      users.push({
        id: u.id,
        email: u.email,
        publicKeyRegistered: Boolean(u.public_key),
        roles,
        permissions,
        createdAt: u.created_at,
      });
    }

    res.json({ users });
  } catch (error) {
    console.error('[Get Members Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization members.' });
  }
});

// GET /api/users/:id/permissions - Query effective roles & permissions for a specific user (Item 7)
router.get('/:id/permissions', verifyToken, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const orgId = req.user.orgId;

    const userCheck = await pool.query(
      'SELECT id, email, organization_id FROM users WHERE id = $1 AND organization_id = $2',
      [targetUserId, orgId]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'User not found in this organization.' });
    }

    const roles = await rbacService.getUserRoles(targetUserId);
    const permissions = await rbacService.getUserPermissions(targetUserId);

    res.json({
      userId: targetUserId,
      email: userCheck.rows[0].email,
      roles,
      permissions,
    });
  } catch (error) {
    console.error('[Get User Permissions Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve user permissions.' });
  }
});

// POST /api/users - Create new organization user account (Requires USER_CREATE)
router.post('/', verifyToken, requirePermission('USER_CREATE'), async (req, res) => {
  try {
    const { email, password, roleIds, roleId } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const orgId = req.user.orgId;

    // Check if user already exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ message: 'A user with this email address already exists.' });
    }

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const userRes = await client.query(
        'INSERT INTO users (organization_id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, created_at',
        [orgId, normalizedEmail, passwordHash]
      );
      const newUser = userRes.rows[0];

      // Determine role IDs to assign
      let targetRoleIds = [];
      if (Array.isArray(roleIds) && roleIds.length > 0) {
        targetRoleIds = roleIds;
      } else if (roleId) {
        targetRoleIds = [roleId];
      } else {
        const orgRoles = await rbacService.getOrganizationRoles(orgId);
        if (orgRoles.length > 0) {
          targetRoleIds = [orgRoles[0].id];
        }
      }

      if (targetRoleIds.length > 0) {
        for (const rId of targetRoleIds) {
          await client.query(
            'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [newUser.id, rId]
          );
        }
      }

      await client.query('COMMIT');

      const assignedRoles = await rbacService.getUserRoles(newUser.id);
      const effectivePermissions = await rbacService.getUserPermissions(newUser.id);

      res.status(201).json({
        message: 'User account created successfully.',
        user: {
          id: newUser.id,
          email: newUser.email,
          roles: assignedRoles,
          permissions: effectivePermissions,
          createdAt: newUser.created_at,
        },
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('[Create User Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to create user account.' });
  }
});

// PUT /api/users/:id/roles - Update role assignments for a user (Requires USER_MANAGE)
router.put('/:id/roles', verifyToken, requirePermission('USER_MANAGE'), async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const { roleIds } = req.body;

    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      return res.status(400).json({ message: 'At least one role ID must be provided.' });
    }

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
      roles: updatedRoles,
      permissions: updatedPermissions,
    });
  } catch (error) {
    console.error('[Update User Roles Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to update user roles.' });
  }
});

module.exports = router;
