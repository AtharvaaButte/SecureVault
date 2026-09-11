const express = require('express');
const argon2 = require('argon2');
const crypto = require('crypto');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const { validateStrongPassword } = require('../utils/validation');
const rbacService = require('../services/rbacService');

const router = express.Router();

// GET /api/users/members - List non-owner organization members for member management, role assignment & file sharing
router.get('/members', verifyToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;

    // 1. Fetch non-owner organization members
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.status, u.is_active, u.setup_token, u.created_at, uk.public_key
       FROM users u
       LEFT JOIN user_keys uk ON u.id = uk.user_id
       WHERE u.organization_id = $1 AND u.is_owner = false
       ORDER BY u.created_at ASC`,
      [orgId]
    );

    const isCallerOwner = Boolean(req.user.isOwner);
    const callerCanManage = isCallerOwner ||
      (await rbacService.hasPermission(req.user.userId, 'USER_MANAGE')) ||
      (await rbacService.hasPermission(req.user.userId, 'USER_CREATE'));

    const users = [];
    for (const u of result.rows) {
      const roles = await rbacService.getUserRoles(u.id);
      const permissions = await rbacService.getUserPermissions(u.id);

      const pubKey = u.public_key || null;
      const isKeyRegistered = Boolean(u.public_key);
      const computedStatus = u.status || (u.is_active ? 'ACTIVE' : 'SETUP_REQUIRED');

      users.push({
        id: u.id,
        name: u.name,
        email: u.email,
        status: computedStatus,
        isActive: Boolean(u.is_active && computedStatus === 'ACTIVE'),
        setupToken: callerCanManage ? (u.setup_token || null) : null,
        publicKey: pubKey,
        publicKeyRegistered: isKeyRegistered,
        roles,
        permissions: callerCanManage ? permissions : [],
        createdAt: u.created_at,
      });
    }

    // 2. Fetch Organization Owner metadata
    const ownerRes = await pool.query(
      `SELECT u.id, u.name, u.email, u.created_at, uk.public_key
       FROM users u
       LEFT JOIN user_keys uk ON u.id = uk.user_id
       WHERE u.organization_id = $1 AND u.is_owner = true`,
      [orgId]
    );

    const owner = ownerRes.rows.length > 0 ? {
      id: ownerRes.rows[0].id,
      name: ownerRes.rows[0].name,
      email: ownerRes.rows[0].email,
      publicKey: ownerRes.rows[0].public_key || null,
      publicKeyRegistered: Boolean(ownerRes.rows[0].public_key),
      isOwner: true,
      createdAt: ownerRes.rows[0].created_at,
    } : null;

    res.json({ users, owner });
  } catch (error) {
    console.error('[Get Members Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization members.' });
  }
});

// GET /api/users/search?q=query - Search for recipients by name or email
router.get('/search', verifyToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;
    const queryStr = req.query.q ? String(req.query.q).trim().toLowerCase() : '';

    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.status, u.is_active, u.created_at, uk.public_key
       FROM users u
       LEFT JOIN user_keys uk ON u.id = uk.user_id
       WHERE u.organization_id = $1 
         AND ($2 = '' OR LOWER(u.name) LIKE $3 OR LOWER(u.email) LIKE $3)
       ORDER BY u.name ASC, u.email ASC
       LIMIT 20`,
      [orgId, queryStr, `%${queryStr}%`]
    );

    const users = [];
    for (const u of result.rows) {
      const roles = await rbacService.getUserRoles(u.id);
      const pubKey = u.public_key || null;
      const isKeyRegistered = Boolean(u.public_key);
      const computedStatus = u.status || (u.is_active ? 'ACTIVE' : 'SETUP_REQUIRED');

      users.push({
        id: u.id,
        name: u.name,
        email: u.email,
        status: computedStatus,
        isActive: Boolean(u.is_active && computedStatus === 'ACTIVE'),
        publicKey: pubKey,
        publicKeyRegistered: isKeyRegistered,
        roles,
        createdAt: u.created_at,
      });
    }

    res.json({ users });
  } catch (error) {
    console.error('[Search Members Error]:', error.message);
    res.status(500).json({ message: 'Failed to search organization members.' });
  }
});

// GET /api/users/:id/permissions - Query effective roles & permissions for a specific user
router.get('/:id/permissions', verifyToken, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const orgId = req.user.orgId;

    const userCheck = await pool.query(
      `SELECT u.id, u.name, u.email, u.is_owner, u.organization_id, uk.public_key 
       FROM users u
       LEFT JOIN user_keys uk ON u.id = uk.user_id
       WHERE u.id = $1 AND u.organization_id = $2`,
      [targetUserId, orgId]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'User not found in this organization.' });
    }

    const targetUser = userCheck.rows[0];
    const roles = await rbacService.getUserRoles(targetUserId);
    const permissions = await rbacService.getUserPermissions(targetUserId);

    const pubKey = targetUser.public_key || null;

    res.json({
      userId: targetUserId,
      name: targetUser.name,
      email: targetUser.email,
      isOwner: Boolean(targetUser.is_owner),
      publicKey: pubKey,
      publicKeyRegistered: Boolean(pubKey),
      roles,
      permissions,
    });
  } catch (error) {
    console.error('[Get User Permissions Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve user permissions.' });
  }
});

// POST /api/users - Create new organization member account (Requires USER_CREATE)
router.post('/', verifyToken, requirePermission('USER_CREATE'), async (req, res) => {
  try {
    const { name, email, password, roleIds, roleId } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email address is required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const userName = name && typeof name === 'string' && name.trim().length > 0 ? name.trim() : normalizedEmail.split('@')[0];
    const orgId = req.user.orgId;

    // Check if user already exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ message: 'A user with this email address already exists.' });
    }

    let passwordHash = null;
    let setupToken = null;
    let setupTokenExpires = null;
    let isActive = false;
    let userStatus = 'SETUP_REQUIRED';

    if (password && String(password).trim().length > 0) {
      const passwordCheck = validateStrongPassword(password);
      if (!passwordCheck.valid) {
        return res.status(400).json({ message: passwordCheck.message });
      }
      passwordHash = await argon2.hash(password.trim(), { type: argon2.argon2id });
      isActive = true;
      userStatus = 'ACTIVE';
    } else {
      setupToken = crypto.randomUUID();
      // Setup token expires in 7 days
      setupTokenExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      isActive = false;
      userStatus = 'SETUP_REQUIRED';
    }

    // Determine role IDs to assign (Mandatory role selection required)
    let targetRoleIds = [];
    if (Array.isArray(roleIds) && roleIds.length > 0) {
      targetRoleIds = roleIds;
    } else if (roleId && typeof roleId === 'string' && roleId.trim().length > 0) {
      targetRoleIds = [roleId];
    }

    if (targetRoleIds.length === 0) {
      return res.status(400).json({ message: 'Please select at least one role.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const userRes = await client.query(
        `INSERT INTO users (organization_id, name, email, password_hash, is_owner, setup_token, setup_token_expires, is_active, status) 
         VALUES ($1, $2, $3, $4, false, $5, $6, $7, $8) 
         RETURNING id, name, email, is_active, status, setup_token, created_at`,
        [orgId, userName, normalizedEmail, passwordHash, setupToken, setupTokenExpires, isActive, userStatus]
      );
      const newUser = userRes.rows[0];

      for (const rId of targetRoleIds) {
        await client.query(
          'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [newUser.id, rId]
        );
      }

      await client.query('COMMIT');

      const assignedRoles = await rbacService.getUserRoles(newUser.id);
      const effectivePermissions = await rbacService.getUserPermissions(newUser.id);

      res.status(201).json({
        message: isActive ? 'User account created successfully.' : 'User account created with pending setup link.',
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          status: newUser.status || 'SETUP_REQUIRED',
          isActive: Boolean(newUser.is_active),
          setupToken: newUser.setup_token || null,
          setupUrl: newUser.setup_token ? `/setup/${newUser.setup_token}` : null,
          isOwner: false,
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

// PUT /api/users/:id/roles - Update role assignments for a non-owner member (Requires USER_MANAGE)
router.put('/:id/roles', verifyToken, requirePermission('USER_MANAGE'), async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const { roleIds } = req.body;

    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      return res.status(400).json({ message: 'At least one role ID must be provided.' });
    }

    const userCheck = await pool.query(
      'SELECT id, is_owner FROM users WHERE id = $1 AND organization_id = $2',
      [targetUserId, req.user.orgId]
    );

    if (userCheck.rows.length === 0) {
      return res.status(403).json({ message: 'Access denied. User does not belong to this organization.' });
    }

    if (userCheck.rows[0].is_owner) {
      return res.status(403).json({ message: 'Role assignments cannot be modified for the Organization Owner.' });
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

// DELETE /api/users/:id - Delete a member account from organization (Requires USER_MANAGE)
router.delete('/:id', verifyToken, requirePermission('USER_MANAGE'), async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const orgId = req.user.orgId;

    const userCheck = await pool.query(
      'SELECT id, name, email, is_owner FROM users WHERE id = $1 AND organization_id = $2',
      [targetUserId, orgId]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'User not found in this organization.' });
    }

    const targetUser = userCheck.rows[0];

    // Inviolable Rule: Owner cannot be deleted via member deletion
    if (targetUser.is_owner) {
      return res.status(403).json({ message: 'Organization Owner cannot be deleted through member deletion.' });
    }

    await pool.query('DELETE FROM users WHERE id = $1 AND organization_id = $2', [targetUserId, orgId]);

    res.json({
      message: `Member account (${targetUser.name || targetUser.email}) deleted successfully.`,
      userId: targetUserId,
    });
  } catch (error) {
    console.error('[Delete Member Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to delete member account.' });
  }
});

module.exports = router;
