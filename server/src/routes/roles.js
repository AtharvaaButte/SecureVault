const express = require('express');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const rbacService = require('../services/rbacService');

const router = express.Router();

// GET /api/roles/permissions - List all available system permissions (Requires ROLE_MANAGE or USER_MANAGE)
router.get('/permissions', verifyToken, requirePermission('ROLE_MANAGE'), async (req, res) => {
  try {
    const permissions = await rbacService.getAllPermissions();
    res.json({ permissions });
  } catch (error) {
    console.error('[List Permissions Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve system permissions.' });
  }
});

// GET /api/roles/audit - Permission Audit View: Retrieve user-role-permission mapping (Item 9, Requires ROLE_MANAGE)
router.get('/audit', verifyToken, requirePermission('ROLE_MANAGE'), async (req, res) => {
  try {
    const auditRecords = await rbacService.getPermissionAuditRecords(req.user.orgId);
    res.json({ auditRecords });
  } catch (error) {
    console.error('[Get Permission Audit View Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve permission audit view.' });
  }
});

// GET /api/roles - List all roles for the current organization (Requires ROLE_MANAGE or USER_MANAGE)
router.get('/', verifyToken, requirePermission('ROLE_MANAGE'), async (req, res) => {
  try {
    const roles = await rbacService.getOrganizationRoles(req.user.orgId);
    res.json({ roles });
  } catch (error) {
    console.error('[List Roles Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization roles.' });
  }
});

// POST /api/roles - Create a custom role in current org with created_by auditability (Requires ROLE_MANAGE)
router.post('/', verifyToken, requirePermission('ROLE_MANAGE'), async (req, res) => {
  try {
    const { name, description, permissions } = req.body || {};

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ message: 'Role name is required.' });
    }

    const newRole = await rbacService.createCustomRole(
      req.user.orgId,
      name.trim(),
      description || '',
      permissions || [],
      req.user.userId
    );

    res.status(201).json({
      message: 'Custom role created successfully.',
      role: newRole,
    });
  } catch (error) {
    console.error('[Create Custom Role Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to create custom role.' });
  }
});

// PUT /api/roles/:id/permissions - Update permissions for a custom role (Requires ROLE_MANAGE)
router.put('/:id/permissions', verifyToken, requirePermission('ROLE_MANAGE'), async (req, res) => {
  try {
    const roleId = req.params.id;
    const { permissions } = req.body || {};

    if (!Array.isArray(permissions)) {
      return res.status(400).json({ message: 'Permissions array is required.' });
    }

    await rbacService.updateRolePermissions(req.user.orgId, roleId, permissions);

    res.json({ message: 'Role permissions updated successfully.' });
  } catch (error) {
    console.error('[Update Role Permissions Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to update role permissions.' });
  }
});

// DELETE /api/roles/:id - Delete a custom organization role (Requires ROLE_MANAGE)
router.delete('/:id', verifyToken, requirePermission('ROLE_MANAGE'), async (req, res) => {
  try {
    const roleId = req.params.id;
    await rbacService.deleteCustomRole(req.user.orgId, roleId);
    res.json({ message: 'Custom role deleted successfully.' });
  } catch (error) {
    console.error('[Delete Custom Role Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to delete custom role.' });
  }
});

module.exports = router;
