const { pool } = require('../db');

/**
 * Finalized Dynamic RBAC Service
 * Legacy users.role removed. Roles come strictly from user_roles -> roles -> role_permissions -> permissions.
 * Role auditability: created_by recorded on custom roles.
 */

/**
 * Check if a user is the Organization Owner.
 */
async function isOwner(userId) {
  if (!userId) return false;
  const res = await pool.query('SELECT is_owner FROM users WHERE id = $1', [userId]);
  return res.rows.length > 0 && Boolean(res.rows[0].is_owner);
}

/**
 * Legacy initial role creation helper (Deprecated - Owner is a special account, not a custom role).
 */
async function createInitialOrgRole(clientOrPool, orgId, roleName = 'Owner', description = 'Organization Owner with full capabilities', creatorUserId = null) {
  // No-op for backwards compatibility during migration/tests
  return null;
}

/**
 * Assign a single role to a user.
 */
async function assignRoleToUser(clientOrPool, userId, roleId) {
  if (!roleId) return;
  const executor = clientOrPool || pool;
  await executor.query(
    `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [userId, roleId]
  );
}

/**
 * Assign multiple roles to a user within an organization.
 */
async function assignUserRoles(orgId, userId, roleIds) {
  if (await isOwner(userId)) {
    throw new Error('Role assignments cannot be modified for the Organization Owner.');
  }

  if (!Array.isArray(roleIds) || roleIds.length === 0) {
    throw new Error('At least one valid role ID must be assigned to the user.');
  }

  const validRoles = await pool.query(
    'SELECT id FROM roles WHERE organization_id = $1 AND id = ANY($2::uuid[])',
    [orgId, roleIds]
  );

  if (validRoles.rows.length !== roleIds.length) {
    throw new Error('One or more selected roles do not belong to this organization.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);

    for (const roleId of roleIds) {
      await client.query(
        'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [userId, roleId]
      );
    }

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Retrieve a list of distinct permission names assigned to a user via their roles.
 * Organization Owners inherently possess all standard system permissions.
 */
async function getUserPermissions(userId) {
  if (await isOwner(userId)) {
    const allPerms = await getAllPermissions();
    return allPerms.map(p => p.name);
  }

  const result = await pool.query(
    `SELECT DISTINCT p.name
     FROM permissions p
     JOIN role_permissions rp ON p.id = rp.permission_id
     JOIN user_roles ur ON rp.role_id = ur.role_id
     WHERE ur.user_id = $1`,
    [userId]
  );
  return result.rows.map(row => row.name);
}

/**
 * Get assigned roles for a user.
 * Organization Owners do not have custom organization roles assigned.
 */
async function getUserRoles(userId) {
  if (await isOwner(userId)) {
    return [];
  }

  const result = await pool.query(
    `SELECT r.id, r.name, r.description, r.created_by
     FROM roles r
     JOIN user_roles ur ON r.id = ur.role_id
     WHERE ur.user_id = $1`,
    [userId]
  );
  return result.rows;
}

/**
 * Check if a user has a specific permission.
 */
async function hasPermission(userId, permissionName) {
  if (await isOwner(userId)) {
    return true;
  }
  const permissions = await getUserPermissions(userId);
  return permissions.includes(permissionName);
}

/**
 * Get all system permissions catalog.
 */
async function getAllPermissions() {
  const result = await pool.query(
    'SELECT id, name, description FROM permissions ORDER BY name ASC'
  );
  return result.rows;
}

/**
 * List all organization roles with mapped permissions and creator auditability.
 */
async function getOrganizationRoles(orgId) {
  const rolesRes = await pool.query(
    `SELECT r.id, r.name, r.description, r.created_by, r.created_at, u.email as creator_email
     FROM roles r
     LEFT JOIN users u ON r.created_by = u.id
     WHERE r.organization_id = $1
     ORDER BY r.created_at ASC`,
    [orgId]
  );

  const roles = [];
  for (const role of rolesRes.rows) {
    const permsRes = await pool.query(
      `SELECT p.id, p.name, p.description
       FROM permissions p
       JOIN role_permissions rp ON p.id = rp.permission_id
       WHERE rp.role_id = $1
       ORDER BY p.name ASC`,
      [role.id]
    );

    roles.push({
      id: role.id,
      name: role.name,
      description: role.description,
      createdBy: role.created_by,
      creatorEmail: role.creator_email,
      permissions: permsRes.rows,
      createdAt: role.created_at,
    });
  }

  return roles;
}

/**
 * Create a new custom role within an organization (Role auditability: created_by).
 * Reserved role name "Owner" cannot be created as a custom role.
 */
async function createCustomRole(orgId, name, description, permissionNames = [], creatorUserId = null) {
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    throw new Error('Role name is required.');
  }

  const normalizedName = name.trim();

  if (normalizedName.toLowerCase() === 'owner') {
    throw new Error('"Owner" is a reserved name and cannot be created as a custom organization role.');
  }

  const existing = await pool.query(
    'SELECT id FROM roles WHERE organization_id = $1 AND LOWER(name) = LOWER($2)',
    [orgId, normalizedName]
  );
  if (existing.rows.length > 0) {
    throw new Error(`A role named "${normalizedName}" already exists in this organization.`);
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const roleRes = await client.query(
      `INSERT INTO roles (organization_id, name, description, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, description, created_by, created_at`,
      [orgId, normalizedName, description || '', creatorUserId]
    );
    const roleId = roleRes.rows[0].id;

    if (Array.isArray(permissionNames) && permissionNames.length > 0) {
      const permsRes = await client.query(
        'SELECT id, name FROM permissions WHERE name = ANY($1::text[])',
        [permissionNames]
      );

      for (const p of permsRes.rows) {
        await client.query(
          'INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [roleId, p.id]
        );
      }
    }

    await client.query('COMMIT');
    return {
      id: roleId,
      name: roleRes.rows[0].name,
      description: roleRes.rows[0].description,
      createdBy: roleRes.rows[0].created_by,
      createdAt: roleRes.rows[0].created_at,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Update permissions for an organization role.
 */
async function updateRolePermissions(orgId, roleId, permissionNames = []) {
  const roleCheck = await pool.query(
    'SELECT id, name FROM roles WHERE id = $1 AND organization_id = $2',
    [roleId, orgId]
  );
  if (roleCheck.rows.length === 0) {
    throw new Error('Role not found or does not belong to this organization.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query('DELETE FROM role_permissions WHERE role_id = $1', [roleId]);

    if (Array.isArray(permissionNames) && permissionNames.length > 0) {
      const permsRes = await client.query(
        'SELECT id, name FROM permissions WHERE name = ANY($1::text[])',
        [permissionNames]
      );

      for (const p of permsRes.rows) {
        await client.query(
          'INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [roleId, p.id]
        );
      }
    }

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Delete a role from an organization.
 */
async function deleteCustomRole(orgId, roleId) {
  const roleCheck = await pool.query(
    'SELECT id, name FROM roles WHERE id = $1 AND organization_id = $2',
    [roleId, orgId]
  );
  if (roleCheck.rows.length === 0) {
    throw new Error('Role not found or does not belong to this organization.');
  }

  const assignedUsersRes = await pool.query(
    'SELECT COUNT(*) FROM user_roles WHERE role_id = $1',
    [roleId]
  );
  const assignedCount = parseInt(assignedUsersRes.rows[0].count, 10);
  if (assignedCount > 0) {
    throw new Error(`Cannot delete role "${roleCheck.rows[0].name}" because it is currently assigned to ${assignedCount} member(s). Reassign or remove the role from those members first.`);
  }

  await pool.query('DELETE FROM roles WHERE id = $1 AND organization_id = $2', [roleId, orgId]);
}

/**
 * Fetch permission audit records from user_permission_audit_view (Item 9)
 */
async function getPermissionAuditRecords(orgId) {
  const result = await pool.query(
    'SELECT * FROM user_permission_audit_view WHERE organization_id = $1 ORDER BY user_email, role_name, permission_name',
    [orgId]
  );
  return result.rows;
}

module.exports = {
  isOwner,
  createInitialOrgRole,
  assignRoleToUser,
  assignUserRoles,
  getUserPermissions,
  getUserRoles,
  hasPermission,
  getAllPermissions,
  getOrganizationRoles,
  createCustomRole,
  updateRolePermissions,
  deleteCustomRole,
  getPermissionAuditRecords,
};
