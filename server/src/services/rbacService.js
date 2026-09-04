const { pool } = require('../db');

/**
 * Finalized RBAC Service
 * Legacy users.role removed. Roles come strictly from user_roles -> roles -> role_permissions -> permissions.
 * No mandatory system default roles; organizations create and manage their own roles.
 */

async function createInitialOrgRole(clientOrPool, orgId, roleName = 'Owner', description = 'Organization Owner with full permissions') {
  const executor = clientOrPool || pool;

  const permRes = await executor.query('SELECT id, name FROM permissions');
  const permMap = {};
  permRes.rows.forEach(p => {
    permMap[p.name] = p.id;
  });

  const roleRes = await executor.query(
    `INSERT INTO roles (organization_id, name, description)
     VALUES ($1, $2, $3)
     ON CONFLICT (organization_id, name) DO UPDATE SET description = EXCLUDED.description
     RETURNING id`,
    [orgId, roleName, description]
  );
  const roleId = roleRes.rows[0].id;

  // Map all standard system permissions to initial role
  const allPermNames = [
    'USER_CREATE', 'USER_MANAGE', 'ROLE_MANAGE', 'ORG_MANAGE',
    'FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE'
  ];

  for (const name of allPermNames) {
    if (permMap[name]) {
      await executor.query(
        `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [roleId, permMap[name]]
      );
    }
  }

  return roleId;
}

/**
 * Assign a single role to a user.
 */
async function assignRoleToUser(clientOrPool, userId, roleId) {
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
 */
async function getUserPermissions(userId) {
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
 */
async function getUserRoles(userId) {
  const result = await pool.query(
    `SELECT r.id, r.name, r.description
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
 * List all organization roles with mapped permissions.
 */
async function getOrganizationRoles(orgId) {
  const rolesRes = await pool.query(
    `SELECT id, name, description, created_at FROM roles WHERE organization_id = $1 ORDER BY created_at ASC`,
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
      permissions: permsRes.rows,
      createdAt: role.created_at,
    });
  }

  return roles;
}

/**
 * Create a new custom role within an organization.
 */
async function createCustomRole(orgId, name, description, permissionNames = []) {
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    throw new Error('Role name is required.');
  }

  const normalizedName = name.trim();

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
      `INSERT INTO roles (organization_id, name, description)
       VALUES ($1, $2, $3)
       RETURNING id, name, description, created_at`,
      [orgId, normalizedName, description || '']
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

  await pool.query('DELETE FROM roles WHERE id = $1 AND organization_id = $2', [roleId, orgId]);
}

module.exports = {
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
};
