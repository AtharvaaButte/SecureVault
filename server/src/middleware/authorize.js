const { pool } = require('../db');
const rbacService = require('../services/rbacService');
const riskService = require('../services/riskService');

/**
 * Middleware: Require a specific dynamic RBAC permission + Risk Evaluation.
 */
function requirePermission(permissionName) {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user.userId) {
        return res.status(401).json({ message: 'Authentication required. No token context.' });
      }

      // 1. Dynamic RBAC Permission Check
      const hasPerm = await rbacService.hasPermission(req.user.userId, permissionName);
      if (!hasPerm) {
        return res.status(403).json({ message: `Access denied. Required permission: ${permissionName}` });
      }

      // 2. Risk & Sensitivity Evaluation
      const riskResult = await riskService.evaluateRisk(req.user.userId, req, permissionName, 'NORMAL');
      if (!riskResult.allow) {
        return res.status(403).json({
          message: riskResult.message || 'Access denied by security policy.',
          stepUpRequired: riskResult.stepUpRequired || false,
        });
      }

      next();
    } catch (error) {
      console.error('[Authorize RequirePermission Error]:', error.message);
      res.status(500).json({ message: 'Internal authorization processing error.' });
    }
  };
}

/**
 * Middleware: Require file access authorization for READ, SHARE, REVOKE, or DELETE.
 * Authorization Model:
 *   Final authorization = Role Permission + File Access + File-Level Restriction (file_restrictions)
 */
function requireFileAccess(accessType) {
  const permMap = {
    'READ': 'FILE_READ',
    'SHARE': 'FILE_SHARE',
    'REVOKE': 'FILE_REVOKE',
    'DELETE': 'FILE_DELETE',
  };

  const requiredPerm = permMap[accessType] || 'FILE_READ';

  return async (req, res, next) => {
    try {
      if (!req.user || !req.user.userId || !req.user.orgId) {
        return res.status(401).json({ message: 'Authentication required. No token context.' });
      }

      const fileId = req.params.id || req.body.fileId;
      if (!fileId) {
        return res.status(400).json({ message: 'File ID parameter is required.' });
      }

      // 1. Global Dynamic RBAC Permission Check
      const hasPerm = await rbacService.hasPermission(req.user.userId, requiredPerm);
      if (!hasPerm) {
        return res.status(403).json({ message: `Access denied. Required permission: ${requiredPerm}` });
      }

      // 2. Fetch file details from PostgreSQL
      const result = await pool.query(
        `SELECT f.id, f.owner_id, f.sensitivity_level, u.organization_id 
         FROM files f 
         JOIN users u ON f.owner_id = u.id 
         WHERE f.id = $1`,
        [fileId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: 'File not found.' });
      }

      const fileRecord = result.rows[0];

      // 3. Organization Isolation Check
      if (fileRecord.organization_id !== req.user.orgId) {
        return res.status(403).json({ message: 'Access denied. Cross-organization access is strictly prohibited.' });
      }

      const isOwner = fileRecord.owner_id === req.user.userId;

      // 4. File Access & Resource Check (file_keys)
      if (!isOwner) {
        const keyCheck = await pool.query(
          'SELECT id, access_level FROM file_keys WHERE file_id = $1 AND user_id = $2',
          [fileId, req.user.userId]
        );

        if (keyCheck.rows.length === 0) {
          return res.status(403).json({ message: 'Access denied. You do not have permission to access this file.' });
        }

        // 5. File-Specific Permission Restriction Check (file_restrictions table)
        const restrictionCheck = await pool.query(
          `SELECT id FROM file_restrictions 
           WHERE file_id = $1 AND user_id = $2 AND blocked_operation = $3`,
          [fileId, req.user.userId, requiredPerm]
        );

        if (restrictionCheck.rows.length > 0) {
          return res.status(403).json({
            message: `Access denied. Operation ${requiredPerm} is explicitly restricted on this specific file.`,
          });
        }
      }

      // 6. File Sensitivity Policy & Context Risk Evaluation
      const riskResult = await riskService.evaluateRisk(
        req.user.userId,
        req,
        requiredPerm,
        fileRecord.sensitivity_level || 'NORMAL'
      );

      if (!riskResult.allow) {
        return res.status(403).json({
          message: riskResult.message || 'Access denied by sensitivity policy.',
          stepUpRequired: riskResult.stepUpRequired || false,
        });
      }

      req.fileRecord = fileRecord;
      next();
    } catch (error) {
      console.error('[Authorize RequireFileAccess Error]:', error.message);
      res.status(500).json({ message: 'Internal authorization processing error.' });
    }
  };
}

module.exports = {
  requirePermission,
  requireFileAccess,
};
