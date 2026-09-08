const express = require('express');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const auditService = require('../services/auditService');

const router = express.Router();

// GET /api/audit & GET /api/audit/logs - Get organization audit logs (Requires ORG_MANAGE or USER_MANAGE)
router.get(['/', '/logs'], verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const logs = await auditService.getOrganizationAuditLogs(req.user.orgId, 100);
    res.json({ auditLogs: logs, logs });
  } catch (error) {
    console.error('[Get Audit Logs Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve security audit logs.' });
  }
});

// GET /api/audit/verify - Verify tamper-evident SHA-256 hash chain integrity (Requires ORG_MANAGE)
router.get('/verify', verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const verification = await auditService.verifyAuditChain(req.user.orgId);
    res.json(verification);
  } catch (error) {
    console.error('[Verify Audit Chain Error]:', error.message);
    res.status(500).json({ message: 'Failed to verify security audit chain integrity.' });
  }
});

module.exports = router;
