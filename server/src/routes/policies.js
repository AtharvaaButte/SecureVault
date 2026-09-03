const express = require('express');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const policyService = require('../services/policyService');

const router = express.Router();

// GET /api/policies - Get current organization security policy (Requires ORG_MANAGE or ROLE_MANAGE)
router.get('/', verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const policy = await policyService.getOrganizationPolicy(req.user.orgId);
    res.json({ policy });
  } catch (error) {
    console.error('[Get Org Policy Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization policy.' });
  }
});

// PUT /api/policies - Update organization security policy (Requires ORG_MANAGE)
router.put('/', verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const updatedPolicy = await policyService.updateOrganizationPolicy(req.user.orgId, req.body);
    res.json({
      message: 'Organization security policy updated successfully.',
      policy: updatedPolicy,
    });
  } catch (error) {
    console.error('[Update Org Policy Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to update organization security policy.' });
  }
});

module.exports = router;
