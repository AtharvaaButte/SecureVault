const express = require('express');
const { verifyToken } = require('../middleware/auth');
const { requirePermission } = require('../middleware/authorize');
const policyService = require('../services/policyService');

const router = express.Router();

// GET /api/policies - Get current organization security policy & allowed geographic locations (Requires ORG_MANAGE)
router.get('/', verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const policy = await policyService.getOrganizationPolicy(req.user.orgId);
    res.json({ policy });
  } catch (error) {
    console.error('[Get Org Policy Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve organization policy.' });
  }
});

// PUT /api/policies - Update organization core security settings (Requires ORG_MANAGE)
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

// POST /api/policies/locations - Add an allowed geographic location rule (Requires ORG_MANAGE)
router.post('/locations', verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const { allowedCountry, allowedState, allowedCity } = req.body;
    const newLocation = await policyService.addGeoPolicyLocation(req.user.orgId, {
      allowedCountry,
      allowedState,
      allowedCity,
    });

    const fullPolicy = await policyService.getOrganizationPolicy(req.user.orgId);

    res.status(201).json({
      message: 'Allowed geographic location policy added successfully.',
      location: newLocation,
      policy: fullPolicy,
    });
  } catch (error) {
    console.error('[Add Geo Location Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to add geographic location policy.' });
  }
});

// DELETE /api/policies/locations/:id - Remove an allowed geographic location rule (Requires ORG_MANAGE)
router.delete('/locations/:id', verifyToken, requirePermission('ORG_MANAGE'), async (req, res) => {
  try {
    const geoPolicyId = req.params.id;
    await policyService.removeGeoPolicyLocation(req.user.orgId, geoPolicyId);

    const fullPolicy = await policyService.getOrganizationPolicy(req.user.orgId);

    res.json({
      message: 'Allowed geographic location policy removed successfully.',
      policy: fullPolicy,
    });
  } catch (error) {
    console.error('[Remove Geo Location Error]:', error.message);
    res.status(400).json({ message: error.message || 'Failed to remove geographic location policy.' });
  }
});

module.exports = router;
