const { pool } = require('../db');

/**
 * Organization Security Policy Service (Cycle 10.2)
 */

async function getOrganizationPolicy(orgId) {
  const result = await pool.query(
    'SELECT * FROM organization_policies WHERE organization_id = $1',
    [orgId]
  );

  if (result.rows.length > 0) {
    return result.rows[0];
  }

  // Seed default policy if missing
  const defaultPolicyRes = await pool.query(
    `INSERT INTO organization_policies 
      (organization_id, allowed_country, allowed_state, allowed_city, require_stepup_new_location, require_stepup_sensitive_file, enforce_geo_fencing)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (organization_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
     RETURNING *`,
    [orgId, 'IN', 'ALL', 'ALL', true, true, false]
  );

  return defaultPolicyRes.rows[0];
}

async function updateOrganizationPolicy(orgId, policyData) {
  const {
    allowedCountry,
    allowedState,
    allowedCity,
    requireStepupNewLocation,
    requireStepupSensitiveFile,
    enforceGeoFencing,
  } = policyData || {};

  const current = await getOrganizationPolicy(orgId);

  const newCountry = (allowedCountry !== undefined && typeof allowedCountry === 'string' && allowedCountry.trim().length > 0)
    ? allowedCountry.trim().toUpperCase()
    : current.allowed_country;

  const newState = (allowedState !== undefined && typeof allowedState === 'string' && allowedState.trim().length > 0)
    ? allowedState.trim()
    : current.allowed_state;

  const newCity = (allowedCity !== undefined && typeof allowedCity === 'string' && allowedCity.trim().length > 0)
    ? allowedCity.trim()
    : current.allowed_city;

  const newStepupNewLoc = requireStepupNewLocation !== undefined ? Boolean(requireStepupNewLocation) : Boolean(current.require_stepup_new_location);
  const newStepupSensFile = requireStepupSensitiveFile !== undefined ? Boolean(requireStepupSensitiveFile) : Boolean(current.require_stepup_sensitive_file);
  const newEnforceGeoFence = enforceGeoFencing !== undefined ? Boolean(enforceGeoFencing) : Boolean(current.enforce_geo_fencing);

  const updateRes = await pool.query(
    `UPDATE organization_policies
     SET allowed_country = $1,
         allowed_state = $2,
         allowed_city = $3,
         require_stepup_new_location = $4,
         require_stepup_sensitive_file = $5,
         enforce_geo_fencing = $6,
         updated_at = CURRENT_TIMESTAMP
     WHERE organization_id = $7
     RETURNING *`,
    [newCountry, newState, newCity, newStepupNewLoc, newStepupSensFile, newEnforceGeoFence, orgId]
  );

  return updateRes.rows[0];
}

function evaluateGeoPolicy(policy, location) {
  if (!policy || !location) {
    return { isViolation: false, allowed: true };
  }

  const countryMatch = policy.allowed_country === 'ALL' || location.country === policy.allowed_country;
  const stateMatch = policy.allowed_state === 'ALL' || location.state === policy.allowed_state;
  const cityMatch = policy.allowed_city === 'ALL' || location.city === policy.allowed_city;

  if (!countryMatch || !stateMatch || !cityMatch) {
    let violationScope = '';
    if (!countryMatch) violationScope = `Country (${location.country} != ${policy.allowed_country})`;
    else if (!stateMatch) violationScope = `State (${location.state} != ${policy.allowed_state})`;
    else if (!cityMatch) violationScope = `City (${location.city} != ${policy.allowed_city})`;

    return {
      isViolation: true,
      allowed: false,
      enforceGeoFencing: Boolean(policy.enforce_geo_fencing),
      violationScope,
      reason: `Access location "${location.city}, ${location.state}, ${location.country}" violates organization geographic scope policy [Scope: ${policy.allowed_city}, ${policy.allowed_state}, ${policy.allowed_country}].`,
    };
  }

  return { isViolation: false, allowed: true };
}

module.exports = {
  getOrganizationPolicy,
  updateOrganizationPolicy,
  evaluateGeoPolicy,
};
