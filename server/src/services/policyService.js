const { pool } = require('../db');

/**
 * Simplified Organization Security Policy & Multi-Geo Policy Service
 */

async function getOrganizationPolicy(orgId) {
  let policyRes = await pool.query(
    'SELECT * FROM organization_policies WHERE organization_id = $1',
    [orgId]
  );

  let policy;
  if (policyRes.rows.length === 0) {
    const defaultPolicyRes = await pool.query(
      `INSERT INTO organization_policies 
        (organization_id, require_stepup_new_location, require_stepup_sensitive_file, enforce_geo_fencing)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (organization_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [orgId, true, true, false]
    );
    policy = defaultPolicyRes.rows[0];
  } else {
    policy = policyRes.rows[0];
  }

  // Fetch allowed geographic scope policies
  let geoRes = await pool.query(
    'SELECT id, allowed_country, allowed_state, allowed_city, created_at FROM organization_geo_policies WHERE organization_id = $1 ORDER BY created_at ASC',
    [orgId]
  );

  let allowedLocations = geoRes.rows;
  if (allowedLocations.length === 0) {
    const defaultGeoRes = await pool.query(
      `INSERT INTO organization_geo_policies 
        (organization_id, allowed_country, allowed_state, allowed_city)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT DO NOTHING
       RETURNING id, allowed_country, allowed_state, allowed_city, created_at`,
      [orgId, 'IN', 'ALL', 'ALL']
    );
    if (defaultGeoRes.rows.length > 0) {
      allowedLocations = defaultGeoRes.rows;
    } else {
      const fetchRefreshed = await pool.query(
        'SELECT id, allowed_country, allowed_state, allowed_city, created_at FROM organization_geo_policies WHERE organization_id = $1',
        [orgId]
      );
      allowedLocations = fetchRefreshed.rows;
    }
  }

  return {
    ...policy,
    allowedLocations,
  };
}

async function updateOrganizationPolicy(orgId, policyData) {
  const data = policyData || {};
  const current = await getOrganizationPolicy(orgId);

  const inputLoc = data.require_stepup_new_location !== undefined ? data.require_stepup_new_location : data.requireStepupNewLocation;
  const inputSens = data.require_stepup_sensitive_file !== undefined ? data.require_stepup_sensitive_file : data.requireStepupSensitiveFile;
  const inputGeo = data.enforce_geo_fencing !== undefined ? data.enforce_geo_fencing : data.enforceGeoFencing;

  const newStepupNewLoc = inputLoc !== undefined ? Boolean(inputLoc) : Boolean(current.require_stepup_new_location);
  const newStepupSensFile = inputSens !== undefined ? Boolean(inputSens) : Boolean(current.require_stepup_sensitive_file);
  const newEnforceGeoFence = inputGeo !== undefined ? Boolean(inputGeo) : Boolean(current.enforce_geo_fencing);

  await pool.query(
    `UPDATE organization_policies
     SET require_stepup_new_location = $1,
         require_stepup_sensitive_file = $2,
         enforce_geo_fencing = $3,
         updated_at = CURRENT_TIMESTAMP
     WHERE organization_id = $4`,
    [newStepupNewLoc, newStepupSensFile, newEnforceGeoFence, orgId]
  );

  const { allowedCountry, allowedState, allowedCity } = data;
  if (allowedCountry !== undefined || allowedState !== undefined || allowedCity !== undefined) {
    const firstLoc = current.allowedLocations[0] || { allowed_country: 'IN', allowed_state: 'ALL', allowed_city: 'ALL' };
    const country = (allowedCountry && allowedCountry.trim()) ? allowedCountry.trim().toUpperCase() : firstLoc.allowed_country;
    const state = (allowedState && allowedState.trim()) ? allowedState.trim() : firstLoc.allowed_state;
    const city = (allowedCity && allowedCity.trim()) ? allowedCity.trim() : firstLoc.allowed_city;

    await pool.query('DELETE FROM organization_geo_policies WHERE organization_id = $1', [orgId]);
    await pool.query(
      `INSERT INTO organization_geo_policies (organization_id, allowed_country, allowed_state, allowed_city)
       VALUES ($1, $2, $3, $4)`,
      [orgId, country, state, city]
    );
  }

  // Reload fresh policy directly from database to return actual persisted values
  return await getOrganizationPolicy(orgId);
}

async function addGeoPolicyLocation(orgId, { allowedCountry, allowedState, allowedCity }) {
  const country = allowedCountry ? allowedCountry.trim().toUpperCase() : 'IN';
  const state = allowedState ? allowedState.trim() : 'ALL';
  const city = allowedCity ? allowedCity.trim() : 'ALL';

  const res = await pool.query(
    `INSERT INTO organization_geo_policies (organization_id, allowed_country, allowed_state, allowed_city)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (organization_id, allowed_country, allowed_state, allowed_city) DO UPDATE SET created_at = CURRENT_TIMESTAMP
     RETURNING id, allowed_country, allowed_state, allowed_city, created_at`,
    [orgId, country, state, city]
  );
  return res.rows[0];
}

async function removeGeoPolicyLocation(orgId, geoPolicyId) {
  await pool.query(
    'DELETE FROM organization_geo_policies WHERE id = $1 AND organization_id = $2',
    [geoPolicyId, orgId]
  );
}

function evaluateGeoPolicy(policyWithGeo, location) {
  if (!policyWithGeo || !location) {
    return { isViolation: false, allowed: true };
  }

  const allowedLocations = policyWithGeo.allowedLocations || [];
  if (allowedLocations.length === 0) {
    return { isViolation: false, allowed: true };
  }

  let matched = false;

  for (const rule of allowedLocations) {
    const countryMatch = rule.allowed_country === 'ALL' || location.country === rule.allowed_country;
    const stateMatch = rule.allowed_state === 'ALL' || location.state === rule.allowed_state;
    const cityMatch = rule.allowed_city === 'ALL' || location.city === rule.allowed_city;

    if (countryMatch && stateMatch && cityMatch) {
      matched = true;
      break;
    }
  }

  if (!matched) {
    return {
      isViolation: true,
      allowed: false,
      enforceGeoFencing: Boolean(policyWithGeo.enforce_geo_fencing),
      reason: `Access location "${location.city}, ${location.state}, ${location.country}" does not match any allowed organization geographic policies.`,
    };
  }

  return { isViolation: false, allowed: true };
}

module.exports = {
  getOrganizationPolicy,
  updateOrganizationPolicy,
  addGeoPolicyLocation,
  removeGeoPolicyLocation,
  evaluateGeoPolicy,
};
