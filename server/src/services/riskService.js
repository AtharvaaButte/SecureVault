const argon2 = require('argon2');
const { pool } = require('../db');
const geoService = require('./geoService');
const policyService = require('./policyService');

async function evaluateRisk(userId, req, operationType, sensitivityLevel = 'NORMAL') {
  const deviceId = req.headers['x-client-device-id'] || 'electron-default-device';
  const devicePlatform = req.headers['x-client-platform'] || 'Electron-Windows';
  const userAgent = req.headers['user-agent'] || 'SecureVault-Electron-Client';

  // 1. Extract location context (Cycle 10.3)
  const location = geoService.extractLocation(req);

  // 2. Fetch user's organization policy (Cycle 10.2)
  const userRes = await pool.query('SELECT organization_id, password_hash FROM users WHERE id = $1', [userId]);
  if (userRes.rows.length === 0) {
    return { allow: false, message: 'User account not found.' };
  }
  const orgId = userRes.rows[0].organization_id;
  const orgPolicy = await policyService.getOrganizationPolicy(orgId);

  // 3. Evaluate Geo Policy (Cycle 10.3)
  const geoEval = policyService.evaluateGeoPolicy(orgPolicy, location);

  let stepUpTriggered = false;
  let triggerReason = '';
  let hardDeny = false;
  let hardDenyReason = '';

  if (geoEval.isViolation) {
    if (geoEval.enforceGeoFencing) {
      hardDeny = true;
      hardDenyReason = geoEval.reason;
    } else {
      stepUpTriggered = true;
      triggerReason = `${geoEval.reason} Step-up re-authentication required.`;
    }
  }

  // 4. Sensitivity Level Policy Check (Phase 9D & Cycle 10.2)
  const normalizedSensitivity = ['NORMAL', 'SENSITIVE', 'HIGHLY_SENSITIVE'].includes(sensitivityLevel)
    ? sensitivityLevel
    : 'NORMAL';

  const highImpactOps = ['FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE', 'USER_CREATE', 'USER_MANAGE', 'ROLE_MANAGE', 'ORG_MANAGE'];
  const isHighImpact = highImpactOps.includes(operationType);

  if (normalizedSensitivity === 'HIGHLY_SENSITIVE') {
    if (operationType === 'FILE_READ' || isHighImpact) {
      stepUpTriggered = true;
      if (!triggerReason) triggerReason = `Step-up re-authentication required to access HIGHLY_SENSITIVE file (${operationType}).`;
    }
  } else if (normalizedSensitivity === 'SENSITIVE') {
    if (isHighImpact && orgPolicy.require_stepup_sensitive_file) {
      stepUpTriggered = true;
      if (!triggerReason) triggerReason = `Step-up re-authentication required for high-impact operation on SENSITIVE file (${operationType}).`;
    }
  }

  // 5. Fetch device history in user_devices (Phase 9C + Cycle 10.3 Location Shift)
  const deviceRes = await pool.query(
    'SELECT * FROM user_devices WHERE user_id = $1 AND device_id = $2',
    [userId, deviceId]
  );

  let isNewDevice = false;
  let isContextShift = false;
  let isTrusted = false;

  if (deviceRes.rows.length === 0) {
    isNewDevice = true;
    isTrusted = false;
  } else {
    const existingDevice = deviceRes.rows[0];
    isTrusted = Boolean(existingDevice.is_trusted);
    const prevLocation = {
      country: existingDevice.last_country,
      state: existingDevice.last_state,
      city: existingDevice.last_city,
    };
    if (geoService.isLocationShift(prevLocation, location) || existingDevice.last_ip !== location.ip) {
      isContextShift = true;
    }
  }

  if (isContextShift && orgPolicy.require_stepup_new_location) {
    stepUpTriggered = true;
    if (!triggerReason) triggerReason = `Location or network context shift detected (${location.regionLabel}). Step-up re-authentication required.`;
  }

  if (isHighImpact && (isNewDevice || !isTrusted)) {
    stepUpTriggered = true;
    if (!triggerReason) triggerReason = 'Step-up re-authentication required for sensitive operation from untrusted device.';
  }

  // FIRST: HARD DENY (Geo-Fencing Violation strictly blocks request, ignoring step-up password)
  if (hardDeny) {
    return {
      allow: false,
      stepUpRequired: false,
      message: hardDenyReason,
    };
  }

  // SECOND: STEP-UP RE-AUTHENTICATION REQUIRED
  if (stepUpTriggered) {
    const reauthPassword = req.headers['x-reauth-password'];
    if (reauthPassword) {
      const isValid = await argon2.verify(userRes.rows[0].password_hash, reauthPassword);
      if (!isValid) {
        return { allow: false, stepUpRequired: true, message: 'Invalid step-up re-authentication password.' };
      }

      // Mark device trusted & record new location in user_devices table
      await pool.query(
        `INSERT INTO user_devices 
          (user_id, device_id, device_platform, user_agent, last_ip, last_region, last_country, last_state, last_city, is_trusted)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
           device_platform = EXCLUDED.device_platform,
           user_agent = EXCLUDED.user_agent,
           last_ip = EXCLUDED.last_ip,
           last_region = EXCLUDED.last_region,
           last_country = EXCLUDED.last_country,
           last_state = EXCLUDED.last_state,
           last_city = EXCLUDED.last_city,
           is_trusted = true,
           last_seen_at = CURRENT_TIMESTAMP`,
        [userId, deviceId, devicePlatform, userAgent, location.ip, location.regionLabel, location.country, location.state, location.city]
      );

      return { allow: true, stepUpPassed: true };
    } else {
      return {
        allow: false,
        stepUpRequired: true,
        message: triggerReason,
      };
    }
  }

  // Standard operation under allowed policy -> Record location context
  if (isNewDevice) {
    await pool.query(
      `INSERT INTO user_devices 
        (user_id, device_id, device_platform, user_agent, last_ip, last_region, last_country, last_state, last_city, is_trusted)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
       ON CONFLICT (user_id, device_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip,
         last_region = EXCLUDED.last_region,
         last_country = EXCLUDED.last_country,
         last_state = EXCLUDED.last_state,
         last_city = EXCLUDED.last_city,
         last_seen_at = CURRENT_TIMESTAMP`,
      [userId, deviceId, devicePlatform, userAgent, location.ip, location.regionLabel, location.country, location.state, location.city]
    );
  } else {
    await pool.query(
      `UPDATE user_devices 
       SET last_ip = $1, last_region = $2, last_country = $3, last_state = $4, last_city = $5, last_seen_at = CURRENT_TIMESTAMP 
       WHERE user_id = $6 AND device_id = $7`,
      [location.ip, location.regionLabel, location.country, location.state, location.city, userId, deviceId]
    );
  }

  return { allow: true };
}

module.exports = {
  evaluateRisk,
};
