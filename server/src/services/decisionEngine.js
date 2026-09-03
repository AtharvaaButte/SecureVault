const argon2 = require('argon2');
const { pool } = require('../db');
const geoService = require('./geoService');
const policyService = require('./policyService');
const auditService = require('./auditService');

/**
 * Cycle 10.4 Explainable Contextual Risk Decision Engine
 */

async function evaluateContextualDecision(userId, req, operationType, sensitivityLevel = 'NORMAL') {
  const deviceId = req.headers['x-client-device-id'] || 'electron-default-device';
  const devicePlatform = req.headers['x-client-platform'] || 'Electron-Windows';
  const userAgent = req.headers['user-agent'] || 'SecureVault-Electron-Client';

  // 1. Location Context Extraction (Cycle 10.3)
  const location = geoService.extractLocation(req);

  // 2. Fetch User & Organization Security Policy (Cycle 10.2)
  const userRes = await pool.query('SELECT organization_id, email, password_hash FROM users WHERE id = $1', [userId]);
  if (userRes.rows.length === 0) {
    return {
      allow: false,
      action: 'DENY',
      decisionCode: 'DENY_USER_NOT_FOUND',
      message: 'User account not found.',
      reason: 'User account not found.',
      riskFactors: ['INVALID_USER'],
    };
  }

  const user = userRes.rows[0];
  const orgId = user.organization_id;
  const orgPolicy = await policyService.getOrganizationPolicy(orgId);

  const riskFactors = [];
  let stepUpTriggered = false;
  let triggerReason = '';
  let decisionCode = 'ALLOW_KNOWN_CONTEXT';

  // 3. Evaluate Geographic Policy
  const geoEval = policyService.evaluateGeoPolicy(orgPolicy, location);

  if (geoEval.isViolation) {
    riskFactors.push(`GEO_POLICY_VIOLATION_${geoEval.violationScope}`);
    if (geoEval.enforceGeoFencing) {
      const denyDecision = {
        allow: false,
        action: 'DENY',
        stepUpRequired: false,
        decisionCode: 'DENY_GEO_FENCE_VIOLATION',
        message: geoEval.reason,
        reason: geoEval.reason,
        riskFactors,
      };

      // Audit Record DENY
      await auditService.recordAuditEvent({
        organizationId: orgId,
        userId,
        userEmail: user.email,
        eventType: 'GEO_VIOLATION',
        action: 'DENY',
        resourceId: req.params?.id || null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
        deviceId,
        reason: geoEval.reason,
      });

      return denyDecision;
    } else {
      stepUpTriggered = true;
      triggerReason = `${geoEval.reason} Step-up re-authentication required.`;
      decisionCode = 'STEP_UP_GEO_POLICY_FLEXIBLE';
    }
  }

  // 4. Evaluate Resource Sensitivity Level Policy
  const normalizedSensitivity = ['NORMAL', 'SENSITIVE', 'HIGHLY_SENSITIVE'].includes(sensitivityLevel)
    ? sensitivityLevel
    : 'NORMAL';

  const highImpactOps = ['FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE', 'USER_CREATE', 'USER_MANAGE', 'ROLE_MANAGE', 'ORG_MANAGE'];
  const isHighImpact = highImpactOps.includes(operationType);

  if (normalizedSensitivity === 'HIGHLY_SENSITIVE') {
    riskFactors.push('HIGHLY_SENSITIVE_RESOURCE');
    if (operationType === 'FILE_READ' || isHighImpact) {
      stepUpTriggered = true;
      if (!triggerReason) triggerReason = `Step-up re-authentication required to access HIGHLY_SENSITIVE file (${operationType}).`;
      if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_HIGHLY_SENSITIVE_RESOURCE';
    }
  } else if (normalizedSensitivity === 'SENSITIVE') {
    riskFactors.push('SENSITIVE_RESOURCE');
    if (isHighImpact && orgPolicy.require_stepup_sensitive_file) {
      stepUpTriggered = true;
      if (!triggerReason) triggerReason = `Step-up re-authentication required for high-impact operation on SENSITIVE file (${operationType}).`;
      if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_SENSITIVE_RESOURCE';
    }
  }

  // 5. Evaluate Device & Location Context Shift
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
    riskFactors.push('NEW_UNTRUSTED_DEVICE');
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
      riskFactors.push('LOCATION_SHIFT_DETECTED');
    }
  }

  if (isContextShift && orgPolicy.require_stepup_new_location) {
    stepUpTriggered = true;
    if (!triggerReason) triggerReason = `Location shift detected (${location.regionLabel}). Step-up re-authentication required.`;
    if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_LOCATION_SHIFT';
  }

  if (isHighImpact && (isNewDevice || !isTrusted)) {
    stepUpTriggered = true;
    if (!triggerReason) triggerReason = 'Step-up re-authentication required for high-impact operation from untrusted device.';
    if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_UNTRUSTED_DEVICE';
  }

  // 6. Handle Step-Up Verification logic
  if (stepUpTriggered) {
    const reauthPassword = req.headers['x-reauth-password'];
    if (reauthPassword) {
      const isValid = await argon2.verify(user.password_hash, reauthPassword);
      if (!isValid) {
        // Audit Invalid Step-up Attempt
        await auditService.recordAuditEvent({
          organizationId: orgId,
          userId,
          userEmail: user.email,
          eventType: 'STEP_UP_FAILED',
          action: 'DENY',
          resourceId: req.params?.id || null,
          ipAddress: location.ip,
          locationLabel: location.regionLabel,
          deviceId,
          reason: 'Invalid step-up re-authentication password.',
        });

        return {
          allow: false,
          action: 'DENY',
          stepUpRequired: true,
          decisionCode: 'DENY_INVALID_STEP_UP_PASSWORD',
          message: 'Invalid step-up re-authentication password.',
          reason: 'Invalid step-up re-authentication password.',
          riskFactors,
        };
      }

      // Record trusted device & location update
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

      // Audit Successful Step-up
      await auditService.recordAuditEvent({
        organizationId: orgId,
        userId,
        userEmail: user.email,
        eventType: 'STEP_UP_SUCCESS',
        action: 'ALLOW',
        resourceId: req.params?.id || null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
        deviceId,
        reason: `Step-up re-authentication verified for operation ${operationType}.`,
      });

      return {
        allow: true,
        action: 'ALLOW',
        stepUpPassed: true,
        decisionCode: 'ALLOW_STEP_UP_VERIFIED',
        reason: 'Step-up re-authentication verified successfully.',
        riskFactors,
      };
    } else {
      // Audit Step-up Prompt
      await auditService.recordAuditEvent({
        organizationId: orgId,
        userId,
        userEmail: user.email,
        eventType: 'STEP_UP_PROMPT',
        action: 'STEP_UP',
        resourceId: req.params?.id || null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
        deviceId,
        reason: triggerReason,
      });

      return {
        allow: false,
        action: 'STEP_UP',
        stepUpRequired: true,
        decisionCode,
        message: triggerReason,
        reason: triggerReason,
        riskFactors,
      };
    }
  }

  // 7. Standard ALLOW under trusted context
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

  return {
    allow: true,
    action: 'ALLOW',
    decisionCode: 'ALLOW_KNOWN_CONTEXT',
    reason: 'Request context verified under organization policy.',
    riskFactors,
  };
}

module.exports = {
  evaluateContextualDecision,
};
