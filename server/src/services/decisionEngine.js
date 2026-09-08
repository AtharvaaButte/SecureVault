const argon2 = require('argon2');
const { pool } = require('../db');
const geoService = require('./geoService');
const policyService = require('./policyService');
const auditService = require('./auditService');

/**
 * Contextual Risk Decision Engine
 */

async function evaluateContextualDecision(userId, req, operationType, dataClassification = 'INTERNAL') {
  // 1. Location Context Extraction
  const location = geoService.extractLocation(req);

  // 2. Fetch User & Organization Security Policy
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
  const orgPolicyWithGeo = await policyService.getOrganizationPolicy(orgId);

  const riskFactors = [];
  let stepUpTriggered = false;
  let triggerReason = '';
  let decisionCode = 'ALLOW_KNOWN_CONTEXT';

  // 3. Evaluate Multi-Geographic Policy
  const geoEval = policyService.evaluateGeoPolicy(orgPolicyWithGeo, location);

  if (geoEval.isViolation) {
    riskFactors.push('GEO_POLICY_VIOLATION');
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

      // Audit Record DENY (resourceType: POLICY)
      await auditService.recordAuditEvent({
        organizationId: orgId,
        userId,
        eventType: 'GEO_VIOLATION',
        action: 'DENY',
        resourceType: 'POLICY',
        resourceId: req.params?.id || req.body?.fileId || null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
      });

      return denyDecision;
    } else {
      stepUpTriggered = true;
      triggerReason = `${geoEval.reason} Step-up re-authentication required.`;
      decisionCode = 'STEP_UP_GEO_POLICY_FLEXIBLE';
    }
  }

  // 4. Evaluate Resource Data Classification Policy (PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_CONFIDENTIAL)
  let rawClass = String(dataClassification || 'INTERNAL').toUpperCase();
  if (rawClass === 'NORMAL') rawClass = 'INTERNAL';
  if (rawClass === 'SENSITIVE') rawClass = 'CONFIDENTIAL';
  if (rawClass === 'HIGHLY_SENSITIVE') rawClass = 'HIGHLY_CONFIDENTIAL';

  const normalizedClassification = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY_CONFIDENTIAL'].includes(rawClass)
    ? rawClass
    : 'INTERNAL';

  const highImpactOps = ['FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE', 'USER_CREATE', 'USER_MANAGE', 'ROLE_MANAGE', 'ORG_MANAGE'];
  const isHighImpact = highImpactOps.includes(operationType);

  if (normalizedClassification === 'HIGHLY_CONFIDENTIAL') {
    riskFactors.push('HIGHLY_SENSITIVE_RESOURCE');
    if (operationType === 'FILE_READ' || isHighImpact) {
      stepUpTriggered = true;
      if (!triggerReason) triggerReason = `Step-up re-authentication required to access HIGHLY_CONFIDENTIAL file (${operationType}).`;
      if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_HIGHLY_SENSITIVE_RESOURCE';
    }
  } else if (normalizedClassification === 'CONFIDENTIAL') {
    riskFactors.push('SENSITIVE_RESOURCE');
    if (operationType === 'FILE_READ' || isHighImpact) {
      stepUpTriggered = true;
      if (!triggerReason) triggerReason = `Step-up re-authentication required for operation on CONFIDENTIAL file (${operationType}).`;
      if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_SENSITIVE_RESOURCE';
    }
  }

  // 5. Evaluate Location Context Shift from user_devices (Keyed by user_id)
  const deviceRes = await pool.query(
    'SELECT * FROM user_devices WHERE user_id = $1',
    [userId]
  );

  let isContextShift = false;

  if (deviceRes.rows.length > 0) {
    const existingContext = deviceRes.rows[0];
    const prevLocation = {
      country: existingContext.last_country,
      state: existingContext.last_state,
      city: existingContext.last_city,
    };
    if (geoService.isLocationShift(prevLocation, location) || existingContext.last_ip !== location.ip) {
      isContextShift = true;
      riskFactors.push('LOCATION_SHIFT_DETECTED');
    }
  }

  if (isContextShift && orgPolicyWithGeo.require_stepup_new_location) {
    stepUpTriggered = true;
    if (!triggerReason) triggerReason = `Location shift detected (${location.regionLabel}). Step-up re-authentication required.`;
    if (decisionCode === 'ALLOW_KNOWN_CONTEXT') decisionCode = 'STEP_UP_LOCATION_SHIFT';
  }

  // 6. Handle Step-Up Verification logic (Argon2id password verification preserved)
  if (stepUpTriggered) {
    const reauthPassword = req.headers['x-reauth-password'];
    if (reauthPassword) {
      const isValid = await argon2.verify(user.password_hash, reauthPassword);
      if (!isValid) {
        // Audit Invalid Step-up Attempt
        await auditService.recordAuditEvent({
          organizationId: orgId,
          userId,
          eventType: 'STEP_UP_FAILED',
          action: 'DENY',
          resourceType: 'AUTH',
          resourceId: req.params?.id || req.body?.fileId || null,
          ipAddress: location.ip,
          locationLabel: location.regionLabel,
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

      // Record location context update in user_devices
      await pool.query(
        `INSERT INTO user_devices (user_id, last_ip, last_country, last_state, last_city)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO UPDATE SET
           last_ip = EXCLUDED.last_ip,
           last_country = EXCLUDED.last_country,
           last_state = EXCLUDED.last_state,
           last_city = EXCLUDED.last_city,
           last_seen_at = CURRENT_TIMESTAMP`,
        [userId, location.ip, location.country, location.state, location.city]
      );

      // Audit Successful Step-up
      await auditService.recordAuditEvent({
        organizationId: orgId,
        userId,
        eventType: 'STEP_UP_SUCCESS',
        action: 'ALLOW',
        resourceType: 'AUTH',
        resourceId: req.params?.id || req.body?.fileId || null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
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
        eventType: 'STEP_UP_PROMPT',
        action: 'STEP_UP',
        resourceType: 'AUTH',
        resourceId: req.params?.id || req.body?.fileId || null,
        ipAddress: location.ip,
        locationLabel: location.regionLabel,
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

  // 7. Standard ALLOW under trusted context -> Record location context
  await pool.query(
    `INSERT INTO user_devices (user_id, last_ip, last_country, last_state, last_city)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id) DO UPDATE SET
       last_ip = EXCLUDED.last_ip,
       last_country = EXCLUDED.last_country,
       last_state = EXCLUDED.last_state,
       last_city = EXCLUDED.last_city,
       last_seen_at = CURRENT_TIMESTAMP`,
    [userId, location.ip, location.country, location.state, location.city]
  );

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
