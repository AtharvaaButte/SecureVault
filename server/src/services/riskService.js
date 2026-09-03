const argon2 = require('argon2');
const { pool } = require('../db');

function determineRegion(ip, headerRegion) {
  if (headerRegion && typeof headerRegion === 'string' && headerRegion.trim().length > 0) {
    return headerRegion.trim();
  }
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.')) {
    return 'LOCAL/DEV';
  }
  return 'EXTERNAL/REGION';
}

async function evaluateRisk(userId, req, operationType, sensitivityLevel = 'NORMAL') {
  const deviceId = req.headers['x-client-device-id'] || 'electron-default-device';
  const devicePlatform = req.headers['x-client-platform'] || 'Electron-Windows';
  const userAgent = req.headers['user-agent'] || 'SecureVault-Electron-Client';
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const region = determineRegion(ip, req.headers['x-client-region']);

  const highImpactOps = ['FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE', 'USER_CREATE', 'USER_MANAGE'];
  const isHighImpact = highImpactOps.includes(operationType);

  // Phase 9D Sensitivity Policy Evaluation
  let stepUpTriggered = false;
  let triggerReason = '';

  const normalizedSensitivity = ['NORMAL', 'SENSITIVE', 'HIGHLY_SENSITIVE'].includes(sensitivityLevel)
    ? sensitivityLevel
    : 'NORMAL';

  if (normalizedSensitivity === 'HIGHLY_SENSITIVE') {
    // Highly Sensitive files require step-up re-authentication for READ, SHARE, REVOKE, DELETE
    if (operationType === 'FILE_READ' || isHighImpact) {
      stepUpTriggered = true;
      triggerReason = `Step-up re-authentication required to access HIGHLY_SENSITIVE file (${operationType}).`;
    }
  } else if (normalizedSensitivity === 'SENSITIVE') {
    // Sensitive files require step-up re-authentication for high-impact operations (SHARE, REVOKE, DELETE)
    if (isHighImpact) {
      stepUpTriggered = true;
      triggerReason = `Step-up re-authentication required for high-impact operation on SENSITIVE file (${operationType}).`;
    }
  }

  // Fetch device record in PostgreSQL
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
    if (existingDevice.last_ip !== ip || existingDevice.last_region !== region) {
      isContextShift = true;
    }
  }

  // Phase 9C Context Risk Check Trigger
  if (isHighImpact && (isNewDevice || !isTrusted || isContextShift)) {
    stepUpTriggered = true;
    if (!triggerReason) {
      triggerReason = 'Step-up re-authentication required for sensitive operation from new device or unusual network context.';
    }
  }

  // If Step-Up Re-Authentication is required:
  if (stepUpTriggered) {
    const reauthPassword = req.headers['x-reauth-password'];

    if (reauthPassword) {
      // Fetch user password hash to verify step-up re-authentication
      const userRes = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
      if (userRes.rows.length === 0) {
        return { allow: false, stepUpRequired: true, message: 'User account not found.' };
      }

      const isValid = await argon2.verify(userRes.rows[0].password_hash, reauthPassword);
      if (!isValid) {
        return { allow: false, stepUpRequired: true, message: 'Invalid step-up re-authentication password.' };
      }

      // Step-Up Password Verified -> Trust device and record context in user_devices table
      await pool.query(
        `INSERT INTO user_devices 
          (user_id, device_id, device_platform, user_agent, last_ip, last_region, is_trusted)
         VALUES ($1, $2, $3, $4, $5, $6, true)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
           device_platform = EXCLUDED.device_platform,
           user_agent = EXCLUDED.user_agent,
           last_ip = EXCLUDED.last_ip,
           last_region = EXCLUDED.last_region,
           is_trusted = true,
           last_seen_at = CURRENT_TIMESTAMP`,
        [userId, deviceId, devicePlatform, userAgent, ip, region]
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

  // Standard operation under NORMAL policy -> Record/track device
  if (isNewDevice) {
    await pool.query(
      `INSERT INTO user_devices 
        (user_id, device_id, device_platform, user_agent, last_ip, last_region, is_trusted)
       VALUES ($1, $2, $3, $4, $5, $6, false)
       ON CONFLICT (user_id, device_id) DO UPDATE SET
         last_ip = EXCLUDED.last_ip,
         last_region = EXCLUDED.last_region,
         last_seen_at = CURRENT_TIMESTAMP`,
      [userId, deviceId, devicePlatform, userAgent, ip, region]
    );
  } else {
    await pool.query(
      `UPDATE user_devices 
       SET last_ip = $1, last_region = $2, last_seen_at = CURRENT_TIMESTAMP 
       WHERE user_id = $3 AND device_id = $4`,
      [ip, region, userId, deviceId]
    );
  }

  return { allow: true };
}

module.exports = {
  evaluateRisk,
};
