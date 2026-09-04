const crypto = require('crypto');
const { pool } = require('../db');

/**
 * Simplified Tamper-Evident Security Event Auditing Service
 * Implements SHA-256 cryptographic hash chain verification.
 */

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function computeRecordHash(data, previousHash) {
  const canonicalString = [
    data.id || '',
    data.organizationId || '',
    data.userId || '',
    data.eventType || '',
    data.action || '',
    data.resourceType || 'FILE',
    data.resourceId || '',
    data.ipAddress || '',
    data.locationLabel || '',
    data.createdAt || '',
  ].join('|');

  return crypto
    .createHash('sha256')
    .update(`${canonicalString}|${previousHash}`)
    .digest('hex');
}

async function recordAuditEvent({
  organizationId,
  userId,
  eventType,
  action,
  resourceType = 'FILE',
  resourceId,
  ipAddress,
  locationLabel,
}) {
  try {
    let previousHash = GENESIS_HASH;
    const lastLogRes = await pool.query(
      `SELECT current_hash FROM audit_logs 
       WHERE organization_id = $1 
       ORDER BY created_at DESC, id DESC 
       LIMIT 1`,
      [organizationId]
    );

    if (lastLogRes.rows.length > 0 && lastLogRes.rows[0].current_hash) {
      previousHash = lastLogRes.rows[0].current_hash;
    }

    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    const recordData = {
      id,
      organizationId,
      userId,
      eventType,
      action,
      resourceType,
      resourceId,
      ipAddress,
      locationLabel,
      createdAt,
    };

    const currentHash = computeRecordHash(recordData, previousHash);

    await pool.query(
      `INSERT INTO audit_logs 
        (id, organization_id, user_id, event_type, action, resource_type, resource_id, ip_address, location_label, previous_hash, current_hash, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        id,
        organizationId,
        userId,
        eventType,
        action,
        resourceType,
        resourceId,
        ipAddress,
        locationLabel,
        previousHash,
        currentHash,
        createdAt,
      ]
    );

    return { id, currentHash, previousHash };
  } catch (error) {
    console.error('[Audit Service Record Error]:', error.message);
    return null;
  }
}

async function verifyAuditChain(organizationId) {
  try {
    const logsRes = await pool.query(
      `SELECT id, organization_id, user_id, event_type, action, resource_type, resource_id, ip_address, location_label, previous_hash, current_hash, created_at
       FROM audit_logs
       WHERE organization_id = $1
       ORDER BY created_at ASC, id ASC`,
      [organizationId]
    );

    const logs = logsRes.rows;
    if (logs.length === 0) {
      return { valid: true, totalLogs: 0, tamperedLogId: null, message: 'No audit logs found for organization.' };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < logs.length; i++) {
      const row = logs[i];
      
      // Check 1: Linkage integrity
      if (row.previous_hash !== expectedPrevHash) {
        return {
          valid: false,
          totalLogs: logs.length,
          tamperedLogId: row.id,
          error: `Audit chain linkage broken at log ID ${row.id} (index ${i}). Expected prev_hash ${expectedPrevHash.substring(0, 10)}..., found ${row.previous_hash.substring(0, 10)}...`,
        };
      }

      // Check 2: Content hash integrity
      const recordData = {
        id: row.id,
        organizationId: row.organization_id,
        userId: row.user_id,
        eventType: row.event_type,
        action: row.action,
        resourceType: row.resource_type || 'FILE',
        resourceId: row.resource_id,
        ipAddress: row.ip_address,
        locationLabel: row.location_label,
        createdAt: new Date(row.created_at).toISOString(),
      };

      const recomputedHash = computeRecordHash(recordData, row.previous_hash);

      if (recomputedHash !== row.current_hash) {
        return {
          valid: false,
          totalLogs: logs.length,
          tamperedLogId: row.id,
          error: `Tamper detected! Data or hash modified at log record ID ${row.id} (index ${i}). Expected ${recomputedHash.substring(0, 10)}..., found ${row.current_hash.substring(0, 10)}...`,
        };
      }

      expectedPrevHash = row.current_hash;
    }

    return {
      valid: true,
      totalLogs: logs.length,
      tamperedLogId: null,
      message: `Audit chain verified successfully! All ${logs.length} log hashes intact.`,
    };
  } catch (error) {
    console.error('[Audit Service Verification Error]:', error.message);
    return { valid: false, totalLogs: 0, error: error.message };
  }
}

async function getOrganizationAuditLogs(organizationId, limit = 50) {
  const result = await pool.query(
    `SELECT id, organization_id, user_id, event_type, action, resource_type, resource_id, ip_address, location_label, previous_hash, current_hash, created_at
     FROM audit_logs
     WHERE organization_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [organizationId, limit]
  );
  return result.rows;
}

module.exports = {
  recordAuditEvent,
  verifyAuditChain,
  getOrganizationAuditLogs,
};
