const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const { requirePermission, requireFileAccess } = require('../middleware/authorize');
const { uploadToB2, getFromB2 } = require('../storage/s3Client');
const auditService = require('../services/auditService');
const geoService = require('../services/geoService');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// POST /api/files/upload - Upload ciphertext to Backblaze B2 and store metadata in PostgreSQL (Requires FILE_UPLOAD permission)
router.post('/upload', verifyToken, requirePermission('FILE_UPLOAD'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ message: 'Ciphertext file payload is required.' });
    }

    const { fileId: clientFileId, originalName, originalSize, iv, authTag, algorithm, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, senderPublicKey, sensitivityLevel } = req.body;

    if (!originalName || !iv || !authTag) {
      return res.status(400).json({ message: 'Missing required encryption metadata (originalName, iv, authTag).' });
    }

    const ownerId = req.user.userId;
    const fileId = (clientFileId && typeof clientFileId === 'string' && clientFileId.trim().length > 0)
      ? clientFileId.trim()
      : crypto.randomUUID();
    const storageKey = `files/${fileId}/encrypted`;

    const normalizedSensitivity = ['NORMAL', 'SENSITIVE', 'HIGHLY_SENSITIVE'].includes(sensitivityLevel)
      ? sensitivityLevel
      : 'NORMAL';

    // 1. Upload ciphertext Buffer to B2 bucket
    await uploadToB2(storageKey, req.file.buffer, 'application/octet-stream');

    // 2. Insert metadata record into PostgreSQL files table
    const result = await pool.query(
      `INSERT INTO files 
        (id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, sensitivity_level) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
       RETURNING id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, sensitivity_level, created_at`,
      [
        fileId,
        ownerId,
        originalName,
        parseInt(originalSize || req.file.size, 10),
        storageKey,
        algorithm || 'AES-256-GCM',
        iv,
        authTag,
        normalizedSensitivity,
      ]
    );

    const savedFile = result.rows[0];

    // 3. If owner DEK wrapping metadata is provided, insert record into file_keys table for DEK recovery
    if (wrappedDek && wrapSalt && wrapIv && wrapAuthTag && senderPublicKey) {
      await pool.query(
        `INSERT INTO file_keys 
          (file_id, user_id, sender_public_key, wrapped_dek, wrap_salt, wrap_iv, wrap_auth_tag)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (file_id, user_id) DO UPDATE SET
           sender_public_key = EXCLUDED.sender_public_key,
           wrapped_dek = EXCLUDED.wrapped_dek,
           wrap_salt = EXCLUDED.wrap_salt,
           wrap_iv = EXCLUDED.wrap_iv,
           wrap_auth_tag = EXCLUDED.wrap_auth_tag,
           created_at = CURRENT_TIMESTAMP`,
        [fileId, ownerId, senderPublicKey, wrappedDek, wrapSalt, wrapIv, wrapAuthTag]
      );
    }

    // Audit Event Recording (Cycle 10.6)
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: ownerId,
      userEmail: req.user.email,
      eventType: 'UPLOAD',
      action: 'ALLOW',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
      deviceId: req.headers['x-client-device-id'] || 'electron-default-device',
      reason: `Uploaded file ${originalName} (Sensitivity: ${normalizedSensitivity}).`,
    });

    res.status(201).json({
      message: 'File ciphertext uploaded successfully to B2.',
      file: {
        id: savedFile.id,
        originalName: savedFile.original_name,
        originalSize: savedFile.original_size,
        storageKey: savedFile.storage_key,
        sensitivityLevel: savedFile.sensitivity_level,
        createdAt: savedFile.created_at,
      },
    });
  } catch (error) {
    console.error('[File Upload Error]:', error.message);
    res.status(500).json({ message: 'Failed to upload file ciphertext.' });
  }
});

// GET /api/files - Get current authenticated user's owned file listing (Requires FILE_READ permission)
router.get('/', verifyToken, requirePermission('FILE_READ'), async (req, res) => {
  try {
    const ownerId = req.user.userId;

    const result = await pool.query(
      `SELECT id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, sensitivity_level, created_at 
       FROM files 
       WHERE owner_id = $1 
       ORDER BY created_at DESC`,
      [ownerId]
    );

    const files = result.rows.map(row => ({
      id: row.id,
      originalName: row.original_name,
      originalSize: parseInt(row.original_size, 10),
      storageKey: row.storage_key,
      algorithm: row.encryption_algorithm,
      iv: row.iv,
      authTag: row.auth_tag,
      sensitivityLevel: row.sensitivity_level,
      createdAt: row.created_at,
    }));

    res.json({ files });
  } catch (error) {
    console.error('[File Listing Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file list.' });
  }
});

// GET /api/files/shared - Get files shared with the current authenticated user (Requires FILE_READ permission)
router.get('/shared', verifyToken, requirePermission('FILE_READ'), async (req, res) => {
  try {
    const currentUserId = req.user.userId;

    const result = await pool.query(
      `SELECT f.id, f.original_name, f.original_size, f.storage_key, f.encryption_algorithm, f.iv, f.auth_tag, f.sensitivity_level, f.created_at,
              fk.sender_public_key, fk.wrapped_dek, fk.wrap_salt, fk.wrap_iv, fk.wrap_auth_tag,
              u.email AS owner_email
       FROM files f
       INNER JOIN file_keys fk ON f.id = fk.file_id
       INNER JOIN users u ON f.owner_id = u.id
       WHERE fk.user_id = $1 AND f.owner_id != $1
       ORDER BY fk.created_at DESC`,
      [currentUserId]
    );

    const sharedFiles = result.rows.map(row => ({
      id: row.id,
      originalName: row.original_name,
      originalSize: parseInt(row.original_size, 10),
      storageKey: row.storage_key,
      algorithm: row.encryption_algorithm,
      iv: row.iv,
      authTag: row.auth_tag,
      sensitivityLevel: row.sensitivity_level,
      createdAt: row.created_at,
      ownerEmail: row.owner_email,
      wrapping: {
        senderPublicKey: row.sender_public_key,
        wrappedDek: row.wrapped_dek,
        wrapSalt: row.wrap_salt,
        wrapIv: row.wrap_iv,
        wrapAuthTag: row.wrap_auth_tag,
      },
    }));

    res.json({ sharedFiles });
  } catch (error) {
    console.error('[Shared Files Listing Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve shared files.' });
  }
});

// GET /api/files/:id/shares - Get list of users a file is shared with (Requires FILE_REVOKE & Owner Access)
router.get('/:id/shares', verifyToken, requireFileAccess('REVOKE'), async (req, res) => {
  try {
    const fileId = req.params.id;
    const currentUserId = req.user.userId;

    const result = await pool.query(
      `SELECT fk.user_id, u.email, fk.created_at
       FROM file_keys fk
       JOIN users u ON fk.user_id = u.id
       WHERE fk.file_id = $1 AND fk.user_id != $2
       ORDER BY fk.created_at DESC`,
      [fileId, currentUserId]
    );

    const shares = result.rows.map(row => ({
      userId: row.user_id,
      email: row.email,
      createdAt: row.created_at,
    }));

    res.json({ shares });
  } catch (error) {
    console.error('[Get Shares Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file share permissions.' });
  }
});

// POST /api/files/:id/share - Share file with a recipient user (Requires FILE_SHARE & Owner Access)
router.post('/:id/share', verifyToken, requireFileAccess('SHARE'), async (req, res) => {
  try {
    const fileId = req.params.id;
    const { recipientUserId, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, senderPublicKey } = req.body;

    if (!recipientUserId || !wrappedDek || !wrapSalt || !wrapIv || !wrapAuthTag || !senderPublicKey) {
      return res.status(400).json({ message: 'Missing required sharing fields.' });
    }

    // 1. Verify recipient exists and check organization boundary
    const recipientResult = await pool.query(
      'SELECT id, email, organization_id, public_key FROM users WHERE id = $1',
      [recipientUserId]
    );

    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Recipient user not found.' });
    }

    const recipient = recipientResult.rows[0];

    // ORGANIZATION BOUNDARY CHECK: Owner and recipient MUST belong to the same organization
    if (recipient.organization_id !== req.user.orgId) {
      return res.status(403).json({ message: 'Access denied. Cross-organization file sharing is strictly prohibited.' });
    }

    if (!recipient.public_key) {
      return res.status(400).json({ message: 'Recipient does not have a registered cryptographic public key.' });
    }

    // 2. Upsert wrapped DEK into file_keys table
    await pool.query(
      `INSERT INTO file_keys 
        (file_id, user_id, sender_public_key, wrapped_dek, wrap_salt, wrap_iv, wrap_auth_tag)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (file_id, user_id) DO UPDATE SET
         sender_public_key = EXCLUDED.sender_public_key,
         wrapped_dek = EXCLUDED.wrapped_dek,
         wrap_salt = EXCLUDED.wrap_salt,
         wrap_iv = EXCLUDED.wrap_iv,
         wrap_auth_tag = EXCLUDED.wrap_auth_tag,
         created_at = CURRENT_TIMESTAMP`,
      [fileId, recipientUserId, senderPublicKey, wrappedDek, wrapSalt, wrapIv, wrapAuthTag]
    );

    // Audit Event Recording
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: req.user.userId,
      userEmail: req.user.email,
      eventType: 'SHARE',
      action: 'ALLOW',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
      deviceId: req.headers['x-client-device-id'] || 'electron-default-device',
      reason: `Shared file ${fileId} with recipient ${recipient.email}.`,
    });

    res.status(201).json({
      message: 'File shared successfully with recipient.',
      fileId,
      recipientUserId,
    });
  } catch (error) {
    console.error('[File Sharing Error]:', error.message);
    res.status(500).json({ message: 'Failed to share file.' });
  }
});

// DELETE /api/files/:id/share/:recipientUserId - Revoke a user's share permission (Requires FILE_REVOKE & Owner Access)
router.delete('/:id/share/:recipientUserId', verifyToken, requireFileAccess('REVOKE'), async (req, res) => {
  try {
    const fileId = req.params.id;
    const recipientUserId = req.params.recipientUserId;

    // Delete file_keys record for recipient
    const deleteResult = await pool.query(
      'DELETE FROM file_keys WHERE file_id = $1 AND user_id = $2 RETURNING id',
      [fileId, recipientUserId]
    );

    if (deleteResult.rows.length === 0) {
      return res.status(404).json({ message: 'Share record not found for this user.' });
    }

    // Audit Event Recording
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: req.user.userId,
      userEmail: req.user.email,
      eventType: 'REVOKE',
      action: 'ALLOW',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
      deviceId: req.headers['x-client-device-id'] || 'electron-default-device',
      reason: `Revoked share access for user ${recipientUserId} on file ${fileId}.`,
    });

    res.json({
      message: 'Share permission revoked successfully.',
      fileId,
      recipientUserId,
    });
  } catch (error) {
    console.error('[Revoke Share Error]:', error.message);
    res.status(500).json({ message: 'Failed to revoke share permission.' });
  }
});

// GET /api/files/:id/download - Download encrypted ciphertext from B2 and metadata from PostgreSQL (Requires FILE_READ & Resource Access)
router.get('/:id/download', verifyToken, requireFileAccess('READ'), async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const fileId = req.params.id;

    // Fetch full file metadata from PostgreSQL
    const fileResult = await pool.query(
      'SELECT id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, sensitivity_level, created_at FROM files WHERE id = $1',
      [fileId]
    );

    const fileRecord = fileResult.rows[0];

    // Fetch file_keys record for requesting user (owner or recipient)
    const keyResult = await pool.query(
      'SELECT sender_public_key, wrapped_dek, wrap_salt, wrap_iv, wrap_auth_tag FROM file_keys WHERE file_id = $1 AND user_id = $2',
      [fileId, currentUserId]
    );

    // Download ciphertext Buffer from Backblaze B2
    const ciphertextBuffer = await getFromB2(fileRecord.storage_key);

    if (!ciphertextBuffer) {
      return res.status(404).json({ message: 'Ciphertext object not found in B2 storage.' });
    }

    // Audit Event Recording
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: currentUserId,
      userEmail: req.user.email,
      eventType: 'DOWNLOAD',
      action: 'ALLOW',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
      deviceId: req.headers['x-client-device-id'] || 'electron-default-device',
      reason: `Downloaded file ${fileRecord.original_name} (Sensitivity: ${fileRecord.sensitivity_level}).`,
    });

    // Return base64 ciphertext and encryption metadata
    const responsePayload = {
      ciphertext: ciphertextBuffer.toString('base64'),
      metadata: {
        id: fileRecord.id,
        ownerId: fileRecord.owner_id,
        originalName: fileRecord.original_name,
        originalSize: parseInt(fileRecord.original_size, 10),
        algorithm: fileRecord.encryption_algorithm,
        iv: fileRecord.iv,
        authTag: fileRecord.auth_tag,
        sensitivityLevel: fileRecord.sensitivity_level,
        createdAt: fileRecord.created_at,
      },
    };

    if (keyResult.rows.length > 0) {
      const shareRecord = keyResult.rows[0];
      responsePayload.wrapping = {
        senderPublicKey: shareRecord.sender_public_key,
        wrappedDek: shareRecord.wrapped_dek,
        wrapSalt: shareRecord.wrap_salt,
        wrapIv: shareRecord.wrap_iv,
        wrapAuthTag: shareRecord.wrap_auth_tag,
      };
    }

    res.json(responsePayload);
  } catch (error) {
    console.error('[File Download Error]:', error.message);
    res.status(500).json({ message: 'Failed to download file ciphertext.' });
  }
});

module.exports = router;
