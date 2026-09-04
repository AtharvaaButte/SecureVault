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

    const { fileId: clientFileId, originalName, originalSize, iv, authTag, algorithm, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, senderPublicKey, dataClassification, sensitivityLevel } = req.body;

    if (!originalName || !iv || !authTag) {
      return res.status(400).json({ message: 'Missing required encryption metadata (originalName, iv, authTag).' });
    }

    const ownerId = req.user.userId;
    const fileId = (clientFileId && typeof clientFileId === 'string' && clientFileId.trim().length > 0)
      ? clientFileId.trim()
      : crypto.randomUUID();
    const storageKey = `files/${fileId}/encrypted`;

    let rawClass = String(dataClassification || sensitivityLevel || 'INTERNAL').toUpperCase();
    if (rawClass === 'NORMAL') rawClass = 'INTERNAL';
    if (rawClass === 'SENSITIVE') rawClass = 'CONFIDENTIAL';
    if (rawClass === 'HIGHLY_SENSITIVE') rawClass = 'HIGHLY_CONFIDENTIAL';

    const normalizedClassification = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY_CONFIDENTIAL'].includes(rawClass)
      ? rawClass
      : 'INTERNAL';

    // 1. Upload ciphertext Buffer to B2 bucket
    await uploadToB2(storageKey, req.file.buffer, 'application/octet-stream');

    // 2. Insert metadata record into PostgreSQL files table
    const result = await pool.query(
      `INSERT INTO files 
        (id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, data_classification) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
       RETURNING id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, data_classification, created_at`,
      [
        fileId,
        ownerId,
        originalName,
        parseInt(originalSize || req.file.size, 10),
        storageKey,
        algorithm || 'AES-256-GCM',
        iv,
        authTag,
        normalizedClassification,
      ]
    );

    const savedFile = result.rows[0];

    // 3. If owner DEK wrapping metadata is provided, insert record into file_keys table (Owner has FULL access_level)
    if (wrappedDek && wrapSalt && wrapIv && wrapAuthTag && senderPublicKey) {
      await pool.query(
        `INSERT INTO file_keys 
          (file_id, user_id, sender_public_key, wrapped_dek, wrap_salt, wrap_iv, wrap_auth_tag, access_level)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (file_id, user_id) DO UPDATE SET
           sender_public_key = EXCLUDED.sender_public_key,
           wrapped_dek = EXCLUDED.wrapped_dek,
           wrap_salt = EXCLUDED.wrap_salt,
           wrap_iv = EXCLUDED.wrap_iv,
           wrap_auth_tag = EXCLUDED.wrap_auth_tag,
           access_level = 'FULL',
           created_at = CURRENT_TIMESTAMP`,
        [fileId, ownerId, senderPublicKey, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, 'FULL']
      );
    }

    // Audit Event Recording (resource_type: FILE)
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: ownerId,
      eventType: 'UPLOAD',
      action: 'ALLOW',
      resourceType: 'FILE',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
    });

    res.status(201).json({
      message: 'File ciphertext uploaded successfully to B2.',
      file: {
        id: savedFile.id,
        originalName: savedFile.original_name,
        originalSize: savedFile.original_size,
        storageKey: savedFile.storage_key,
        dataClassification: savedFile.data_classification,
        sensitivityLevel: savedFile.data_classification,
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
      `SELECT id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, data_classification, created_at 
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
      dataClassification: row.data_classification,
      sensitivityLevel: row.data_classification,
      createdAt: row.created_at,
    }));

    res.json({ files });
  } catch (error) {
    console.error('[File Listing Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file list.' });
  }
});

// GET /api/files/shared - Get files shared with current user (Requires FILE_READ permission)
router.get('/shared', verifyToken, requirePermission('FILE_READ'), async (req, res) => {
  try {
    const currentUserId = req.user.userId;

    const result = await pool.query(
      `SELECT f.id, f.original_name, f.original_size, f.storage_key, f.encryption_algorithm, f.iv, f.auth_tag, f.data_classification, f.created_at,
              fk.sender_public_key, fk.wrapped_dek, fk.wrap_salt, fk.wrap_iv, fk.wrap_auth_tag, fk.access_level,
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
      dataClassification: row.data_classification,
      sensitivityLevel: row.data_classification,
      accessLevel: row.access_level || 'READ',
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

// GET /api/files/:id/shares - Get list of users a file is shared with (Requires FILE_REVOKE & Access)
router.get('/:id/shares', verifyToken, requireFileAccess('REVOKE'), async (req, res) => {
  try {
    const fileId = req.params.id;
    const currentUserId = req.user.userId;

    const result = await pool.query(
      `SELECT fk.user_id, u.email, fk.access_level, fk.created_at
       FROM file_keys fk
       JOIN users u ON fk.user_id = u.id
       WHERE fk.file_id = $1 AND fk.user_id != $2
       ORDER BY fk.created_at DESC`,
      [fileId, currentUserId]
    );

    const shares = result.rows.map(row => ({
      userId: row.user_id,
      email: row.email,
      accessLevel: row.access_level || 'READ',
      createdAt: row.created_at,
    }));

    res.json({ shares });
  } catch (error) {
    console.error('[Get Shares Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file share permissions.' });
  }
});

// POST /api/files/:id/share - Share file with recipient user & enforce file_restrictions
router.post('/:id/share', verifyToken, requireFileAccess('SHARE'), async (req, res) => {
  try {
    const fileId = req.params.id;
    const { recipientUserId, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, senderPublicKey, accessLevel } = req.body;

    if (!recipientUserId || !wrappedDek || !wrapSalt || !wrapIv || !wrapAuthTag || !senderPublicKey) {
      return res.status(400).json({ message: 'Missing required sharing fields.' });
    }

    const normalizedAccessLevel = (accessLevel === 'FULL') ? 'FULL' : 'READ';

    // 1. Verify recipient exists and check organization boundary + fetch X25519 public_key from user_keys
    const recipientResult = await pool.query(
      `SELECT u.id, u.email, u.organization_id, uk.public_key 
       FROM users u
       LEFT JOIN user_keys uk ON u.id = uk.user_id
       WHERE u.id = $1`,
      [recipientUserId]
    );

    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Recipient user not found.' });
    }

    const recipient = recipientResult.rows[0];

    // ORGANIZATION BOUNDARY CHECK
    if (recipient.organization_id !== req.user.orgId) {
      return res.status(403).json({ message: 'Access denied. Cross-organization file sharing is strictly prohibited.' });
    }

    if (!recipient.public_key) {
      return res.status(400).json({ message: 'Recipient does not have a registered cryptographic public key in user_keys.' });
    }

    // 2. Upsert wrapped DEK into file_keys table
    await pool.query(
      `INSERT INTO file_keys 
        (file_id, user_id, sender_public_key, wrapped_dek, wrap_salt, wrap_iv, wrap_auth_tag, access_level)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (file_id, user_id) DO UPDATE SET
         sender_public_key = EXCLUDED.sender_public_key,
         wrapped_dek = EXCLUDED.wrapped_dek,
         wrap_salt = EXCLUDED.wrap_salt,
         wrap_iv = EXCLUDED.wrap_iv,
         wrap_auth_tag = EXCLUDED.wrap_auth_tag,
         access_level = EXCLUDED.access_level,
         created_at = CURRENT_TIMESTAMP`,
      [fileId, recipientUserId, senderPublicKey, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, normalizedAccessLevel]
    );

    // 3. Update file_restrictions table (Item 3: File-level permission restrictions)
    if (normalizedAccessLevel === 'READ') {
      const blockedOps = ['FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE'];
      for (const op of blockedOps) {
        await pool.query(
          `INSERT INTO file_restrictions (file_id, user_id, blocked_operation)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [fileId, recipientUserId, op]
        );
      }
    } else {
      await pool.query(
        `DELETE FROM file_restrictions WHERE file_id = $1 AND user_id = $2`,
        [fileId, recipientUserId]
      );
    }

    // Audit Event Recording (resource_type: FILE)
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: req.user.userId,
      eventType: 'SHARE',
      action: 'ALLOW',
      resourceType: 'FILE',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
    });

    res.status(201).json({
      message: `File shared successfully with recipient (${normalizedAccessLevel} access level).`,
      fileId,
      recipientUserId,
      accessLevel: normalizedAccessLevel,
    });
  } catch (error) {
    console.error('[File Sharing Error]:', error.message);
    res.status(500).json({ message: 'Failed to share file.' });
  }
});

// DELETE /api/files/:id/share/:recipientUserId - Revoke a user's share permission (Requires FILE_REVOKE & Access)
router.delete('/:id/share/:recipientUserId', verifyToken, requireFileAccess('REVOKE'), async (req, res) => {
  try {
    const fileId = req.params.id;
    const recipientUserId = req.params.recipientUserId;

    // Delete file_keys and file_restrictions records for recipient
    const deleteResult = await pool.query(
      'DELETE FROM file_keys WHERE file_id = $1 AND user_id = $2 RETURNING id',
      [fileId, recipientUserId]
    );

    if (deleteResult.rows.length === 0) {
      return res.status(404).json({ message: 'Share record not found for this user.' });
    }

    await pool.query(
      'DELETE FROM file_restrictions WHERE file_id = $1 AND user_id = $2',
      [fileId, recipientUserId]
    );

    // Audit Event Recording (resource_type: FILE)
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: req.user.userId,
      eventType: 'REVOKE',
      action: 'ALLOW',
      resourceType: 'FILE',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
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

// GET /api/files/:id/download - Download encrypted ciphertext from B2 and metadata from PostgreSQL (Requires FILE_READ & Access)
router.get('/:id/download', verifyToken, requireFileAccess('READ'), async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const fileId = req.params.id;

    // Fetch full file metadata from PostgreSQL
    const fileResult = await pool.query(
      'SELECT id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, data_classification, created_at FROM files WHERE id = $1',
      [fileId]
    );

    const fileRecord = fileResult.rows[0];

    // Fetch file_keys record for requesting user
    const keyResult = await pool.query(
      'SELECT sender_public_key, wrapped_dek, wrap_salt, wrap_iv, wrap_auth_tag, access_level FROM file_keys WHERE file_id = $1 AND user_id = $2',
      [fileId, currentUserId]
    );

    // Download ciphertext Buffer from Backblaze B2
    const ciphertextBuffer = await getFromB2(fileRecord.storage_key);

    if (!ciphertextBuffer) {
      return res.status(404).json({ message: 'Ciphertext object not found in B2 storage.' });
    }

    // Audit Event Recording (resource_type: FILE)
    const location = geoService.extractLocation(req);
    await auditService.recordAuditEvent({
      organizationId: req.user.orgId,
      userId: currentUserId,
      eventType: 'DOWNLOAD',
      action: 'ALLOW',
      resourceType: 'FILE',
      resourceId: fileId,
      ipAddress: location.ip,
      locationLabel: location.regionLabel,
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
        dataClassification: fileRecord.data_classification,
        sensitivityLevel: fileRecord.data_classification,
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
        accessLevel: shareRecord.access_level || 'READ',
      };
    }

    res.json(responsePayload);
  } catch (error) {
    console.error('[File Download Error]:', error.message);
    res.status(500).json({ message: 'Failed to download file ciphertext.' });
  }
});

module.exports = router;
