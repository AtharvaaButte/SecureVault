const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');
const { uploadToB2, getFromB2 } = require('../storage/s3Client');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// POST /api/files/upload - Upload ciphertext to Backblaze B2 and store metadata in PostgreSQL
router.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ message: 'Ciphertext file payload is required.' });
    }

    const { fileId: clientFileId, originalName, originalSize, iv, authTag, algorithm } = req.body;

    if (!originalName || !iv || !authTag) {
      return res.status(400).json({ message: 'Missing required encryption metadata (originalName, iv, authTag).' });
    }

    const ownerId = req.user.userId;
    const fileId = (clientFileId && typeof clientFileId === 'string' && clientFileId.trim().length > 0)
      ? clientFileId.trim()
      : crypto.randomUUID();
    const storageKey = `files/${fileId}/encrypted`;

    // 1. Upload ciphertext Buffer to B2 bucket
    await uploadToB2(storageKey, req.file.buffer, 'application/octet-stream');

    // 2. Insert metadata record into PostgreSQL files table
    const result = await pool.query(
      `INSERT INTO files 
        (id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
       RETURNING id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, created_at`,
      [
        fileId,
        ownerId,
        originalName,
        parseInt(originalSize || req.file.size, 10),
        storageKey,
        algorithm || 'AES-256-GCM',
        iv,
        authTag,
      ]
    );

    const savedFile = result.rows[0];

    res.status(201).json({
      message: 'File ciphertext uploaded successfully to B2.',
      file: {
        id: savedFile.id,
        originalName: savedFile.original_name,
        originalSize: savedFile.original_size,
        storageKey: savedFile.storage_key,
        createdAt: savedFile.created_at,
      },
    });
  } catch (error) {
    console.error('[File Upload Error]:', error.message);
    res.status(500).json({ message: 'Failed to upload file ciphertext.' });
  }
});

// GET /api/files - Get current authenticated user's owned file listing
router.get('/', verifyToken, async (req, res) => {
  try {
    const ownerId = req.user.userId;

    const result = await pool.query(
      `SELECT id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, created_at 
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
      createdAt: row.created_at,
    }));

    res.json({ files });
  } catch (error) {
    console.error('[File Listing Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file list.' });
  }
});

// GET /api/files/shared - Get files shared with the current authenticated user
router.get('/shared', verifyToken, async (req, res) => {
  try {
    const currentUserId = req.user.userId;

    const result = await pool.query(
      `SELECT f.id, f.original_name, f.original_size, f.storage_key, f.encryption_algorithm, f.iv, f.auth_tag, f.created_at,
              fk.sender_public_key, fk.wrapped_dek, fk.wrap_salt, fk.wrap_iv, fk.wrap_auth_tag,
              u.email AS owner_email
       FROM files f
       INNER JOIN file_keys fk ON f.id = fk.file_id
       INNER JOIN users u ON f.owner_id = u.id
       WHERE fk.user_id = $1
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

// POST /api/files/:id/share - Share file with a recipient user by storing their wrapped DEK
router.post('/:id/share', verifyToken, async (req, res) => {
  try {
    const fileId = req.params.id;
    const currentUserId = req.user.userId;
    const organizationId = req.user.orgId;
    const { recipientUserId, wrappedDek, wrapSalt, wrapIv, wrapAuthTag, senderPublicKey } = req.body;

    if (!recipientUserId || !wrappedDek || !wrapSalt || !wrapIv || !wrapAuthTag || !senderPublicKey) {
      return res.status(400).json({ message: 'Missing required sharing fields.' });
    }

    // 1. Verify file exists and belongs to current user
    const fileResult = await pool.query(
      'SELECT id, owner_id FROM files WHERE id = $1 AND owner_id = $2',
      [fileId, currentUserId]
    );

    if (fileResult.rows.length === 0) {
      return res.status(404).json({ message: 'File not found or unauthorized.' });
    }

    // 2. Verify recipient exists in the same organization and has a public key
    const recipientResult = await pool.query(
      'SELECT id, organization_id, public_key FROM users WHERE id = $1',
      [recipientUserId]
    );

    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Recipient user not found.' });
    }

    const recipient = recipientResult.rows[0];
    if (recipient.organization_id !== organizationId) {
      return res.status(403).json({ message: 'Recipient belongs to a different organization.' });
    }

    if (!recipient.public_key) {
      return res.status(400).json({ message: 'Recipient does not have a registered cryptographic public key.' });
    }

    // 3. Upsert wrapped DEK into file_keys table
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

// GET /api/files/:id/download - Download encrypted ciphertext from B2 and metadata from PostgreSQL
router.get('/:id/download', verifyToken, async (req, res) => {
  try {
    const currentUserId = req.user.userId;
    const fileId = req.params.id;

    // 1. Check if current user is owner OR has a file_keys record
    const fileResult = await pool.query(
      `SELECT f.id, f.owner_id, f.original_name, f.original_size, f.storage_key, f.encryption_algorithm, f.iv, f.auth_tag, f.created_at,
              fk.sender_public_key, fk.wrapped_dek, fk.wrap_salt, fk.wrap_iv, fk.wrap_auth_tag
       FROM files f
       LEFT JOIN file_keys fk ON f.id = fk.file_id AND fk.user_id = $2
       WHERE f.id = $1 AND (f.owner_id = $2 OR fk.user_id = $2)`,
      [fileId, currentUserId]
    );

    if (fileResult.rows.length === 0) {
      return res.status(404).json({ message: 'File not found or access denied.' });
    }

    const fileRecord = fileResult.rows[0];

    // 2. Download ciphertext Buffer from Backblaze B2
    const ciphertextBuffer = await getFromB2(fileRecord.storage_key);

    if (!ciphertextBuffer) {
      return res.status(404).json({ message: 'Ciphertext object not found in B2 storage.' });
    }

    // 3. Return base64 ciphertext and encryption metadata
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
        createdAt: fileRecord.created_at,
      },
    };

    // If requesting user is recipient, attach wrapping metadata for local unwrapping
    if (fileRecord.owner_id !== currentUserId && fileRecord.wrapped_dek) {
      responsePayload.wrapping = {
        senderPublicKey: fileRecord.sender_public_key,
        wrappedDek: fileRecord.wrapped_dek,
        wrapSalt: fileRecord.wrap_salt,
        wrapIv: fileRecord.wrap_iv,
        wrapAuthTag: fileRecord.wrap_auth_tag,
      };
    }

    res.json(responsePayload);
  } catch (error) {
    console.error('[File Download Error]:', error.message);
    res.status(500).json({ message: 'Failed to download file ciphertext.' });
  }
});

module.exports = router;
