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

// GET /api/files - Get current authenticated user's file listing
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

// GET /api/files/:id/download - Download encrypted ciphertext from B2 and metadata from PostgreSQL
router.get('/:id/download', verifyToken, async (req, res) => {
  try {
    const ownerId = req.user.userId;
    const fileId = req.params.id;

    // 1. Fetch file record from PostgreSQL
    const result = await pool.query(
      `SELECT id, owner_id, original_name, original_size, storage_key, encryption_algorithm, iv, auth_tag, created_at 
       FROM files 
       WHERE id = $1 AND owner_id = $2`,
      [fileId, ownerId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'File not found or access denied.' });
    }

    const fileRecord = result.rows[0];

    // 2. Download ciphertext Buffer from Backblaze B2
    const ciphertextBuffer = await getFromB2(fileRecord.storage_key);

    if (!ciphertextBuffer) {
      return res.status(404).json({ message: 'Ciphertext object not found in B2 storage.' });
    }

    // 3. Return base64 ciphertext and encryption metadata
    res.json({
      ciphertext: ciphertextBuffer.toString('base64'),
      metadata: {
        id: fileRecord.id,
        originalName: fileRecord.original_name,
        originalSize: parseInt(fileRecord.original_size, 10),
        algorithm: fileRecord.encryption_algorithm,
        iv: fileRecord.iv,
        authTag: fileRecord.auth_tag,
        createdAt: fileRecord.created_at,
      },
    });
  } catch (error) {
    console.error('[File Download Error]:', error.message);
    res.status(500).json({ message: 'Failed to download file ciphertext.' });
  }
});

module.exports = router;
