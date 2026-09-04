const express = require('express');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

// POST /api/crypto/public-key - Register or update current user's X25519 public key in user_keys table
router.post('/public-key', verifyToken, async (req, res) => {
  const { publicKey, keyAlgorithm } = req.body;

  if (!publicKey || typeof publicKey !== 'string' || !publicKey.trim()) {
    return res.status(400).json({ message: 'Valid public key is required.' });
  }

  try {
    const userId = req.user.userId;
    const algo = (keyAlgorithm && typeof keyAlgorithm === 'string') ? keyAlgorithm.trim() : 'X25519';

    const result = await pool.query(
      `INSERT INTO user_keys (user_id, public_key, key_algorithm)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET
         public_key = EXCLUDED.public_key,
         key_algorithm = EXCLUDED.key_algorithm,
         updated_at = CURRENT_TIMESTAMP
       RETURNING id, user_id, public_key, key_algorithm, updated_at`,
      [userId, publicKey.trim(), algo]
    );

    res.json({
      message: 'Public key stored successfully in user_keys.',
      userId: result.rows[0].user_id,
      hasPublicKey: true,
      publicKey: result.rows[0].public_key,
      keyAlgorithm: result.rows[0].key_algorithm,
    });
  } catch (error) {
    console.error('[Crypto Public Key Error]:', error.message);
    res.status(500).json({ message: 'Failed to store public key in user_keys.' });
  }
});

// GET /api/crypto/public-key - Get current user's public key status from user_keys table
router.get('/public-key', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const result = await pool.query(
      'SELECT public_key, key_algorithm FROM user_keys WHERE user_id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.json({
        hasPublicKey: false,
        publicKey: null,
        keyAlgorithm: null,
      });
    }

    const row = result.rows[0];

    res.json({
      hasPublicKey: true,
      publicKey: row.public_key,
      keyAlgorithm: row.key_algorithm,
    });
  } catch (error) {
    console.error('[Crypto Get Public Key Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve public key status.' });
  }
});

module.exports = router;
