const express = require('express');
const { pool } = require('../db');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

// POST /api/crypto/public-key - Register or update current user's public key
router.post('/public-key', verifyToken, async (req, res) => {
  const { publicKey } = req.body;

  if (!publicKey || typeof publicKey !== 'string' || !publicKey.trim()) {
    return res.status(400).json({ message: 'Valid public key is required.' });
  }

  try {
    const userId = req.user.userId;

    const result = await pool.query(
      'UPDATE users SET public_key = $1 WHERE id = $2 RETURNING id, email, public_key',
      [publicKey.trim(), userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({
      message: 'Public key stored successfully.',
      userId: result.rows[0].id,
      hasPublicKey: true,
      publicKey: result.rows[0].public_key,
    });
  } catch (error) {
    console.error('[Crypto Public Key Error]:', error.message);
    res.status(500).json({ message: 'Failed to store public key.' });
  }
});

// GET /api/crypto/public-key - Get current user's public key status
router.get('/public-key', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const result = await pool.query(
      'SELECT public_key FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const publicKey = result.rows[0].public_key;

    res.json({
      hasPublicKey: !!publicKey,
      publicKey: publicKey || null,
    });
  } catch (error) {
    console.error('[Crypto Get Public Key Error]:', error.message);
    res.status(500).json({ message: 'Failed to retrieve public key status.' });
  }
});

module.exports = router;
