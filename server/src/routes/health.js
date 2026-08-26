const express = require('express');
const { checkDatabaseConnection } = require('../db');

const router = express.Router();

router.get('/health', async (_req, res) => {
  const dbStatus = await checkDatabaseConnection();

  const responseData = {
    status: dbStatus.connected ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    backend: {
      status: 'online',
      uptime: process.uptime(),
    },
    database: dbStatus,
  };

  res.status(dbStatus.connected ? 200 : 503).json(responseData);
});

module.exports = router;
