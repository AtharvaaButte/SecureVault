const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { initDb } = require('./db');
const healthRouter = require('./routes/health');
const authRouter = require('./routes/auth');
const cryptoRouter = require('./routes/crypto');
const filesRouter = require('./routes/files');
const usersRouter = require('./routes/users');
const rolesRouter = require('./routes/roles');
const policiesRouter = require('./routes/policies');
const auditRouter = require('./routes/audit');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Routes
app.use('/api', healthRouter);
app.use('/api/auth', authRouter);
app.use('/api/crypto', cryptoRouter);
app.use('/api/files', filesRouter);
app.use('/api/users', usersRouter);
app.use('/api/roles', rolesRouter);
app.use('/api/policies', policiesRouter);
app.use('/api/audit', auditRouter);

app.get('/', (_req, res) => {
  res.json({ message: 'SecureVault Backend API' });
});

const { initGeoLocationService } = require('./services/geoLocationService');

// Initialize database schema, IP2Location DB, and start server
initDb().then(() => {
  initGeoLocationService();
  app.listen(PORT, () => {
    console.log(`[Server] Express server running on port ${PORT}`);
  });
});
