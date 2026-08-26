const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { initDb } = require('./db');
const healthRouter = require('./routes/health');
const authRouter = require('./routes/auth');
const cryptoRouter = require('./routes/crypto');
const filesRouter = require('./routes/files');

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

app.get('/', (_req, res) => {
  res.json({ message: 'SecureVault Backend API' });
});

// Initialize database schema and start server
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[Server] Express server running on port ${PORT}`);
  });
});
