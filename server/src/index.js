const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const healthRouter = require('./routes/health');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Routes
app.use('/api', healthRouter);

app.get('/', (_req, res) => {
  res.json({ message: 'SecureVault Backend API' });
});

app.listen(PORT, () => {
  console.log(`[Server] Express server running on port ${PORT}`);
  
});
