const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  idleTimeoutMillis: 5000,
  connectionTimeoutMillis: 3000,
});

async function checkDatabaseConnection() {
  try {
    const result = await pool.query('SELECT NOW() as now');
    return {
      connected: true,
      message: 'PostgreSQL connection successful',
      timestamp: result.rows[0].now,
    };
  } catch (error) {
    return {
      connected: false,
      message: error.message || 'Failed to connect to PostgreSQL',
    };
  }
}

async function initDb() {
  try {
    // Ensure pgcrypto extension for UUID generation if needed
    await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');

    // Create organizations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS organizations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL CHECK (role IN ('ADMIN', 'USER')),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('[DB] Database tables initialized successfully (organizations, users)');
  } catch (error) {
    console.error('[DB] Database initialization error:', error.message);
  }
}

module.exports = {
  pool,
  checkDatabaseConnection,
  initDb,
};