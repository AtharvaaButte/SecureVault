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
    await pool.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');

    // 1. Organizations Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS organizations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. Users Table (Legacy users.role removed completely)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        public_key TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE users DROP COLUMN IF EXISTS role;
    `);

    // 3. Permissions Table (System-wide Standard Permission Catalog)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS permissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 4. Roles Table (Organization-scoped Roles)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(organization_id, name)
      );
    `);

    // 5. Role-Permissions Junction Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS role_permissions (
        role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, permission_id)
      );
    `);

    // 6. User-Roles Junction Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_roles (
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, role_id)
      );
    `);

    // 7. Files Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        original_name VARCHAR(255) NOT NULL,
        original_size BIGINT NOT NULL,
        storage_key VARCHAR(255) NOT NULL,
        encryption_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
        iv VARCHAR(255) NOT NULL,
        auth_tag VARCHAR(255) NOT NULL,
        sensitivity_level VARCHAR(30) NOT NULL DEFAULT 'NORMAL' CHECK (sensitivity_level IN ('NORMAL', 'SENSITIVE', 'HIGHLY_SENSITIVE')),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 8. File Keys Table (Per-user DEK Wrapping + Resource Access Restrictions)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS file_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        sender_public_key TEXT NOT NULL,
        wrapped_dek TEXT NOT NULL,
        wrap_salt TEXT NOT NULL,
        wrap_iv TEXT NOT NULL,
        wrap_auth_tag TEXT NOT NULL,
        access_level VARCHAR(20) NOT NULL DEFAULT 'READ' CHECK (access_level IN ('READ', 'FULL')),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(file_id, user_id)
      );
    `);

    await pool.query(`
      ALTER TABLE file_keys ADD COLUMN IF NOT EXISTS access_level VARCHAR(20) NOT NULL DEFAULT 'READ';
    `);

    // Recreate user_devices table cleanly with user_id PRIMARY KEY
    await pool.query(`DROP TABLE IF EXISTS user_devices CASCADE;`);

    // 9. Simplified User Devices Table (Keyed by user_id for location context)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_devices (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        last_ip VARCHAR(100),
        last_country VARCHAR(10) DEFAULT 'IN',
        last_state VARCHAR(100) DEFAULT 'Maharashtra',
        last_city VARCHAR(100) DEFAULT 'Mumbai',
        last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 10. Simplified Organization Policies Table (Core Security Settings)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS organization_policies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID UNIQUE NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        require_stepup_new_location BOOLEAN NOT NULL DEFAULT true,
        require_stepup_sensitive_file BOOLEAN NOT NULL DEFAULT true,
        enforce_geo_fencing BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE organization_policies DROP COLUMN IF EXISTS allowed_country;
      ALTER TABLE organization_policies DROP COLUMN IF EXISTS allowed_state;
      ALTER TABLE organization_policies DROP COLUMN IF EXISTS allowed_city;
    `);

    // 11. Multiple Allowed Geographic Locations Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS organization_geo_policies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        allowed_country VARCHAR(10) NOT NULL DEFAULT 'IN',
        allowed_state VARCHAR(100) NOT NULL DEFAULT 'ALL',
        allowed_city VARCHAR(100) NOT NULL DEFAULT 'ALL',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(organization_id, allowed_country, allowed_state, allowed_city)
      );
    `);

    // 12. Simplified Tamper-Evident Audit Logs Table with Hash Chain
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        event_type VARCHAR(100) NOT NULL,
        action VARCHAR(50) NOT NULL,
        resource_id VARCHAR(255),
        ip_address VARCHAR(100),
        location_label VARCHAR(255),
        previous_hash VARCHAR(64) NOT NULL,
        current_hash VARCHAR(64) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE audit_logs DROP COLUMN IF EXISTS user_email;
      ALTER TABLE audit_logs DROP COLUMN IF EXISTS device_id;
      ALTER TABLE audit_logs DROP COLUMN IF EXISTS reason;
    `);

    // Seed Standard System Permissions Catalog
    const standardPermissions = [
      ['FILE_READ', 'Download and decrypt owned or explicitly shared files'],
      ['FILE_UPLOAD', 'Encrypt and upload new file ciphertexts to cloud storage'],
      ['FILE_SHARE', 'Share owned files with organization members via DEK wrapping'],
      ['FILE_REVOKE', 'Revoke shared file access for recipient users'],
      ['FILE_DELETE', 'Delete owned files from cloud storage and database'],
      ['USER_CREATE', 'Create additional user accounts within the organization'],
      ['USER_MANAGE', 'Manage organization users and user status'],
      ['ROLE_MANAGE', 'Create, edit, and assign custom organization roles and permissions'],
      ['ORG_MANAGE', 'Manage organization-level settings and configuration'],
    ];

    for (const [name, desc] of standardPermissions) {
      await pool.query(
        `INSERT INTO permissions (name, description) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`,
        [name, desc]
      );
    }

    console.log('[DB] Finalized RBAC schema, file_keys access_level, simplified user_devices, organization_geo_policies, and audit_logs initialized successfully.');
  } catch (error) {
    console.error('[DB] Database initialization error:', error.message);
  }
}

module.exports = {
  pool,
  checkDatabaseConnection,
  initDb,
};