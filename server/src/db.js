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

    // 2. Users Table (No legacy role or public_key columns)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. User Keys Table (Cryptographic Identity - X25519)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_key TEXT NOT NULL,
        key_algorithm VARCHAR(50) NOT NULL DEFAULT 'X25519',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 4. Permissions Table (System-wide Standard Permission Catalog)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS permissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 5. Roles Table (Organization-scoped Roles with created_by auditability)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        created_by UUID REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(organization_id, name)
      );
    `);

    // 6. Role-Permissions Junction Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS role_permissions (
        role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, permission_id)
      );
    `);

    // 7. User-Roles Junction Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_roles (
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, role_id)
      );
    `);

    // 8. Files Table (data_classification: PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_CONFIDENTIAL)
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
        data_classification VARCHAR(30) NOT NULL DEFAULT 'INTERNAL' CHECK (data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY_CONFIDENTIAL')),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 9. File Keys Table (DEK Wrapping - X25519 + HKDF + AES-256-GCM + AAD)
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

    // 10. File Restrictions Table (Per-user, per-file operation blocks)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS file_restrictions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        blocked_operation VARCHAR(100) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(file_id, user_id, blocked_operation)
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_file_restrictions_lookup ON file_restrictions(file_id, user_id);
    `);

    // 11. User Devices Table (Keyed by user_id for location context)
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

    // 12. Organization Policies Table (Core Security Settings)
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

    // 13. Multiple Allowed Geographic Locations Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS organization_geo_policies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        allowed_country VARCHAR(10) NOT NULL DEFAULT 'IN',
        allowed_state VARCHAR(100),
        allowed_city VARCHAR(100),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(organization_id, allowed_country, allowed_state, allowed_city)
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_geo_policies_org ON organization_geo_policies(organization_id);
    `);

    // 14. Tamper-Evident Audit Logs Table with Hash Chain & Indexes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        event_type VARCHAR(100) NOT NULL,
        action VARCHAR(50) NOT NULL,
        resource_type VARCHAR(50) NOT NULL DEFAULT 'FILE',
        resource_id VARCHAR(255),
        ip_address VARCHAR(100),
        location_label VARCHAR(255),
        previous_hash VARCHAR(64) NOT NULL,
        current_hash VARCHAR(64) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(organization_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_logs(user_id, created_at DESC);
    `);

    // 15. Permission Audit View
    await pool.query(`
      CREATE OR REPLACE VIEW user_permission_audit_view AS
      SELECT 
        o.id AS organization_id,
        o.name AS organization_name,
        u.id AS user_id,
        u.email AS user_email,
        r.id AS role_id,
        r.name AS role_name,
        p.id AS permission_id,
        p.name AS permission_name,
        p.description AS permission_description
      FROM organizations o
      JOIN users u ON u.organization_id = o.id
      JOIN user_roles ur ON ur.user_id = u.id
      JOIN roles r ON r.id = ur.role_id
      JOIN role_permissions rp ON rp.role_id = r.id
      JOIN permissions p ON p.id = rp.permission_id;
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

    console.log('[DB] Finalized clean security schema initialized successfully from scratch.');
  } catch (error) {
    console.error('[DB] Database initialization error:', error.message);
  }
}

module.exports = {
  pool,
  checkDatabaseConnection,
  initDb,
};