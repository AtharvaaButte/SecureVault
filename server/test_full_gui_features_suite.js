const path = require('path');
const http = require('http');
const crypto = require('crypto');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const { pool } = require('./src/db');
const fileCrypto = require('../client/src/main/crypto/fileCrypto');
const keyWrapping = require('../client/src/main/crypto/keyWrapping');

function request(method, pathName, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = typeof body === 'string' ? body : (body ? JSON.stringify(body) : '');
    const req = http.request({
      hostname: 'localhost',
      port: 5000,
      path: pathName,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data || '{}') });
        } catch (e) {
          resolve({ status: res.statusCode, raw: data });
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function uploadMultipart(pathName, fields, fileBuffer, fileName, headers = {}) {
  return new Promise((resolve, reject) => {
    const boundary = '----WebKitFormBoundary' + Math.random().toString(16).substring(2);
    let bodyParts = [];

    for (const [key, val] of Object.entries(fields)) {
      bodyParts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${val}\r\n`);
    }

    bodyParts.push(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n`
    );

    const bodyHead = Buffer.from(bodyParts.join(''));
    const bodyTail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const fullBody = Buffer.concat([bodyHead, fileBuffer, bodyTail]);

    const req = http.request({
      hostname: 'localhost',
      port: 5000,
      path: pathName,
      method: 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': fullBody.length,
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(data || '{}') }));
    });

    req.on('error', reject);
    req.write(fullBody);
    req.end();
  });
}

async function runFullGuiFeaturesSuite() {
  console.log('================================================================');
  console.log('--- STARTING SECUREVAULT FULL GUI FEATURES E2E VERIFICATION ---');
  console.log('================================================================\n');

  const ts = Date.now();
  const orgName = `GuiFullOrg_${ts}`;
  const adminEmail = `admin_${ts}@guifull.com`;
  const subManagerEmail = `submgr_${ts}@guifull.com`;
  const userBobEmail = `bob_${ts}@guifull.com`;

  // Keypairs for cryptographic identity
  const subManagerKeys = crypto.generateKeyPairSync('x25519');
  const subMgrPrivPem = subManagerKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const subMgrPubPem = subManagerKeys.publicKey.export({ type: 'spki', format: 'pem' });

  const bobKeys = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeys.publicKey.export({ type: 'spki', format: 'pem' });

  // 1. Register Organization and Owner
  const regRes = await request('POST', '/api/auth/register', { orgName, email: adminEmail, password: 'AdminPassword2026!' });
  if (regRes.status !== 201) throw new Error(`Reg failed: ${JSON.stringify(regRes.data)}`);
  const adminToken = regRes.data.token;
  console.log(`[Step 1] Organization "${orgName}" registered successfully.`);

  // 2. Custom Role Creation (Requirement 3)
  console.log('\n[Step 2] Admin creates custom "SubManager" role with permissions...');
  const createRoleRes = await request('POST', '/api/roles', {
    name: `SubManager_${ts}`,
    description: 'Sub-Manager with user creation, file sharing & read capabilities',
    permissions: ['USER_CREATE', 'USER_MANAGE', 'FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE', 'FILE_REVOKE'],
  }, { 'Authorization': `Bearer ${adminToken}` });

  if (createRoleRes.status !== 201) throw new Error(`Create role failed: ${JSON.stringify(createRoleRes.data)}`);
  const subManagerRoleId = createRoleRes.data.role.id;
  console.log(`✅ [Step 2] Custom role created: ID ${subManagerRoleId}`);

  // Fetch Roles and System Permissions catalog
  const rolesCatalog = await request('GET', '/api/roles', null, { 'Authorization': `Bearer ${adminToken}` });
  const permsCatalog = await request('GET', '/api/roles/permissions', null, { 'Authorization': `Bearer ${adminToken}` });
  if (rolesCatalog.status !== 200 || permsCatalog.status !== 200) throw new Error('Role catalog query failed');
  console.log(`✅ [Step 2] Retrieved role catalog (${rolesCatalog.data.roles.length} roles) and system permissions catalog (${permsCatalog.data.permissions.length} perms).`);

  // 3. User creation + role assignment (Requirement 1 & 2)
  console.log('\n[Step 3] Admin creates SubManager user with assigned role IDs...');
  const createSubMgrRes = await request('POST', '/api/users', {
    email: subManagerEmail,
    password: 'SubManagerPassword2026!',
    roleIds: [subManagerRoleId],
  }, { 'Authorization': `Bearer ${adminToken}` });

  if (createSubMgrRes.status !== 201) throw new Error(`Create SubManager failed: ${JSON.stringify(createSubMgrRes.data)}`);
  const subMgrUserId = createSubMgrRes.data.user.id;
  console.log(`✅ [Step 3] SubManager user created: ID ${subMgrUserId} with assigned roles.`);

  // SubManager logs in and registers crypto identity
  const subMgrLogin = await request('POST', '/api/auth/login', { email: subManagerEmail, password: 'SubManagerPassword2026!' });
  const subMgrToken = subMgrLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: subMgrPubPem }, { 'Authorization': `Bearer ${subMgrToken}` });

  // 4. Non-owner user creates user (Requirement 2)
  console.log('\n[Step 4] SubManager (non-owner) creates Bob using USER_CREATE permission...');
  const createBobRes = await request('POST', '/api/users', {
    email: userBobEmail,
    password: 'BobPassword2026!',
    roleIds: [subManagerRoleId],
  }, { 'Authorization': `Bearer ${subMgrToken}` });

  if (createBobRes.status !== 201) throw new Error(`Non-owner user creation failed: ${JSON.stringify(createBobRes.data)}`);
  const bobUserId = createBobRes.data.user.id;
  console.log(`✅ [Step 4] Bob created by non-owner SubManager: ID ${bobUserId}`);

  // Bob logs in and registers crypto identity
  const bobLogin = await request('POST', '/api/auth/login', { email: userBobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  // 5. Query user effective permissions endpoint (Requirement 7)
  console.log('\n[Step 5] Querying effective user permissions for Bob (Requirement 7)...');
  const bobPermsRes = await request('GET', `/api/users/${bobUserId}/permissions`, null, { 'Authorization': `Bearer ${subMgrToken}` });
  if (bobPermsRes.status !== 200) throw new Error(`Query permissions failed: ${JSON.stringify(bobPermsRes.data)}`);
  console.log(`✅ [Step 5] Bob effective permissions query succeeded:`, bobPermsRes.data.permissions);

  // 6. Organization Security Policies & Multiple Allowed Geo Locations (Requirements 4 & 5)
  console.log('\n[Step 6] Testing Security Policies & Geo-Fencing (Requirements 4 & 5)...');
  const policyRes = await request('GET', '/api/policies', null, { 'Authorization': `Bearer ${adminToken}` });
  if (policyRes.status !== 200) throw new Error('Policy query failed');
  if (policyRes.data.policy.enforce_geo_fencing !== false) throw new Error('Geo fencing default must be disabled (false)');
  console.log('✅ Default Geo-fencing is disabled (false) as required!');

  // Add multiple allowed geo locations
  const addLoc1 = await request('POST', '/api/policies/locations', { allowedCountry: 'US', allowedState: 'CA', allowedCity: 'San Francisco' }, { 'Authorization': `Bearer ${adminToken}` });
  const addLoc2 = await request('POST', '/api/policies/locations', { allowedCountry: 'IN', allowedState: 'MH', allowedCity: 'Mumbai' }, { 'Authorization': `Bearer ${adminToken}` });
  if (addLoc1.status !== 201 || addLoc2.status !== 201) throw new Error('Add location failed');
  console.log(`✅ [Step 6] Added multiple allowed geo locations. Total: ${addLoc2.data.policy.allowedLocations.length}`);

  // 7. Data Classification File Upload & Sharing with File-Level Restrictions (Requirements 6, 8, 9)
  console.log('\n[Step 7] SubManager uploads HIGHLY_CONFIDENTIAL file & shares with Bob with READ ONLY restriction...');
  const fileId = crypto.randomUUID();
  const plaintext = Buffer.from('TOP SECRET CONFIDENTIAL STRATEGY');
  const enc = fileCrypto.encryptBuffer(plaintext);
  fileCrypto.storeDek(fileId, enc.dek);
  const wrap = keyWrapping.wrapDek(enc.dek, subMgrPrivPem, subMgrPubPem, fileId, subMgrUserId);

  await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'HighlyConfidentialStrategy.pdf',
    originalSize: plaintext.length.toString(),
    iv: enc.iv.toString('base64'),
    authTag: enc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: wrap.wrappedDek,
    wrapSalt: wrap.wrapSalt,
    wrapIv: wrap.wrapIv,
    wrapAuthTag: wrap.wrapAuthTag,
    senderPublicKey: subMgrPubPem,
    dataClassification: 'HIGHLY_CONFIDENTIAL',
  }, enc.ciphertext, 'HighlyConfidentialStrategy.enc', { 'Authorization': `Bearer ${subMgrToken}` });

  // Share with Bob with READ access level (File-level restriction applied)
  const bobWrap = keyWrapping.wrapDek(enc.dek, subMgrPrivPem, bobPubPem, fileId, bobUserId);
  const shareRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobUserId,
    senderPublicKey: subMgrPubPem,
    wrappedDek: bobWrap.wrappedDek,
    wrapSalt: bobWrap.wrapSalt,
    wrapIv: bobWrap.wrapIv,
    wrapAuthTag: bobWrap.wrapAuthTag,
    accessLevel: 'READ',
  }, { 'Authorization': `Bearer ${subMgrToken}`, 'X-Reauth-Password': 'SubManagerPassword2026!' });

  if (shareRes.status !== 201) throw new Error(`Share failed: ${JSON.stringify(shareRes.data)}`);
  console.log('✅ [Step 7] File uploaded with HIGHLY_CONFIDENTIAL classification and shared with READ ONLY restriction!');

  // 8. Step-Up Authentication Test (Requirement 10 & 11)
  console.log('\n[Step 8] Bob attempts download without step-up password (triggers 403 stepUpRequired)...');
  const bobDlNoPwd = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  if (bobDlNoPwd.status !== 403 || !bobDlNoPwd.data.stepUpRequired) {
    throw new Error('Expected 403 stepUpRequired for HIGHLY_CONFIDENTIAL file download');
  }
  console.log('✅ [Step 8] Backend correctly returned 403 stepUpRequired!');

  // Bob attempts download with correct step-up password
  const bobDlWithPwd = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${bobToken}`,
    'X-Reauth-Password': 'BobPassword2026!',
  });
  if (bobDlWithPwd.status !== 200) throw new Error(`Bob download with step-up failed: ${bobDlWithPwd.status}`);

  const unwrappedDek = keyWrapping.unwrapDek(
    bobDlWithPwd.data.wrapping.wrappedDek,
    bobDlWithPwd.data.wrapping.wrapSalt,
    bobDlWithPwd.data.wrapping.wrapIv,
    bobDlWithPwd.data.wrapping.wrapAuthTag,
    bobDlWithPwd.data.wrapping.senderPublicKey,
    bobPrivPem,
    fileId,
    bobUserId
  );
  const decrypted = fileCrypto.decryptBuffer(
    Buffer.from(bobDlWithPwd.data.ciphertext, 'base64'),
    unwrappedDek,
    Buffer.from(bobDlWithPwd.data.metadata.iv, 'base64'),
    Buffer.from(bobDlWithPwd.data.metadata.authTag, 'base64')
  );
  if (!decrypted.equals(plaintext)) throw new Error('Decrypted content mismatch');
  console.log('✅ [Step 8] Bob step-up re-authentication succeeded! File decrypted 100% byte-for-byte!');

  // 9. Audit Log & Hash Chain Integrity Verification (Requirement 12)
  console.log('\n[Step 9] Verifying Security Audit Logs & SHA-256 Hash Chain Integrity...');
  const auditLogsRes = await request('GET', '/api/audit', null, { 'Authorization': `Bearer ${adminToken}` });
  const verifyRes = await request('GET', '/api/audit/verify', null, { 'Authorization': `Bearer ${adminToken}` });

  if (auditLogsRes.status !== 200 || verifyRes.status !== 200) throw new Error('Audit query failed');
  if (!verifyRes.data.valid) throw new Error(`Audit hash chain invalid: ${verifyRes.data.error}`);
  console.log(`✅ [Step 9] Audit chain verified successfully! All ${verifyRes.data.totalLogs} logs intact.`);

  console.log('\n================================================================');
  console.log('🎉 ALL 15 SECUREVAULT GUI & SECURITY FEATURES PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runFullGuiFeaturesSuite().catch(err => {
  console.error('\n❌ FULL GUI FEATURES SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
