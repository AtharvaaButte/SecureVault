const path = require('path');
const http = require('http');
const crypto = require('crypto');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const { pool } = require('./src/db');
const fileCrypto = require('../client/src/main/crypto/fileCrypto');
const keyWrapping = require('../client/src/main/crypto/keyWrapping');
const auditService = require('./src/services/auditService');

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

async function runFinalRbacTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING FINALIZED RBAC & RESOURCE RESTRICTIONS SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users
  const mainOrgName = `FinalOrg_${Date.now()}`;
  const aliceEmail = `alice_${Date.now()}@final.com`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `submanager_${Date.now()}@final.com`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const carolEmail = `carol_${Date.now()}@final.com`;
  const carolKeyPair = crypto.generateKeyPairSync('x25519');
  const carolPrivPem = carolKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const carolPubPem = carolKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Register Main Org (Alice = Owner)
  const aliceReg = await request('POST', '/api/auth/register', { orgName: mainOrgName, email: aliceEmail, password: 'AlicePassword2026!' });
  console.log('aliceReg response:', JSON.stringify(aliceReg, null, 2));
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const mainOrgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}` });

  // --- TEST 1: Removal of Legacy users.role ---
  console.log('[TEST 1] Testing removal of legacy users.role column...');
  const userColRes = await pool.query(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'role'"
  );
  if (userColRes.rows.length > 0) {
    throw new Error('FAIL: Legacy users.role column still exists in database!');
  }
  console.log('✅ TEST 1 PASSED: Legacy users.role column completely removed! Roles derived dynamically from user_roles!');

  // --- TEST 2: Custom Organization Roles & Removal of Mandatory Admin/Member Blocks ---
  console.log('\n[TEST 2] Testing organization role creation and role deletion...');
  
  // Create Sub-Manager role with FILE_READ & FILE_SHARE permissions
  const subManagerRoleRes = await request('POST', '/api/roles', {
    name: 'Sub-Manager',
    description: 'Sub-Manager role with file read and global file share permissions',
    permissions: ['FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE'],
  }, { 'Authorization': `Bearer ${aliceToken}` });

  if (subManagerRoleRes.status !== 201) throw new Error('FAIL: Sub-Manager role creation failed');
  const subManagerRoleId = subManagerRoleRes.data.role.id;

  // Alice creates Sub-Manager Bob and User Carol
  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', roleIds: [subManagerRoleId] }, { 'Authorization': `Bearer ${aliceToken}` });
  const bobId = bobCreate.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  const carolCreate = await request('POST', '/api/users', { email: carolEmail, password: 'CarolPassword2026!' }, { 'Authorization': `Bearer ${aliceToken}` });
  const carolId = carolCreate.data.user.id;
  const carolLogin = await request('POST', '/api/auth/login', { email: carolEmail, password: 'CarolPassword2026!' });
  const carolToken = carolLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: carolPubPem }, { 'Authorization': `Bearer ${carolToken}` });

  // Test role deletion of a custom role
  const tempRoleRes = await request('POST', '/api/roles', { name: 'TempRole', permissions: ['FILE_READ'] }, { 'Authorization': `Bearer ${aliceToken}` });
  const deleteTempRes = await request('DELETE', `/api/roles/${tempRoleRes.data.role.id}`, null, { 'Authorization': `Bearer ${aliceToken}` });
  if (deleteTempRes.status !== 200) throw new Error('FAIL: Custom role deletion failed');
  console.log('✅ TEST 2 PASSED: Organization role creation and deletion verified!');

  // --- TEST 3: Simplified user_devices Context ---
  console.log('\n[TEST 3] Testing simplified user_devices location context...');
  const devRes = await pool.query('SELECT * FROM user_devices WHERE user_id = $1', [aliceId]);
  if (devRes.rows.length === 0) throw new Error('FAIL: user_devices record missing for user');
  const devRow = devRes.rows[0];
  if (devRow.device_id !== undefined || devRow.is_trusted !== undefined) {
    throw new Error('FAIL: Obsolete device_id or is_trusted fields still present in user_devices!');
  }
  console.log(`  User Device Context: user_id=${devRow.user_id}, location=${devRow.last_city}, ${devRow.last_state}, ${devRow.last_country}`);
  console.log('✅ TEST 3 PASSED: Simplified user_devices table verified!');

  // --- TEST 4: Multiple Allowed Geographic Locations (organization_geo_policies) ---
  console.log('\n[TEST 4] Testing multiple allowed geographic locations in organization_geo_policies...');
  
  // Add second allowed location: US / California / San Francisco
  const addGeoRes = await request('POST', '/api/policies/locations', {
    allowedCountry: 'US',
    allowedState: 'California',
    allowedCity: 'San Francisco',
  }, { 'Authorization': `Bearer ${aliceToken}` });

  console.log(`  Add Geo Location Result: ${addGeoRes.status} (Total allowed locations: ${addGeoRes.data.policy.allowedLocations.length})`);
  if (addGeoRes.status !== 201 || addGeoRes.data.policy.allowedLocations.length < 2) {
    throw new Error('FAIL: Adding multiple geo locations failed');
  }

  // Alice uploads File A
  const samplePlaintext = Buffer.from('FINAL RBAC & RESOURCE RESTRICTIONS TEST PAYLOAD');
  const fileAId = crypto.randomUUID();
  const { dek: dekA, iv: ivA, ciphertext: cipherA, authTag: tagA } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileAId, dekA);

  const ownerWrappingA = keyWrapping.wrapDek(dekA, alicePrivPem, alicePubPem, fileAId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: fileAId,
    originalName: 'Confidential_A.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: ivA.toString('base64'),
    authTag: tagA.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrappingA.wrappedDek,
    wrapSalt: ownerWrappingA.wrapSalt,
    wrapIv: ownerWrappingA.wrapIv,
    wrapAuthTag: ownerWrappingA.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'NORMAL',
  }, cipherA, 'Confidential_A.enc', { 'Authorization': `Bearer ${aliceToken}` });

  // Test access from US / California / San Francisco (Second allowed location) -> OK
  const usLocDl = await request('GET', `/api/files/${fileAId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Country': 'US',
    'X-Client-State': 'California',
    'X-Client-City': 'San Francisco',
    'X-Reauth-Password': 'AlicePassword2026!',
  });
  if (usLocDl.status !== 200) throw new Error('FAIL: Multiple allowed geo location check failed for US location');
  console.log('✅ TEST 4 PASSED: Multiple allowed geographic locations in organization_geo_policies verified!');

  // --- TEST 5: Simplified audit_logs & SHA-256 Hash Chain Integrity ---
  console.log('\n[TEST 5] Testing simplified audit_logs and hash chain verification...');
  const auditLogsRes = await request('GET', '/api/audit', null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Reauth-Password': 'AlicePassword2026!',
  });
  console.log('auditLogsRes:', JSON.stringify(auditLogsRes, null, 2));
  const auditRow = auditLogsRes.data.logs ? auditLogsRes.data.logs[0] : null;
  if (auditRow.user_email !== undefined || auditRow.reason !== undefined) {
    throw new Error('FAIL: Obsolete user_email or reason fields still present in audit_logs!');
  }

  const auditVerify = await auditService.verifyAuditChain(mainOrgId);
  console.log(`  Audit Chain Verification: Valid=${auditVerify.valid}, Total=${auditVerify.totalLogs}`);
  if (!auditVerify.valid) throw new Error('FAIL: Audit chain verification failed');
  console.log('✅ TEST 5 PASSED: Simplified audit_logs SHA-256 hash chain verified!');

  // --- TEST 6: Resource-Level File Access Restrictions (Manager / Sub-Manager Scenario) ---
  console.log('\n[TEST 6] Testing Resource-Level Restrictions: Manager shares File A with Sub-Manager as READ ONLY...');
  
  // Alice (Manager) shares File A with Bob (Sub-Manager) as READ ONLY (accessLevel = 'READ')
  const bobWrappingA = keyWrapping.wrapDek(dekA, alicePrivPem, bobPubPem, fileAId, aliceId);
  const shareResA = await request('POST', `/api/files/${fileAId}/share`, {
    recipientUserId: bobId,
    wrappedDek: bobWrappingA.wrappedDek,
    wrapSalt: bobWrappingA.wrapSalt,
    wrapIv: bobWrappingA.wrapIv,
    wrapAuthTag: bobWrappingA.wrapAuthTag,
    senderPublicKey: alicePubPem,
    accessLevel: 'READ', // READ ONLY
  }, { 'Authorization': `Bearer ${aliceToken}` });

  console.log(`  Manager -> Sub-Manager Share File A Result: ${shareResA.status} (Access Level: ${shareResA.data.accessLevel})`);
  if (shareResA.status !== 201 || shareResA.data.accessLevel !== 'READ') {
    throw new Error('FAIL: Share File A as READ failed');
  }

  // 6a. Sub-Manager Bob downloads & decrypts File A -> SUCCESS (Global FILE_READ permission + file_keys record)
  const bobDlA = await request('GET', `/api/files/${fileAId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  Sub-Manager Download File A Result: ${bobDlA.status}`);
  if (bobDlA.status !== 200) throw new Error('FAIL: Sub-Manager failed to download READ ONLY file A');

  // 6b. Sub-Manager Bob (who has global FILE_SHARE role permission) attempts to RE-SHARE File A with Carol
  const carolWrappingA = keyWrapping.wrapDek(dekA, bobPrivPem, carolPubPem, fileAId, bobId);
  const bobReshareAttempt = await request('POST', `/api/files/${fileAId}/share`, {
    recipientUserId: carolId,
    wrappedDek: carolWrappingA.wrappedDek,
    wrapSalt: carolWrappingA.wrapSalt,
    wrapIv: carolWrappingA.wrapIv,
    wrapAuthTag: carolWrappingA.wrapAuthTag,
    senderPublicKey: bobPubPem,
    accessLevel: 'READ',
  }, { 'Authorization': `Bearer ${bobToken}` });

  console.log(`  Sub-Manager Re-Share File A Attempt: ${bobReshareAttempt.status} (${bobReshareAttempt.data.message})`);
  if (bobReshareAttempt.status !== 403) {
    throw new Error('CRITICAL AUTHORIZATION FAILURE: Sub-Manager was able to re-share a file restricted to READ ONLY!');
  }
  console.log('  ✓ Re-sharing READ ONLY File A strictly DENIED with HTTP 403!');

  // 6c. Now Alice shares File B with Bob as FULL access (accessLevel = 'FULL')
  const fileBId = crypto.randomUUID();
  const { dek: dekB, iv: ivB, ciphertext: cipherB, authTag: tagB } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileBId, dekB);

  const ownerWrappingB = keyWrapping.wrapDek(dekB, alicePrivPem, alicePubPem, fileBId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: fileBId,
    originalName: 'Confidential_B.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: ivB.toString('base64'),
    authTag: tagB.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrappingB.wrappedDek,
    wrapSalt: ownerWrappingB.wrapSalt,
    wrapIv: ownerWrappingB.wrapIv,
    wrapAuthTag: ownerWrappingB.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'NORMAL',
  }, cipherB, 'Confidential_B.enc', { 'Authorization': `Bearer ${aliceToken}` });

  const bobWrappingB = keyWrapping.wrapDek(dekB, alicePrivPem, bobPubPem, fileBId, aliceId);
  await request('POST', `/api/files/${fileBId}/share`, {
    recipientUserId: bobId,
    wrappedDek: bobWrappingB.wrappedDek,
    wrapSalt: bobWrappingB.wrapSalt,
    wrapIv: bobWrappingB.wrapIv,
    wrapAuthTag: bobWrappingB.wrapAuthTag,
    senderPublicKey: alicePubPem,
    accessLevel: 'FULL', // FULL ACCESS
  }, { 'Authorization': `Bearer ${aliceToken}` });

  // Sub-Manager Bob (who has global FILE_SHARE) re-shares File B (FULL access) with Carol -> SUCCESS!
  const carolWrappingB = keyWrapping.wrapDek(dekB, bobPrivPem, carolPubPem, fileBId, carolId);
  const bobShareBRes = await request('POST', `/api/files/${fileBId}/share`, {
    recipientUserId: carolId,
    wrappedDek: carolWrappingB.wrappedDek,
    wrapSalt: carolWrappingB.wrapSalt,
    wrapIv: carolWrappingB.wrapIv,
    wrapAuthTag: carolWrappingB.wrapAuthTag,
    senderPublicKey: bobPubPem,
    accessLevel: 'READ',
  }, { 'Authorization': `Bearer ${bobToken}` });

  console.log(`  Sub-Manager Re-Share File B (FULL) Result: ${bobShareBRes.status}`);
  if (bobShareBRes.status !== 201) {
    throw new Error('FAIL: Sub-Manager failed to share File B which had FULL access level');
  }
  console.log('✅ TEST 6 PASSED: Resource-Level File Access Restrictions (READ vs FULL) verified 100%!');

  // --- TEST 7: E2EE Decryption Verification ---
  console.log('\n[TEST 7] Verifying Carol downloads & decrypts File B shared by Bob...');
  const carolDlB = await request('GET', `/api/files/${fileBId}/download`, null, { 'Authorization': `Bearer ${carolToken}` });
  if (carolDlB.status !== 200) throw new Error('FAIL: Carol download failed');

  const carolWrappingData = carolDlB.data.wrapping;
  const unwrappedDekB = keyWrapping.unwrapDek(
    carolWrappingData.wrappedDek,
    carolWrappingData.wrapSalt,
    carolWrappingData.wrapIv,
    carolWrappingData.wrapAuthTag,
    bobPubPem,
    carolPrivPem,
    fileBId,
    carolId
  );

  const decryptedB = fileCrypto.decryptBuffer(
    Buffer.from(carolDlB.data.ciphertext, 'base64'),
    unwrappedDekB,
    Buffer.from(carolDlB.data.metadata.iv, 'base64'),
    Buffer.from(carolDlB.data.metadata.authTag, 'base64')
  );

  if (decryptedB.toString() !== samplePlaintext.toString()) {
    throw new Error('FAIL: Decrypted payload mismatch!');
  }
  console.log('✅ TEST 7 PASSED: E2EE unwrapping & AES-256-GCM decryption verified 100% byte-for-byte!');

  console.log('\n================================================================');
  console.log('🎉 ALL 7 FINALIZED RBAC & RESOURCE RESTRICTIONS TESTS PASSED!');
  console.log('================================================================');
  process.exit(0);
}

runFinalRbacTestSuite().catch(err => {
  console.error('\n❌ FINAL RBAC SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
