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

async function runCycle10_1TestSuite() {
  console.log('================================================================');
  console.log('--- STARTING CYCLE 10.1 STRENGTHENED ORGANIZATIONAL RBAC SUITE ---');
  console.log('================================================================\n');

  const mainOrgName = `RBAC_MainOrg_${Date.now()}`;
  const aliceEmail = `alice_${Date.now()}@rbac.com`;
  const aliceDeviceId = `device-alice-${Date.now()}`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@rbac.com`;
  const bobDeviceId = `device-bob-${Date.now()}`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const extOrgName = `RBAC_ExtOrg_${Date.now()}`;
  const eveEmail = `eve_${Date.now()}@external.com`;
  const eveDeviceId = `device-eve-${Date.now()}`;

  // Register Main Org (Alice = Owner)
  const aliceReg = await request('POST', '/api/auth/register', { orgName: mainOrgName, email: aliceEmail, password: 'AlicePassword2026!' }, { 'X-Client-Device-ID': aliceDeviceId });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const mainOrgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Register External Org (Eve)
  const eveReg = await request('POST', '/api/auth/register', { orgName: extOrgName, email: eveEmail, password: 'EvePassword2026!' }, { 'X-Client-Device-ID': eveDeviceId });
  const eveToken = eveReg.data.token;

  // Alice creates Bob in Main Org
  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!' }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const bobId = bobCreate.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' }, { 'X-Client-Device-ID': bobDeviceId });
  const bobToken = bobLogin.data.token;

  console.log(`[Setup] Main Org (${mainOrgId}) & Ext Org (${eveReg.data.organization.id}):`);
  console.log(`  - Alice (Main Org Admin): ${aliceId}`);
  console.log(`  - Bob   (Main Org User) : ${bobId}`);
  console.log(`  - Eve   (External Admin): ${eveReg.data.user.id}\n`);

  // --- TEST 1: Initial System Role & Permission Seeding ---
  console.log('[TEST 1] Testing initial organization roles and permission seeding...');
  const rolesRes = await request('GET', '/api/roles', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  console.log(`  HTTP Result: ${rolesRes.status} (Roles count: ${rolesRes.data.roles.length})`);
  if (rolesRes.status !== 200 || rolesRes.data.roles.length < 1) {
    throw new Error('FAIL: Organization roles listing failed');
  }

  const ownerRole = rolesRes.data.roles[0];
  const ownerPerms = ownerRole.permissions.map(p => p.name);
  if (!ownerPerms.includes('ROLE_MANAGE') || !ownerPerms.includes('USER_MANAGE') || !ownerPerms.includes('FILE_READ')) {
    throw new Error('FAIL: Initial Owner role missing expected administrative permissions');
  }
  console.log('✅ TEST 1 PASSED: Initial organization role and permission catalog verified!');

  // --- TEST 2: Creation of Custom Organization Role ---
  console.log('\n[TEST 2] Admin creates custom organization role "Security Auditor"...');
  const createRoleRes = await request('POST', '/api/roles', {
    name: 'Security Auditor',
    description: 'Custom auditor role with read and role management permissions',
    permissions: ['FILE_READ', 'ROLE_MANAGE'],
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  console.log(`  HTTP Result: ${createRoleRes.status} (Role ID: ${createRoleRes.data.role?.id})`);
  if (createRoleRes.status !== 201 || !createRoleRes.data.role?.id) {
    throw new Error('FAIL: Custom role creation failed');
  }
  const auditorRoleId = createRoleRes.data.role.id;
  console.log('✅ TEST 2 PASSED: Custom organization role created successfully!');

  // --- TEST 3: Assigning Multiple Roles to User & Effective Permissions Union ---
  console.log('\n[TEST 3] Admin assigns multiple roles to Bob...');
  const assignRolesRes = await request('PUT', `/api/users/${bobId}/roles`, {
    roleIds: [ownerRole.id, auditorRoleId],
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  console.log(`  HTTP Result: ${assignRolesRes.status} (Roles assigned: ${assignRolesRes.data.roles.length})`);
  if (assignRolesRes.status !== 200 || assignRolesRes.data.roles.length !== 2) {
    throw new Error('FAIL: Multiple role assignment failed');
  }

  const userPerms = assignRolesRes.data.permissions;
  if (!userPerms.includes('FILE_READ') || !userPerms.includes('ROLE_MANAGE')) {
    throw new Error('FAIL: Effective permissions union calculation failed');
  }
  console.log('✅ TEST 3 PASSED: Multiple role assignment verified! Union of effective permissions calculated!');

  // --- TEST 4: Dynamic Role Permission Modification ---
  console.log('\n[TEST 4] Admin updates permissions for "Security Auditor" role (adds USER_MANAGE)...');
  const updatePermsRes = await request('PUT', `/api/roles/${auditorRoleId}/permissions`, {
    permissions: ['FILE_READ', 'ROLE_MANAGE', 'USER_CREATE', 'USER_MANAGE'],
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  if (updatePermsRes.status !== 200) throw new Error('FAIL: Role permission update failed');

  const meRes = await request('GET', '/api/auth/me', null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': bobDeviceId });
  if (!meRes.data.user.permissions.includes('USER_CREATE')) {
    throw new Error('FAIL: Dynamic permission recalculation failed after role update');
  }
  console.log('✅ TEST 4 PASSED: Dynamic permission recalculation after role permission modification verified!');

  // --- TEST 5: Security Invariant: Management Permissions DO NOT Grant Plaintext File Access ---
  console.log('\n[TEST 5] Testing Security Invariant: User with ROLE_MANAGE & USER_MANAGE attempts to download Alice\'s encrypted file without share...');
  
  // Alice uploads a file
  const samplePlaintext = Buffer.from('TOP SECRET ORGANIZATIONAL ENCRYPTED FILE DATA');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);

  await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'SecretFile.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrapping.wrappedDek,
    wrapSalt: ownerWrapping.wrapSalt,
    wrapIv: ownerWrapping.wrapIv,
    wrapAuthTag: ownerWrapping.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'NORMAL',
  }, fileCiphertext, 'SecretFile.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Bob (has USER_MANAGE & ROLE_MANAGE) attempts download without file ownership/share
  const bobDlAttempt = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': bobDeviceId });
  console.log(`  HTTP Result: ${bobDlAttempt.status} (${bobDlAttempt.data.message})`);
  if (bobDlAttempt.status !== 403) {
    throw new Error('CRITICAL SECURITY FAILURE: Management permissions allowed unauthorized file download!');
  }
  console.log('✅ TEST 5 PASSED: Security invariant verified! Admin/Management privileges do NOT grant file access!');

  // --- TEST 6: Organization Isolation ---
  console.log('\n[TEST 6] Testing Organization Isolation: External Eve attempts to list/modify Alice\'s org roles...');
  const eveAssignAttempt = await request('PUT', `/api/users/${aliceId}/roles`, {
    roleIds: [auditorRoleId],
  }, { 'Authorization': `Bearer ${eveToken}`, 'X-Client-Device-ID': eveDeviceId });

  console.log(`  Cross-Org Role Assign Result: ${eveAssignAttempt.status} (${eveAssignAttempt.data.message})`);
  if (eveAssignAttempt.status !== 403) {
    throw new Error('FAIL: Cross-organization role assignment attempt was not rejected with HTTP 403');
  }
  console.log('✅ TEST 6 PASSED: Organization isolation strictly enforced for custom roles!');

  // --- TEST 7: Custom Role Deletion ---
  console.log('\n[TEST 7] Testing custom role deletion (Auditor)...');
  const deleteCustomRole = await request('DELETE', `/api/roles/${auditorRoleId}`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  if (deleteCustomRole.status !== 200) throw new Error('FAIL: Custom role deletion failed');
  console.log('✅ TEST 7 PASSED: Custom role deletion verified!');

  console.log('\n================================================================');
  console.log('🎉 ALL 7 CYCLE 10.1 STRENGTHENED RBAC INTEGRATION TESTS PASSED!');
  console.log('================================================================');
  process.exit(0);
}

runCycle10_1TestSuite().catch(err => {
  console.error('\n❌ CYCLE 10.1 TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
