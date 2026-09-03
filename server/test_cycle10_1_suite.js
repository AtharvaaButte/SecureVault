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

  // 1. Setup Organization & Users
  const mainOrgName = `Cycle10_MainOrg_${Date.now()}`;
  const extOrgName = `Cycle10_ExtOrg_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@c10.com`;
  const aliceDeviceId = `alice-dev-${Date.now()}`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@c10.com`;
  const bobDeviceId = `bob-dev-${Date.now()}`;

  const eveEmail = `eve_${Date.now()}@external.com`;
  const eveDeviceId = `eve-dev-${Date.now()}`;

  // Register Main Org (Alice = Admin)
  const aliceReg = await request('POST', '/api/auth/register', { orgName: mainOrgName, email: aliceEmail, password: 'AlicePassword2026!' }, { 'X-Client-Device-ID': aliceDeviceId });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const mainOrgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Register External Org (Eve = External Admin)
  const eveReg = await request('POST', '/api/auth/register', { orgName: extOrgName, email: eveEmail, password: 'EvePassword2026!' }, { 'X-Client-Device-ID': eveDeviceId });
  const eveToken = eveReg.data.token;
  const extOrgId = eveReg.data.organization.id;

  // Alice creates Bob in Main Org
  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const bobId = bobCreate.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' }, { 'X-Client-Device-ID': bobDeviceId });
  const bobToken = bobLogin.data.token;

  console.log(`[Setup] Main Org (${mainOrgId}) & Ext Org (${extOrgId}):`);
  console.log(`  - Alice (Main Org Admin): ${aliceId}`);
  console.log(`  - Bob   (Main Org User) : ${bobId}`);
  console.log(`  - Eve   (External Admin): ${eveReg.data.user.id}\n`);

  // --- TEST 1: Default System Roles & Permission Seeding ---
  console.log('[TEST 1] Testing default system roles and permission seeding...');
  const rolesRes = await request('GET', '/api/roles', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  console.log(`  HTTP Result: ${rolesRes.status} (Roles count: ${rolesRes.data.roles.length})`);
  if (rolesRes.status !== 200 || rolesRes.data.roles.length < 2) {
    throw new Error('FAIL: Organization roles listing failed');
  }

  const adminRole = rolesRes.data.roles.find(r => r.name === 'Admin');
  const memberRole = rolesRes.data.roles.find(r => r.name === 'Member');

  const adminPerms = adminRole.permissions.map(p => p.name);
  if (!adminPerms.includes('ROLE_MANAGE') || !adminPerms.includes('USER_MANAGE') || !adminPerms.includes('FILE_READ')) {
    throw new Error('FAIL: Admin role missing expected administrative permissions');
  }
  console.log('✅ TEST 1 PASSED: Default Admin & Member system roles and permissions verified!');

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
  console.log('\n[TEST 3] Admin assigns multiple roles (Member + Security Auditor) to Bob...');
  const assignRolesRes = await request('PUT', `/api/users/${bobId}/roles`, {
    roleIds: [memberRole.id, auditorRoleId],
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  console.log(`  HTTP Result: ${assignRolesRes.status} (Roles assigned: ${assignRolesRes.data.roles?.length})`);
  if (assignRolesRes.status !== 200) throw new Error('FAIL: Multiple role assignment failed');

  const bobPerms = assignRolesRes.data.permissions;
  if (!bobPerms.includes('FILE_READ') || !bobPerms.includes('FILE_UPLOAD') || !bobPerms.includes('ROLE_MANAGE')) {
    throw new Error('FAIL: Bob effective permissions do not match expected union of assigned roles');
  }
  console.log('✅ TEST 3 PASSED: Multiple role assignment verified! Union of effective permissions calculated!');

  // --- TEST 4: Updating Custom Role Permissions & Dynamic Calculation ---
  console.log('\n[TEST 4] Admin updates permissions for "Security Auditor" role (adds USER_MANAGE)...');
  const updatePermsRes = await request('PUT', `/api/roles/${auditorRoleId}/permissions`, {
    permissions: ['FILE_READ', 'ROLE_MANAGE', 'USER_MANAGE'],
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  console.log(`  HTTP Result: ${updatePermsRes.status}`);
  if (updatePermsRes.status !== 200) throw new Error('FAIL: Updating role permissions failed');

  const bobMembersRes = await request('GET', '/api/users/members', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const updatedBob = bobMembersRes.data.users.find(u => u.id === bobId);
  if (!updatedBob.permissions.includes('USER_MANAGE')) {
    throw new Error('FAIL: User effective permissions did not dynamically update after role permission modification');
  }
  console.log('✅ TEST 4 PASSED: Dynamic permission recalculation after role permission modification verified!');

  // --- TEST 5: Security Invariant - Admin Privileges NEVER Grant Cryptographic File Access ---
  console.log('\n[TEST 5] Testing Security Invariant: User with ROLE_MANAGE & USER_MANAGE attempts to download Alice\'s encrypted file without share...');
  
  // Alice uploads File A
  const samplePlaintext = Buffer.from('CYCLE 10.1 CONFIDENTIAL FILE CONTENT');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Confidential_Cycle10.pdf',
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
  }, fileCiphertext, 'Confidential_Cycle10.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Bob has ROLE_MANAGE & USER_MANAGE permissions, but NO explicit share on Alice's file
  const bobDlRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': bobDeviceId });
  console.log(`  HTTP Result: ${bobDlRes.status} (${bobDlRes.data.message})`);
  if (bobDlRes.status !== 403) {
    throw new Error(`FAIL: Expected HTTP 403 Access Denied, got status ${bobDlRes.status}`);
  }
  console.log('✅ TEST 5 PASSED: Security invariant verified! Admin/Management privileges do NOT grant file access!');

  // --- TEST 6: Organization Isolation for Custom Roles ---
  console.log('\n[TEST 6] Testing Organization Isolation: External Eve attempts to list/modify Alice\'s org roles...');
  const eveRoleAccess = await request('GET', '/api/roles', null, { 'Authorization': `Bearer ${eveToken}`, 'X-Client-Device-ID': eveDeviceId });
  const eveRoles = eveRoleAccess.data.roles.map(r => r.id);
  if (eveRoles.includes(auditorRoleId)) {
    throw new Error('CRITICAL SECURITY FAILURE: External user was able to view another organization\'s custom role!');
  }

  const eveAssignAttempt = await request('PUT', `/api/users/${bobId}/roles`, {
    roleIds: [memberRole.id],
  }, { 'Authorization': `Bearer ${eveToken}`, 'X-Client-Device-ID': eveDeviceId });

  console.log(`  Cross-Org Role Assign Result: ${eveAssignAttempt.status} (${eveAssignAttempt.data.message})`);
  if (eveAssignAttempt.status !== 403) {
    throw new Error('FAIL: Cross-organization role assignment attempt was not rejected with HTTP 403');
  }
  console.log('✅ TEST 6 PASSED: Organization isolation strictly enforced for custom roles!');

  // --- TEST 7: Custom Role Deletion ---
  console.log('\n[TEST 7] Testing custom role deletion (Auditor) & preventing system role deletion...');
  const deleteSystemRole = await request('DELETE', `/api/roles/${adminRole.id}`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  if (deleteSystemRole.status !== 400) throw new Error('FAIL: Deleting system Admin role should be rejected');

  const deleteCustomRole = await request('DELETE', `/api/roles/${auditorRoleId}`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  if (deleteCustomRole.status !== 200) throw new Error('FAIL: Custom role deletion failed');
  console.log('✅ TEST 7 PASSED: Custom role deletion verified and default system roles protected!');

  console.log('\n================================================================');
  console.log('🎉 ALL 7 CYCLE 10.1 STRENGTHENED RBAC INTEGRATION TESTS PASSED!');
  console.log('================================================================');
  process.exit(0);
}

runCycle10_1TestSuite().catch(err => {
  console.error('\n❌ CYCLE 10.1 TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
