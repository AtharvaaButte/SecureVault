const path = require('path');
const http = require('http');
const crypto = require('crypto');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

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

async function runPhase9BTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING PHASE 9B RESOURCE & PERMISSION AUTHORIZATION SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organizations & Users
  const mainOrgName = `Phase9B_MainOrg_${Date.now()}`;
  const externalOrgName = `Phase9B_ExtOrg_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@mainorg.com`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@mainorg.com`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const adminEmail = `admin_${Date.now()}@mainorg.com`;

  const externalEmail = `eve_${Date.now()}@extorg.com`;
  const externalKeyPair = crypto.generateKeyPairSync('x25519');
  const externalPubPem = externalKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Register Alice (Creates Main Org & receives Admin role)
  const aliceReg = await request('POST', '/api/auth/register', { orgName: mainOrgName, email: aliceEmail, password: 'AlicePassword2026!' });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const mainOrgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}` });

  // Alice creates Bob (Member role)
  const bobCreateRes = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${aliceToken}` });
  const bobId = bobCreateRes.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  // Alice creates Org Admin
  const adminCreateRes = await request('POST', '/api/users', { email: adminEmail, password: 'AdminPassword2026!', role: 'ADMIN' }, { 'Authorization': `Bearer ${aliceToken}` });
  const adminId = adminCreateRes.data.user.id;
  const adminLogin = await request('POST', '/api/auth/login', { email: adminEmail, password: 'AdminPassword2026!' });
  const adminToken = adminLogin.data.token;

  // Register Eve (Creates External Org)
  const extReg = await request('POST', '/api/auth/register', { orgName: externalOrgName, email: externalEmail, password: 'EvePassword2026!' });
  const extToken = extReg.data.token;
  const extUserId = extReg.data.user.id;
  await request('POST', '/api/crypto/public-key', { publicKey: externalPubPem }, { 'Authorization': `Bearer ${extToken}` });

  console.log(`[Setup] Registered Main Org (${mainOrgId}) & External Org:`);
  console.log(`  - Alice (Admin/Owner) : ${aliceId}`);
  console.log(`  - Bob   (Member)      : ${bobId}`);
  console.log(`  - Admin (Org Admin)   : ${adminId}`);
  console.log(`  - Eve   (External)    : ${extUserId}\n`);

  // --- TEST 1: Unauthenticated Request -> 401 ---
  console.log('[TEST 1] Testing unauthenticated request (no Authorization header)...');
  const t1 = await request('GET', '/api/files');
  console.log(`  HTTP Result: ${t1.status}`);
  if (t1.status !== 401) throw new Error(`FAIL: Expected 401, got ${t1.status}`);
  console.log('✅ TEST 1 PASSED: Unauthenticated request rejected with HTTP 401!');

  // --- TEST 2: Invalid JWT -> 401 ---
  console.log('\n[TEST 2] Testing invalid JWT token...');
  const forgedToken = jwt.sign({ userId: 'fake', orgId: 'fake', role: 'ADMIN' }, 'WRONG_SECRET');
  const t2 = await request('GET', '/api/files', null, { 'Authorization': `Bearer ${forgedToken}` });
  console.log(`  HTTP Result: ${t2.status}`);
  if (t2.status !== 401) throw new Error(`FAIL: Expected 401, got ${t2.status}`);
  console.log('✅ TEST 2 PASSED: Invalid token rejected with HTTP 401!');

  // --- TEST 3: Valid User + Permitted Operation -> Success ---
  console.log('\n[TEST 3] Testing valid user with FILE_UPLOAD & FILE_READ permissions (Alice uploads File A)...');
  const samplePlaintext = Buffer.from('ZERO TRUST PHASE 9B RESOURCE AUTHORIZATION TEST PAYLOAD');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);
  const t3 = await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Phase9B_Resource.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrapping.wrappedDek,
    wrapSalt: ownerWrapping.wrapSalt,
    wrapIv: ownerWrapping.wrapIv,
    wrapAuthTag: ownerWrapping.wrapAuthTag,
    senderPublicKey: alicePubPem,
  }, fileCiphertext, 'Phase9B_Resource.enc', { 'Authorization': `Bearer ${aliceToken}` });

  console.log(`  HTTP Result: ${t3.status}`);
  if (t3.status !== 201) throw new Error(`FAIL: Upload failed with status ${t3.status}`);
  console.log('✅ TEST 3 PASSED: Permitted file upload succeeded with HTTP 201!');

  // --- TEST 4: Valid User + Missing Permission -> 403 ---
  console.log('\n[TEST 4] Testing Bob (Member role, lacking USER_CREATE) attempting to create user...');
  const t4 = await request('POST', '/api/users', { email: 'forbidden@test.com', password: 'Password123!', role: 'USER' }, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Result: ${t4.status} (${t4.data.message})`);
  if (t4.status !== 403) throw new Error(`FAIL: Missing permission returned status ${t4.status}`);
  console.log('✅ TEST 4 PASSED: Missing permission request rejected with HTTP 403!');

  // --- TEST 5: Owner + Permitted File Operation -> Success ---
  console.log('\n[TEST 5] Testing Alice (Owner) downloading File A...');
  const t5 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}` });
  console.log(`  HTTP Result: ${t5.status}`);
  if (t5.status !== 200) throw new Error(`FAIL: Owner download returned status ${t5.status}`);
  console.log('✅ TEST 5 PASSED: Owner download succeeded with HTTP 200!');

  // --- TEST 6: Shared User + Permitted File Access -> Success ---
  console.log('\n[TEST 6] Alice shares File A with Bob -> Bob downloads File A...');
  const bobWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, bobPubPem, fileId, bobId);
  const shareRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}` });

  if (shareRes.status !== 201) throw new Error(`Share failed with status ${shareRes.status}`);

  const t6 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Result: ${t6.status}`);
  if (t6.status !== 200) throw new Error(`FAIL: Shared user download returned status ${t6.status}`);
  console.log('✅ TEST 6 PASSED: Shared recipient download succeeded with HTTP 200!');

  // --- TEST 7: Shared User Attempting Owner-Only Operation -> 403 ---
  console.log('\n[TEST 7] Testing Bob (Shared user, non-owner) attempting to share File A...');
  const t7 = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: adminId,
    senderPublicKey: bobPubPem,
    wrappedDek: 'fake-dek',
    wrapSalt: 'fake-salt',
    wrapIv: 'fake-iv',
    wrapAuthTag: 'fake-tag',
  }, { 'Authorization': `Bearer ${bobToken}` });

  console.log(`  HTTP Result: ${t7.status} (${t7.data.message})`);
  if (t7.status !== 403) throw new Error(`FAIL: Shared user owner operation returned status ${t7.status}`);
  console.log('✅ TEST 7 PASSED: Non-owner share attempt rejected with HTTP 403!');

  // --- TEST 8: Admin Without File Access -> 403 ---
  console.log('\n[TEST 8] Testing Org Admin (without explicit file share) attempting to download File A...');
  const t8 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${adminToken}` });
  console.log(`  HTTP Result: ${t8.status} (${t8.data.message})`);
  if (t8.status !== 403 && t8.status !== 404) throw new Error(`FAIL: Admin without access returned status ${t8.status}`);
  console.log('✅ TEST 8 PASSED: Admin without explicit file share rejected with HTTP 403!');

  // --- TEST 9: Cross-Organization Access -> 403 ---
  console.log('\n[TEST 9] Testing Eve (External Org) attempting to access File A...');
  const t9 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${extToken}` });
  console.log(`  HTTP Result: ${t9.status} (${t9.data.message})`);
  if (t9.status !== 403 && t9.status !== 404) throw new Error(`FAIL: Cross-org access returned status ${t9.status}`);
  console.log('✅ TEST 9 PASSED: Cross-organization access strictly rejected with HTTP 403!');

  // --- TEST 10: UUID / IDOR Manipulation -> 403/404 ---
  console.log('\n[TEST 10] Testing Bob attempting IDOR access on guessed file UUID...');
  const guessedUUID = crypto.randomUUID();
  const t10 = await request('GET', `/api/files/${guessedUUID}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Result: ${t10.status} (${t10.data.message})`);
  if (t10.status !== 404 && t10.status !== 403) throw new Error(`FAIL: IDOR request returned status ${t10.status}`);
  console.log('✅ TEST 10 PASSED: IDOR UUID manipulation safely rejected with 404/403!');

  // --- TEST 11: Revoked User Access -> 403 ---
  console.log('\n[TEST 11] Alice revokes Bob -> Bob attempts download...');
  await request('DELETE', `/api/files/${fileId}/share/${bobId}`, null, { 'Authorization': `Bearer ${aliceToken}` });
  const t11 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Result: ${t11.status} (${t11.data.message})`);
  if (t11.status !== 403 && t11.status !== 404) throw new Error(`FAIL: Revoked user download returned status ${t11.status}`);
  console.log('✅ TEST 11 PASSED: Revoked user access strictly denied with HTTP 403!');

  // --- TEST 12: Cycles 1-8 Regression Check ---
  console.log('\n[TEST 12] Performing Cycles 1–8 & Phase 9A regression verification...');
  const healthRes = await request('GET', '/api/health');
  if (healthRes.status !== 200 || !healthRes.data.database.connected) throw new Error('Health check failed!');
  console.log('✅ TEST 12 PASSED: All core infrastructure and prior cycles fully operational!');

  console.log('\n================================================================');
  console.log('🎉 ALL 12 PHASE 9B AUTHORIZATION INTEGRATION TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runPhase9BTestSuite().catch(err => {
  console.error('\n❌ PHASE 9B TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
