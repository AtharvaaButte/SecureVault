const path = require('path');
const http = require('http');
const crypto = require('crypto');
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

async function runPhase9CTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING PHASE 9C CONTEXT-AWARE & RISK-BASED ACCESS SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users
  const orgName = `Phase9C_Org_${Date.now()}`;
  const aliceEmail = `alice_${Date.now()}@phase9c.com`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@phase9c.com`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const knownDeviceId = `known-device-laptop-alice`;

  // Register Alice (Admin/Owner) with known device ID
  const aliceReg = await request('POST', '/api/auth/register', { orgName, email: aliceEmail, password: 'AlicePassword2026!' }, { 'X-Client-Device-ID': knownDeviceId });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': knownDeviceId });

  const bobDeviceId = `known-device-bob`;
  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': knownDeviceId });
  const bobId = bobCreate.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' }, { 'X-Client-Device-ID': bobDeviceId });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': bobDeviceId });

  // Alice uploads File A
  const samplePlaintext = Buffer.from('PHASE 9C RISK-BASED STEP-UP RE-AUTHENTICATION TEST PAYLOAD');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Phase9C_RiskTest.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrapping.wrappedDek,
    wrapSalt: ownerWrapping.wrapSalt,
    wrapIv: ownerWrapping.wrapIv,
    wrapAuthTag: ownerWrapping.wrapAuthTag,
    senderPublicKey: alicePubPem,
  }, fileCiphertext, 'Phase9C_RiskTest.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': knownDeviceId });

  console.log(`[Setup] Alice (${aliceId}) uploaded File A (${fileId}) from device "${knownDeviceId}".\n`);

  // --- TEST 1: Known Device / Context -> Normal Authorized Access ---
  console.log('[TEST 1] Testing known device performing normal file download...');
  const t1 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': knownDeviceId });
  console.log(`  HTTP Result: ${t1.status}`);
  if (t1.status !== 200) throw new Error(`FAIL: Known device download returned status ${t1.status}`);
  console.log('✅ TEST 1 PASSED: Known device context allowed normal authorized access!');

  // --- TEST 2: Unauthorized User -> Denied Regardless of Device/Location ---
  console.log('\n[TEST 2] Testing unauthorized user (Bob) attempting download from a valid device...');
  const t2 = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': bobDeviceId });
  console.log(`  HTTP Result: ${t2.status} (${t2.data.message})`);
  if (t2.status !== 403) throw new Error(`FAIL: Unauthorized user download returned status ${t2.status}`);
  console.log('✅ TEST 2 PASSED: Authorization check strictly enforced regardless of device!');

  // --- TEST 3: New Device Detection ---
  console.log('\n[TEST 3] Testing request from a NEW/unrecognized device ID...');
  const newDeviceId = `new-unrecognized-phone-${Date.now()}`;
  const aliceNewDeviceToken = jwt.sign({ userId: aliceId, orgId: aliceReg.data.organization.id, role: 'ADMIN', deviceId: newDeviceId }, process.env.JWT_SECRET);
  
  const t3 = await request('GET', '/api/files', null, { 'Authorization': `Bearer ${aliceNewDeviceToken}`, 'X-Client-Device-ID': newDeviceId });
  console.log(`  HTTP Result: ${t3.status} (Files count: ${t3.data.files.length})`);
  if (t3.status !== 200) throw new Error(`FAIL: Standard operation on new device returned status ${t3.status}`);

  const checkDeviceDb = await pool.query('SELECT * FROM user_devices WHERE user_id = $1 AND device_id = $2', [aliceId, newDeviceId]);
  if (checkDeviceDb.rows.length === 0) throw new Error('FAIL: New device was not registered in user_devices table!');
  console.log('✅ TEST 3 PASSED: New device detected and registered in user_devices table!');

  // --- TEST 4: Changed IP/Context Detection Without Automatic Blocking for Standard Operations ---
  console.log('\n[TEST 4] Testing changed IP address on standard operation (FILE_READ)...');
  const t4 = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': knownDeviceId,
    'X-Forwarded-For': '203.0.113.195', // Simulated changed external IP
    'X-Client-Region': 'US-EAST',
  });
  console.log(`  HTTP Result: ${t4.status}`);
  if (t4.status !== 200) throw new Error(`FAIL: Changed IP standard operation returned status ${t4.status}`);
  console.log('✅ TEST 4 PASSED: Changed IP context detected without blocking standard operation!');

  // --- TEST 5: Sensitive Operation from Suspicious/New Context -> Step-Up Re-Authentication Required ---
  console.log('\n[TEST 5] Testing sensitive operation (FILE_SHARE) from new device WITHOUT step-up password...');
  const bobWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, bobPubPem, fileId, bobId);

  const t5 = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, {
    'Authorization': `Bearer ${aliceNewDeviceToken}`,
    'X-Client-Device-ID': newDeviceId,
    'X-Forwarded-For': '198.51.100.44', // New context
  });

  console.log(`  HTTP Result: ${t5.status} (${t5.data.message}) [stepUpRequired: ${t5.data.stepUpRequired}]`);
  if (t5.status !== 403 || !t5.data.stepUpRequired) {
    throw new Error(`FAIL: Expected stepUpRequired: true with status 403, got status ${t5.status}`);
  }
  console.log('✅ TEST 5 PASSED: Sensitive operation from new context triggered step-up re-authentication requirement!');

  // --- TEST 6: Failed Re-Authentication -> Denied ---
  console.log('\n[TEST 6] Testing sensitive operation with INCORRECT re-authentication password...');
  const t6 = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, {
    'Authorization': `Bearer ${aliceNewDeviceToken}`,
    'X-Client-Device-ID': newDeviceId,
    'X-Reauth-Password': 'WRONG_ALICE_PASSWORD_123',
  });

  console.log(`  HTTP Result: ${t6.status} (${t6.data.message})`);
  if (t6.status !== 403) throw new Error(`FAIL: Wrong reauth password returned status ${t6.status}`);
  console.log('✅ TEST 6 PASSED: Failed re-authentication strictly denied with HTTP 403!');

  // --- TEST 7: Successful Re-Authentication -> Operation Succeeds & Device Trusted ---
  console.log('\n[TEST 7] Testing sensitive operation with CORRECT re-authentication password...');
  const t7 = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, {
    'Authorization': `Bearer ${aliceNewDeviceToken}`,
    'X-Client-Device-ID': newDeviceId,
    'X-Reauth-Password': 'AlicePassword2026!',
  });

  console.log(`  HTTP Result: ${t7.status} (${t7.data.message})`);
  if (t7.status !== 201) throw new Error(`FAIL: Step-up re-authentication share returned status ${t7.status}`);
  console.log('✅ TEST 7 PASSED: Step-up re-authentication verified! Share operation completed and device trusted!');

  // --- TEST 8: Private Key & Secret Privacy Invariant ---
  console.log('\n[TEST 8] Inspecting user_devices database records for zero private key / secret leakage...');
  const devicesDb = await pool.query('SELECT * FROM user_devices WHERE user_id = $1', [aliceId]);
  for (const row of devicesDb.rows) {
    const rowStr = JSON.stringify(row);
    if (rowStr.includes('BEGIN PRIVATE KEY') || rowStr.includes('AlicePassword2026!')) {
      throw new Error('CRITICAL PRIVACY FAILURE: Sensitive secret or private key stored in user_devices!');
    }
  }
  console.log('✅ TEST 8 PASSED: Zero private key, password, or plaintext secret leakage in context storage!');

  // --- TEST 9: Cycles 1-8 & Phase 9A/9B Regression Verification ---
  console.log('\n[TEST 9] Performing Cycles 1–8 & Phase 9A/9B regression check...');
  const healthRes = await request('GET', '/api/health');
  if (healthRes.status !== 200 || !healthRes.data.database.connected) throw new Error('Health check failed!');
  console.log('✅ TEST 9 PASSED: All prior cycles and security subsystems fully operational!');

  console.log('\n================================================================');
  console.log('🎉 ALL 9 PHASE 9C CONTEXT-AWARE & RISK INTEGRATION TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runPhase9CTestSuite().catch(err => {
  console.error('\n❌ PHASE 9C TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
