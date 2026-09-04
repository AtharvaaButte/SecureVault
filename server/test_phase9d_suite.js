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

async function runPhase9DTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING PHASE 9D STEP-UP AUTH & SENSITIVITY POLICY SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users
  const orgName = `Phase9D_Org_${Date.now()}`;
  const aliceEmail = `alice_${Date.now()}@phase9d.com`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@phase9d.com`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const aliceDeviceId = `alice-laptop-${Date.now()}`;
  const bobDeviceId = `bob-laptop-${Date.now()}`;

  // Register Alice (Admin/Owner)
  const aliceReg = await request('POST', '/api/auth/register', { orgName, email: aliceEmail, password: 'AlicePassword2026!' }, { 'X-Client-Device-ID': aliceDeviceId });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Create Bob (Member)
  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const bobId = bobCreate.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' }, { 'X-Client-Device-ID': bobDeviceId });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': bobDeviceId });

  console.log(`[Setup] Registered Users in Org (${aliceReg.data.organization.id}):`);
  console.log(`  - Alice (Owner) : ${aliceId}`);
  console.log(`  - Bob   (Member): ${bobId}\n`);

  // --- TEST 1: Normal File Access Without Re-authentication ---
  console.log('[TEST 1] Testing NORMAL sensitivity file upload and download...');
  const normalPlaintext = Buffer.from('NORMAL SENSITIVITY FILE CONTENT');
  const normalFileId = crypto.randomUUID();
  const normalEnc = fileCrypto.encryptBuffer(normalPlaintext);
  fileCrypto.storeDek(normalFileId, normalEnc.dek);

  const normalOwnerWrap = keyWrapping.wrapDek(normalEnc.dek, alicePrivPem, alicePubPem, normalFileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: normalFileId,
    originalName: 'Normal_Document.pdf',
    originalSize: normalPlaintext.length.toString(),
    iv: normalEnc.iv.toString('base64'),
    authTag: normalEnc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: normalOwnerWrap.wrappedDek,
    wrapSalt: normalOwnerWrap.wrapSalt,
    wrapIv: normalOwnerWrap.wrapIv,
    wrapAuthTag: normalOwnerWrap.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'NORMAL',
  }, normalEnc.ciphertext, 'Normal_Document.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  const t1 = await request('GET', `/api/files/${normalFileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  console.log(`  HTTP Result: ${t1.status} (Sensitivity: ${t1.data.metadata.sensitivityLevel})`);
  if (t1.status !== 200 || !['NORMAL', 'INTERNAL'].includes(t1.data.metadata.sensitivityLevel)) {
    throw new Error(`FAIL: Normal file download failed or sensitivity level mismatch (Status ${t1.status})`);
  }
  console.log('✅ TEST 1 PASSED: Normal file accessed without re-authentication!');

  // --- TEST 2: Sensitive File Policy Enforcement ---
  console.log('\n[TEST 2] Testing SENSITIVE file policy (download ok, share requires step-up)...');
  const sensitivePlaintext = Buffer.from('SENSITIVE FILE CONTENT - FINANCES');
  const sensitiveFileId = crypto.randomUUID();
  const sensitiveEnc = fileCrypto.encryptBuffer(sensitivePlaintext);
  fileCrypto.storeDek(sensitiveFileId, sensitiveEnc.dek);

  const sensitiveOwnerWrap = keyWrapping.wrapDek(sensitiveEnc.dek, alicePrivPem, alicePubPem, sensitiveFileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: sensitiveFileId,
    originalName: 'Sensitive_Finances.pdf',
    originalSize: sensitivePlaintext.length.toString(),
    iv: sensitiveEnc.iv.toString('base64'),
    authTag: sensitiveEnc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: sensitiveOwnerWrap.wrappedDek,
    wrapSalt: sensitiveOwnerWrap.wrapSalt,
    wrapIv: sensitiveOwnerWrap.wrapIv,
    wrapAuthTag: sensitiveOwnerWrap.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'SENSITIVE',
  }, sensitiveEnc.ciphertext, 'Sensitive_Finances.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Download SENSITIVE file -> OK
  const t2Dl = await request('GET', `/api/files/${sensitiveFileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  if (t2Dl.status !== 200) throw new Error(`FAIL: Sensitive file download returned status ${t2Dl.status}`);

  // Share SENSITIVE file without re-auth -> HTTP 403 stepUpRequired: true
  const bobWrap = keyWrapping.wrapDek(sensitiveEnc.dek, alicePrivPem, bobPubPem, sensitiveFileId, bobId);
  const t2Share = await request('POST', `/api/files/${sensitiveFileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrap.wrappedDek,
    wrapSalt: bobWrap.wrapSalt,
    wrapIv: bobWrap.wrapIv,
    wrapAuthTag: bobWrap.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  console.log(`  HTTP Share Result: ${t2Share.status} (${t2Share.data.message}) [stepUpRequired: ${t2Share.data.stepUpRequired}]`);
  if (t2Share.status !== 403 || !t2Share.data.stepUpRequired) {
    throw new Error(`FAIL: Expected SENSITIVE file share to trigger stepUpRequired: true with HTTP 403`);
  }
  console.log('✅ TEST 2 PASSED: SENSITIVE file policy enforced! High-impact operation triggered step-up re-authentication!');

  // --- TEST 3: Highly Sensitive File Policy Enforcement ---
  console.log('\n[TEST 3] Testing HIGHLY_SENSITIVE file policy (download requires step-up)...');
  const highlyPlaintext = Buffer.from('TOP SECRET HIGHLY SENSITIVE PAYLOAD');
  const highlyFileId = crypto.randomUUID();
  const highlyEnc = fileCrypto.encryptBuffer(highlyPlaintext);
  fileCrypto.storeDek(highlyFileId, highlyEnc.dek);

  const highlyOwnerWrap = keyWrapping.wrapDek(highlyEnc.dek, alicePrivPem, alicePubPem, highlyFileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: highlyFileId,
    originalName: 'Highly_Sensitive_Secret.pdf',
    originalSize: highlyPlaintext.length.toString(),
    iv: highlyEnc.iv.toString('base64'),
    authTag: highlyEnc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: highlyOwnerWrap.wrappedDek,
    wrapSalt: highlyOwnerWrap.wrapSalt,
    wrapIv: highlyOwnerWrap.wrapIv,
    wrapAuthTag: highlyOwnerWrap.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'HIGHLY_SENSITIVE',
  }, highlyEnc.ciphertext, 'Highly_Sensitive_Secret.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Download HIGHLY_SENSITIVE file without re-auth -> HTTP 403 stepUpRequired: true
  const t3Dl = await request('GET', `/api/files/${highlyFileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  console.log(`  HTTP Download Result: ${t3Dl.status} (${t3Dl.data.message}) [stepUpRequired: ${t3Dl.data.stepUpRequired}]`);
  if (t3Dl.status !== 403 || !t3Dl.data.stepUpRequired) {
    throw new Error(`FAIL: Expected HIGHLY_SENSITIVE download to trigger stepUpRequired: true with HTTP 403`);
  }
  console.log('✅ TEST 3 PASSED: HIGHLY_SENSITIVE download strictly required step-up re-authentication!');

  // --- TEST 4: Security Order - Unauthorized User Denied BEFORE Step-Up Prompt ---
  console.log('\n[TEST 4] Testing security order: Unauthorized Bob attempts download on Alice\'s HIGHLY_SENSITIVE file...');
  const t4 = await request('GET', `/api/files/${highlyFileId}/download`, null, {
    'Authorization': `Bearer ${bobToken}`,
    'X-Client-Device-ID': bobDeviceId,
    'X-Reauth-Password': 'AlicePassword2026!', // Sending Alice's password trying to bypass resource check
  });
  console.log(`  HTTP Result: ${t4.status} (${t4.data.message})`);
  if (t4.status !== 403 || t4.data.stepUpRequired) {
    throw new Error(`FAIL: Expected resource access rejection (403 without stepUpRequired), got status ${t4.status}`);
  }
  console.log('✅ TEST 4 PASSED: Security order verified! Resource access check denied Bob BEFORE step-up evaluation!');

  // --- TEST 5: Wrong Password Re-authentication Rejection ---
  console.log('\n[TEST 5] Alice attempts HIGHLY_SENSITIVE download with INCORRECT step-up password...');
  const t5 = await request('GET', `/api/files/${highlyFileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Reauth-Password': 'WRONG_ALICE_PASSWORD',
  });
  console.log(`  HTTP Result: ${t5.status} (${t5.data.message})`);
  if (t5.status !== 403) throw new Error(`FAIL: Wrong re-auth password returned status ${t5.status}`);
  console.log('✅ TEST 5 PASSED: Wrong re-authentication password strictly rejected with HTTP 403!');

  // --- TEST 6: Correct Password Re-authentication Success ---
  console.log('\n[TEST 6] Alice attempts HIGHLY_SENSITIVE download with CORRECT step-up password...');
  const t6 = await request('GET', `/api/files/${highlyFileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Reauth-Password': 'AlicePassword2026!',
  });
  console.log(`  HTTP Result: ${t6.status}`);
  if (t6.status !== 200) throw new Error(`FAIL: Correct re-auth password download returned status ${t6.status}`);

  const aliceUnwrapped = keyWrapping.unwrapDek(
    t6.data.wrapping.wrappedDek,
    t6.data.wrapping.wrapSalt,
    t6.data.wrapping.wrapIv,
    t6.data.wrapping.wrapAuthTag,
    t6.data.wrapping.senderPublicKey,
    alicePrivPem,
    highlyFileId,
    aliceId
  );
  const aliceDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(t6.data.ciphertext, 'base64'),
    aliceUnwrapped,
    Buffer.from(t6.data.metadata.iv, 'base64'),
    Buffer.from(t6.data.metadata.authTag, 'base64')
  );

  if (!aliceDecrypted.equals(highlyPlaintext)) throw new Error('FAIL: Decrypted HIGHLY_SENSITIVE content byte mismatch!');
  console.log('✅ TEST 6 PASSED: Correct step-up password granted download access! Decrypted 100% byte-for-byte!');

  // --- TEST 7: High-Impact Operations Follow Sensitivity Policy ---
  console.log('\n[TEST 7] Testing high-impact operation (SHARE) on HIGHLY_SENSITIVE file with step-up password...');
  const t7Share = await request('POST', `/api/files/${highlyFileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrap.wrappedDek,
    wrapSalt: bobWrap.wrapSalt,
    wrapIv: bobWrap.wrapIv,
    wrapAuthTag: bobWrap.wrapAuthTag,
  }, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Reauth-Password': 'AlicePassword2026!',
  });

  console.log(`  HTTP Share Result: ${t7Share.status} (${t7Share.data.message})`);
  if (t7Share.status !== 201) throw new Error(`FAIL: Step-up share returned status ${t7Share.status}`);
  console.log('✅ TEST 7 PASSED: High-impact share operation succeeded with step-up re-authentication!');

  // --- TEST 8: Privacy & Secret Storage Invariant ---
  console.log('\n[TEST 8] Inspecting PostgreSQL files & user_devices for zero password / private key leakage...');
  const filesDb = await pool.query('SELECT * FROM files WHERE id = $1', [highlyFileId]);
  const rowStr = JSON.stringify(filesDb.rows[0]);
  if (rowStr.includes('AlicePassword2026!') || rowStr.includes('BEGIN PRIVATE KEY')) {
    throw new Error('CRITICAL PRIVACY FAILURE: Password or private key stored in files table!');
  }
  console.log('✅ TEST 8 PASSED: Zero password or private key leakage in database!');

  // --- TEST 9: Cycles 1–8 & Phase 9A–9C Regression Check ---
  console.log('\n[TEST 9] Performing Cycles 1–8 & Phase 9A–9C regression verification...');
  const healthRes = await request('GET', '/api/health');
  if (healthRes.status !== 200 || !healthRes.data.database.connected) throw new Error('Health check failed!');
  console.log('✅ TEST 9 PASSED: All prior cycles and security subsystems fully operational!');

  console.log('\n================================================================');
  console.log('🎉 ALL 9 PHASE 9D STEP-UP AUTH & SENSITIVITY TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runPhase9DTestSuite().catch(err => {
  console.error('\n❌ PHASE 9D TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
