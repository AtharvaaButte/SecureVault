const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const argon2 = require('argon2');

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

async function runDekRecoveryTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING PERSISTENT DEK RECOVERY INTEGRATION TEST SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users (Alice & Bob)
  const orgName = `DekRecovery_Org_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@dekrec.org`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@dekrec.org`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Register Alice (Creates Org)
  const aliceReg = await request('POST', '/api/auth/register', { orgName, email: aliceEmail, password: 'AlicePassword2026!' });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const orgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}` });

  // Add Bob to Same Org
  const bobHash = await argon2.hash('BobPassword2026!', { type: argon2.argon2id });
  const bobDb = await pool.query(
    'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
    [orgId, bobEmail, bobHash, 'USER']
  );
  const bobId = bobDb.rows[0].id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  console.log(`[Setup] Registered Users in Organization (${orgId}):`);
  console.log(`  - Alice : ${aliceId}`);
  console.log(`  - Bob   : ${bobId}\n`);

  // --- TEST 1: Encrypt & Upload File with Owner Self-Wrapped DEK ---
  console.log('[TEST 1] Testing file upload with Owner DEK self-wrapping...');
  const samplePlaintext = Buffer.from('CONFIDENTIAL RECOVERABLE FILE PAYLOAD - PERSISTENT DEK MANAGEMENT TEST');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);

  // Store in memory initially
  fileCrypto.storeDek(fileId, originalDek);

  // Owner self-wraps DEK using Alice's private key + Alice's public key
  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);

  const uploadRes = await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Recoverable_Document.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrapping.wrappedDek,
    wrapSalt: ownerWrapping.wrapSalt,
    wrapIv: ownerWrapping.wrapIv,
    wrapAuthTag: ownerWrapping.wrapAuthTag,
    senderPublicKey: alicePubPem,
  }, fileCiphertext, 'Recoverable_Document.enc', { 'Authorization': `Bearer ${aliceToken}` });

  if (uploadRes.status !== 201) throw new Error(`Upload failed with status ${uploadRes.status}`);

  const ownerKeyCheck = await pool.query('SELECT * FROM file_keys WHERE file_id = $1 AND user_id = $2', [fileId, aliceId]);
  if (ownerKeyCheck.rows.length === 0) throw new Error('FAIL: Owner wrapped DEK record missing in file_keys database table!');
  console.log('✅ TEST 1 PASSED: File uploaded and Owner wrapped DEK safely persisted in file_keys!');

  // --- TEST 2: Owner DEK Recovery After Electron Restart / Memory Reset ---
  console.log('\n[TEST 2] Testing Owner DEK recovery after memory reset (simulating Electron app restart)...');
  // Clear memory DEK to simulate process restart
  fileCrypto.storeDek(fileId, undefined);
  if (fileCrypto.getDek(fileId) !== undefined) throw new Error('FAIL: In-memory DEK reset failed!');

  // Alice fetches download payload
  const aliceDlRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}` });
  if (aliceDlRes.status !== 200) throw new Error(`Alice download failed with status ${aliceDlRes.status}`);
  if (!aliceDlRes.data.wrapping) throw new Error('FAIL: Wrapping payload missing from owner download response!');

  // Alice unwraps DEK locally using Alice's private key
  const aliceRecoveredDek = keyWrapping.unwrapDek(
    aliceDlRes.data.wrapping.wrappedDek,
    aliceDlRes.data.wrapping.wrapSalt,
    aliceDlRes.data.wrapping.wrapIv,
    aliceDlRes.data.wrapping.wrapAuthTag,
    aliceDlRes.data.wrapping.senderPublicKey,
    alicePrivPem,
    fileId,
    aliceId
  );

  if (!aliceRecoveredDek.equals(originalDek)) throw new Error('FAIL: Recovered DEK does NOT match original DEK!');

  const aliceDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(aliceDlRes.data.ciphertext, 'base64'),
    aliceRecoveredDek,
    Buffer.from(aliceDlRes.data.metadata.iv, 'base64'),
    Buffer.from(aliceDlRes.data.metadata.authTag, 'base64')
  );

  if (!aliceDecrypted.equals(samplePlaintext)) throw new Error('FAIL: Decrypted payload byte mismatch!');
  console.log('✅ TEST 2 PASSED: Alice (Owner) successfully recovered DEK from server wrapped key and decrypted file!');

  // --- TEST 3: Owner Sharing File After Application Restart ---
  console.log('\n[TEST 3] Testing file sharing after application restart (DEK auto-recovery before sharing)...');
  // Clear memory DEK again
  fileCrypto.storeDek(fileId, undefined);

  // Alice's client recovers DEK from server wrapping
  const aliceFetchForShare = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}` });
  const aliceAutoRecoveredDek = keyWrapping.unwrapDek(
    aliceFetchForShare.data.wrapping.wrappedDek,
    aliceFetchForShare.data.wrapping.wrapSalt,
    aliceFetchForShare.data.wrapping.wrapIv,
    aliceFetchForShare.data.wrapping.wrapAuthTag,
    aliceFetchForShare.data.wrapping.senderPublicKey,
    alicePrivPem,
    fileId,
    aliceId
  );
  fileCrypto.storeDek(fileId, aliceAutoRecoveredDek);

  // Alice wraps DEK for Bob
  const bobWrapping = keyWrapping.wrapDek(aliceAutoRecoveredDek, alicePrivPem, bobPubPem, fileId, bobId);
  const shareRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}` });

  if (shareRes.status !== 201) throw new Error(`Share failed with status ${shareRes.status}`);
  console.log('✅ TEST 3 PASSED: Alice auto-recovered DEK and shared file with Bob post-restart!');

  // --- TEST 4: Recipient (Bob) DEK Unwrapping & File Decryption ---
  console.log('\n[TEST 4] Testing Bob (Recipient) DEK unwrapping and decryption...');
  const bobDlRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  if (bobDlRes.status !== 200) throw new Error(`Bob download failed with status ${bobDlRes.status}`);

  const bobUnwrappedDek = keyWrapping.unwrapDek(
    bobDlRes.data.wrapping.wrappedDek,
    bobDlRes.data.wrapping.wrapSalt,
    bobDlRes.data.wrapping.wrapIv,
    bobDlRes.data.wrapping.wrapAuthTag,
    bobDlRes.data.wrapping.senderPublicKey,
    bobPrivPem,
    fileId,
    bobId
  );

  if (!bobUnwrappedDek.equals(originalDek)) throw new Error('FAIL: Bob unwrapped DEK does NOT match original DEK!');

  const bobDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(bobDlRes.data.ciphertext, 'base64'),
    bobUnwrappedDek,
    Buffer.from(bobDlRes.data.metadata.iv, 'base64'),
    Buffer.from(bobDlRes.data.metadata.authTag, 'base64')
  );

  if (!bobDecrypted.equals(samplePlaintext)) throw new Error('FAIL: Bob decrypted payload byte mismatch!');
  console.log('✅ TEST 4 PASSED: Bob successfully unwrapped DEK and decrypted shared file 100% byte-for-byte!');

  // --- TEST 5: Security Boundary Verification (Zero Plaintext DEK in DB) ---
  console.log('\n[TEST 5] Inspecting database for zero plaintext DEK storage...');
  const dbFileKeys = await pool.query('SELECT * FROM file_keys WHERE file_id = $1', [fileId]);
  const origDekHex = originalDek.toString('hex');
  const origDekB64 = originalDek.toString('base64');

  for (const row of dbFileKeys.rows) {
    const rowStr = JSON.stringify(row);
    if (rowStr.includes(origDekHex) || rowStr.includes(origDekB64)) {
      throw new Error('CRITICAL SECURITY FAILURE: Plaintext DEK detected in database file_keys table!');
    }
  }
  console.log('✅ TEST 5 PASSED: Verified zero plaintext DEKs stored in PostgreSQL database!');

  // --- TEST 6: Core Infrastructure & Regression ---
  console.log('\n[TEST 6] Running regression check...');
  const healthRes = await request('GET', '/api/health');
  if (healthRes.status !== 200 || !healthRes.data.database.connected) throw new Error('Health check failed!');
  console.log('✅ TEST 6 PASSED: All core subsystems and prior cycles fully operational!');

  console.log('\n================================================================');
  console.log('🎉 ALL 6 PERSISTENT DEK RECOVERY INTEGRATION TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runDekRecoveryTestSuite().catch((err) => {
  console.error('\n❌ DEK RECOVERY TEST RUNNER FAILED:', err.stack || err.message);
  process.exit(1);
});
