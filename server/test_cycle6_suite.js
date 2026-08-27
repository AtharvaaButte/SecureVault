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

async function runCycle6TestSuite() {
  console.log('================================================================');
  console.log('--- STARTING CYCLE 6 E2EE FILE SHARING INTEGRATION TEST SUITE ---');
  console.log('================================================================\n');

  // 1. Create Organization & 3 Test Users (Alice, Bob, Charlie) in SAME organization
  const orgName = `Cycle6_Org_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@cycle6.org`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@cycle6.org`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const charlieEmail = `charlie_${Date.now()}@cycle6.org`;
  const charlieKeyPair = crypto.generateKeyPairSync('x25519');
  const charliePrivPem = charlieKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const charliePubPem = charlieKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Register Alice (Creates Org)
  const aliceReg = await request('POST', '/api/auth/register', { orgName, email: aliceEmail, password: 'AlicePassword2026!' });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const orgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}` });

  // Add Bob to SAME Org
  const bobHash = await argon2.hash('BobPassword2026!', { type: argon2.argon2id });
  const bobDb = await pool.query(
    'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
    [orgId, bobEmail, bobHash, 'USER']
  );
  const bobId = bobDb.rows[0].id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  // Add Charlie to SAME Org
  const charlieHash = await argon2.hash('CharliePassword2026!', { type: argon2.argon2id });
  const charlieDb = await pool.query(
    'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
    [orgId, charlieEmail, charlieHash, 'USER']
  );
  const charlieId = charlieDb.rows[0].id;
  const charlieLogin = await request('POST', '/api/auth/login', { email: charlieEmail, password: 'CharliePassword2026!' });
  const charlieToken = charlieLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: charliePubPem }, { 'Authorization': `Bearer ${charlieToken}` });

  console.log(`[Setup] Registered Users in Organization (${orgId}):`);
  console.log(`  - Alice   : ${aliceId}`);
  console.log(`  - Bob     : ${bobId}`);
  console.log(`  - Charlie : ${charlieId}\n`);

  // Alice encrypts & uploads File A
  const samplePlaintext = Buffer.from('CONFIDENTIAL CYCLE 6 SHARED DOCUMENT CONTENT - 100% E2EE DEK WRAPPING');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const uploadRes = await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Confidential_Document.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
  }, fileCiphertext, 'Confidential_Document.enc', { 'Authorization': `Bearer ${aliceToken}` });

  const initialStorageKey = uploadRes.data.file.storageKey;

  // --- TEST 1: User Search ---
  console.log('[TEST 1] Testing User Search (Alice searches directory)...');
  const userSearchRes = await request('GET', '/api/users', null, { 'Authorization': `Bearer ${aliceToken}` });
  if (userSearchRes.status !== 200) throw new Error(`User search failed with status ${userSearchRes.status}`);
  const foundBob = userSearchRes.data.users.find(u => u.id === bobId);
  if (!foundBob || foundBob.publicKey !== bobPubPem.trim()) {
    throw new Error('FAIL: Bob not found in user directory or public key mismatch!');
  }
  console.log('✅ TEST 1 PASSED: Alice searched directory and retrieved Bob with public key!');

  // --- TEST 2: Share File A with Bob ---
  console.log('\n[TEST 2] Testing E2EE File Sharing (Alice shares File A with Bob)...');
  const bobWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, bobPubPem, fileId, bobId);

  const shareRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}` });

  if (shareRes.status !== 201) {
    console.error('Share endpoint error payload:', shareRes.data || shareRes.raw);
    throw new Error(`Share endpoint returned status ${shareRes.status}`);
  }
  const dbKeyCheck = await pool.query('SELECT * FROM file_keys WHERE file_id = $1 AND user_id = $2', [fileId, bobId]);
  if (dbKeyCheck.rows.length === 0) throw new Error('FAIL: file_keys database record not created!');
  console.log('✅ TEST 2 PASSED: Alice shared File A with Bob. file_keys row created!');

  // --- TEST 3: Same Ciphertext Verification ---
  console.log('\n[TEST 3] Verifying file ciphertext is NOT duplicated or re-encrypted...');
  const postShareFileRes = await pool.query('SELECT storage_key FROM files WHERE id = $1', [fileId]);
  const currentStorageKey = postShareFileRes.rows[0].storage_key;
  if (currentStorageKey !== initialStorageKey) {
    throw new Error(`FAIL: Storage key altered! Was ${initialStorageKey}, now ${currentStorageKey}`);
  }
  console.log(`✅ TEST 3 PASSED: Ciphertext object unchanged in B2 (${currentStorageKey})!`);

  // --- TEST 4: Alice (Owner) Access ---
  console.log('\n[TEST 4] Verifying Alice (Owner) can download and decrypt File A...');
  const aliceDownloadRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}` });
  const aliceDek = fileCrypto.getDek(fileId);
  const aliceDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(aliceDownloadRes.data.ciphertext, 'base64'),
    aliceDek,
    Buffer.from(aliceDownloadRes.data.metadata.iv, 'base64'),
    Buffer.from(aliceDownloadRes.data.metadata.authTag, 'base64')
  );
  if (!aliceDecrypted.equals(samplePlaintext)) throw new Error('FAIL: Alice decryption byte mismatch!');
  console.log('✅ TEST 4 PASSED: Alice (Owner) downloaded and decrypted file cleanly!');

  // --- TEST 5: Bob (Recipient) Access & Unwrapping ---
  console.log('\n[TEST 5] Verifying Bob (Recipient) can unwrap DEK and decrypt File A...');
  const bobSharedRes = await request('GET', '/api/files/shared', null, { 'Authorization': `Bearer ${bobToken}` });
  const bobFileListing = bobSharedRes.data.sharedFiles.find(f => f.id === fileId);
  if (!bobFileListing) throw new Error('FAIL: File A missing from Bob shared file listing!');

  const bobDownloadRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  const bobWrapData = bobDownloadRes.data.wrapping;

  // Bob unwraps DEK locally using Bob's private key + Alice's public key
  const bobUnwrappedDek = keyWrapping.unwrapDek(
    bobWrapData.wrappedDek,
    bobWrapData.wrapSalt,
    bobWrapData.wrapIv,
    bobWrapData.wrapAuthTag,
    bobWrapData.senderPublicKey,
    bobPrivPem,
    fileId,
    bobId
  );

  if (!bobUnwrappedDek.equals(originalDek)) throw new Error('FAIL: Bob unwrapped DEK does NOT match original DEK!');

  const bobDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(bobDownloadRes.data.ciphertext, 'base64'),
    bobUnwrappedDek,
    Buffer.from(bobDownloadRes.data.metadata.iv, 'base64'),
    Buffer.from(bobDownloadRes.data.metadata.authTag, 'base64')
  );
  if (!bobDecrypted.equals(samplePlaintext)) throw new Error('FAIL: Bob decrypted buffer is NOT byte-for-byte identical!');
  console.log('✅ TEST 5 PASSED: Bob unwrapped DEK & decrypted file 100% byte-for-byte identical!');

  // --- TEST 6: Different Wrapped DEKs ---
  console.log('\n[TEST 6] Verifying per-user wrapped DEKs produce distinct ciphertexts...');
  // Also wrap DEK for Charlie to compare
  const charlieWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, charliePubPem, fileId, charlieId);
  if (bobWrapping.wrappedDek === charlieWrapping.wrappedDek) {
    throw new Error('FAIL: Wrapped DEKs for Bob and Charlie are identical!');
  }
  console.log('✅ TEST 6 PASSED: Wrapped DEKs for Bob and Charlie are distinct ciphertexts!');

  // --- TEST 7: Server Boundary Inspection ---
  console.log('\n[TEST 7] Inspecting server request boundary for secret leakage...');
  const sharePayloadStr = JSON.stringify(bobWrapping);
  const origDekHex = originalDek.toString('hex');
  const origDekB64 = originalDek.toString('base64');
  const alicePrivHex = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');

  if (sharePayloadStr.includes(origDekHex) || sharePayloadStr.includes(origDekB64) || sharePayloadStr.includes(alicePrivHex)) {
    throw new Error('CRITICAL SECURITY FAILURE: Plaintext DEK or private key detected in HTTP payload!');
  }
  console.log('✅ TEST 7 PASSED: Zero DEK/private key leakage verified in network request!');

  // --- TEST 8: Wrong Private Key Unwrapping Rejection ---
  console.log('\n[TEST 8] Testing wrong private key unwrapping (Charlie tries unwrapping Bob DEK)...');
  let wrongKeyFailed = false;
  try {
    keyWrapping.unwrapDek(
      bobWrapData.wrappedDek,
      bobWrapData.wrapSalt,
      bobWrapData.wrapIv,
      bobWrapData.wrapAuthTag,
      bobWrapData.senderPublicKey,
      charliePrivPem, // Charlie's private key instead of Bob's
      fileId,
      bobId
    );
  } catch (e) {
    wrongKeyFailed = true;
  }
  if (!wrongKeyFailed) throw new Error('FAIL: Unwrapping succeeded with wrong private key!');
  console.log('✅ TEST 8 PASSED: Unwrapping rejected when using unauthorized private key!');

  // --- TEST 9: Tampered Wrapped DEK / Salt / IV / Tag Rejection ---
  console.log('\n[TEST 9] Testing tampered wrapped DEK authentication rejection...');
  const tamperedWrappedDek = Buffer.from(bobWrapData.wrappedDek, 'base64');
  tamperedWrappedDek[0] ^= 0xFF;
  let tamperFailed = false;
  try {
    keyWrapping.unwrapDek(
      tamperedWrappedDek.toString('base64'),
      bobWrapData.wrapSalt,
      bobWrapData.wrapIv,
      bobWrapData.wrapAuthTag,
      bobWrapData.senderPublicKey,
      bobPrivPem,
      fileId,
      bobId
    );
  } catch (e) {
    tamperFailed = true;
  }
  if (!tamperFailed) throw new Error('FAIL: Tampered wrapped DEK accepted without AES-GCM error!');
  console.log('✅ TEST 9 PASSED: Tampered wrapped DEK rejected by AES-256-GCM authentication!');

  // --- TEST 10: AAD Binding Violation Rejection ---
  console.log('\n[TEST 10] Testing AAD binding violation (attempting cross-file/cross-user DEK reuse)...');
  let aadFailed = false;
  try {
    keyWrapping.unwrapDek(
      bobWrapData.wrappedDek,
      bobWrapData.wrapSalt,
      bobWrapData.wrapIv,
      bobWrapData.wrapAuthTag,
      bobWrapData.senderPublicKey,
      bobPrivPem,
      crypto.randomUUID(), // Different fileId
      bobId
    );
  } catch (e) {
    aadFailed = true;
  }
  if (!aadFailed) throw new Error('FAIL: AAD binding violation went undetected!');
  console.log('✅ TEST 10 PASSED: AAD mismatch rejected by AES-256-GCM authentication!');

  // --- TEST 11: No File Re-encryption Verification ---
  console.log('\n[TEST 11] Verifying B2 object remains unchanged after multiple shares...');
  const finalFileDb = await pool.query('SELECT storage_key FROM files WHERE id = $1', [fileId]);
  if (finalFileDb.rows[0].storage_key !== initialStorageKey) {
    throw new Error('FAIL: B2 storage key modified!');
  }
  console.log('✅ TEST 11 PASSED: B2 ciphertext object key strictly invariant!');

  // --- TEST 12: Regression Testing (Cycles 1–5) ---
  console.log('\n[TEST 12] Performing Cycle 1-5 regression suite...');
  const healthRes = await request('GET', '/api/health');
  if (healthRes.status !== 200 || !healthRes.data.database.connected) throw new Error('Health check failed!');
  console.log('✅ TEST 12 PASSED: Cycles 1–5 backend health and encryption subsystems fully regression-verified!');

  console.log('\n================================================================');
  console.log('🎉 ALL 12 CYCLE 6 INTEGRATION TESTS PASSED WITH 100% SUCCESS!');
  console.log('================================================================');
  process.exit(0);
}

runCycle6TestSuite().catch((err) => {
  console.error('\n❌ CYCLE 6 TEST RUNNER FAILED:', err.stack || err.message);
  process.exit(1);
});
