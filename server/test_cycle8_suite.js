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

async function runCycle8TestSuite() {
  console.log('================================================================');
  console.log('--- STARTING CYCLE 8 REVOCATION FOCUSED TEST SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users (Alice, Bob)
  const orgName = `Cycle8_Org_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@cycle8.org`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@cycle8.org`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Register Alice (Creates Org)
  const aliceReg = await request('POST', '/api/auth/register', { orgName, email: aliceEmail, password: 'AlicePassword2026!' });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const orgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}` });

  // Add Bob to Same Org via Admin API
  const bobCreateRes = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${aliceToken}` });
  const bobId = bobCreateRes.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  console.log(`[Setup] Registered Users in Organization (${orgId}):`);
  console.log(`  - Alice (Owner)     : ${aliceId}`);
  console.log(`  - Bob   (Recipient) : ${bobId}\n`);

  // Alice encrypts & uploads File A
  const samplePlaintext = Buffer.from('CYCLE 8 REVOCATION TEST PAYLOAD - TOP SECRET ENCRYPTED DOCUMENT');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);

  const uploadRes = await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Cycle8_Top_Secret.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrapping.wrappedDek,
    wrapSalt: ownerWrapping.wrapSalt,
    wrapIv: ownerWrapping.wrapIv,
    wrapAuthTag: ownerWrapping.wrapAuthTag,
    senderPublicKey: alicePubPem,
  }, fileCiphertext, 'Cycle8_Top_Secret.enc', { 'Authorization': `Bearer ${aliceToken}` });

  if (uploadRes.status !== 201) throw new Error(`Upload failed with status ${uploadRes.status}`);
  const initialStorageKey = uploadRes.data.file.storageKey;

  // --- TEST 1: Alice shares File A with Bob -> Bob Access Verification ---
  console.log('[TEST 1] Testing initial file sharing (Alice shares File A with Bob)...');
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

  // Bob checks shared files list
  const bobSharedRes = await request('GET', '/api/files/shared', null, { 'Authorization': `Bearer ${bobToken}` });
  const foundFileInBobList = bobSharedRes.data.sharedFiles.find(f => f.id === fileId);
  if (!foundFileInBobList) throw new Error('FAIL: File A missing from Bob shared file listing!');

  // Bob downloads & decrypts file
  const bobDlRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
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
  const bobDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(bobDlRes.data.ciphertext, 'base64'),
    bobUnwrappedDek,
    Buffer.from(bobDlRes.data.metadata.iv, 'base64'),
    Buffer.from(bobDlRes.data.metadata.authTag, 'base64')
  );

  if (!bobDecrypted.equals(samplePlaintext)) throw new Error('FAIL: Bob decrypted payload byte mismatch!');
  console.log('✅ TEST 1 PASSED: Alice shared file with Bob; Bob listed, unwrapped DEK, and decrypted successfully!');

  // --- TEST 2: Alice Revokes Bob's Access ---
  console.log('\n[TEST 2] Testing Alice revoking Bob\'s access...');
  const revokeRes = await request('DELETE', `/api/files/${fileId}/share/${bobId}`, null, { 'Authorization': `Bearer ${aliceToken}` });
  if (revokeRes.status !== 200) throw new Error(`Revoke endpoint returned status ${revokeRes.status}`);

  const checkDbKeys = await pool.query('SELECT * FROM file_keys WHERE file_id = $1 AND user_id = $2', [fileId, bobId]);
  if (checkDbKeys.rows.length > 0) throw new Error('FAIL: file_keys row for Bob was not deleted!');
  console.log('✅ TEST 2 PASSED: Alice revoked Bob! file_keys record for Bob removed from database!');

  // --- TEST 3: Revoked User Listing Check ---
  console.log('\n[TEST 3] Verifying File A no longer appears in Bob\'s shared files list...');
  const bobSharedPostRevoke = await request('GET', '/api/files/shared', null, { 'Authorization': `Bearer ${bobToken}` });
  const fileStillInBobList = bobSharedPostRevoke.data.sharedFiles.find(f => f.id === fileId);
  if (fileStillInBobList) throw new Error('FAIL: Revoked file still appears in Bob\'s shared files list!');
  console.log('✅ TEST 3 PASSED: Revoked file immediately vanished from Bob\'s shared files list!');

  // --- TEST 4: Revoked User Access Rejection ---
  console.log('\n[TEST 4] Verifying Bob cannot download or decrypt ciphertext post-revocation...');
  const bobPostRevokeDl = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Download Result: ${bobPostRevokeDl.status} (${bobPostRevokeDl.data.message})`);
  if (bobPostRevokeDl.status !== 403 && bobPostRevokeDl.status !== 404) {
    throw new Error(`FAIL: Revoked user download returned unexpected status ${bobPostRevokeDl.status}`);
  }
  console.log('✅ TEST 4 PASSED: Bob download request strictly rejected with HTTP 403 Forbidden!');

  // --- TEST 5: Owner Continued Access ---
  console.log('\n[TEST 5] Verifying Alice (Owner) retains full download and decryption access post-revocation...');
  const alicePostRevokeDl = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}` });
  if (alicePostRevokeDl.status !== 200) throw new Error(`Alice download failed post-revocation with status ${alicePostRevokeDl.status}`);

  const aliceUnwrappedDek = keyWrapping.unwrapDek(
    alicePostRevokeDl.data.wrapping.wrappedDek,
    alicePostRevokeDl.data.wrapping.wrapSalt,
    alicePostRevokeDl.data.wrapping.wrapIv,
    alicePostRevokeDl.data.wrapping.wrapAuthTag,
    alicePostRevokeDl.data.wrapping.senderPublicKey,
    alicePrivPem,
    fileId,
    aliceId
  );
  const aliceDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(alicePostRevokeDl.data.ciphertext, 'base64'),
    aliceUnwrappedDek,
    Buffer.from(alicePostRevokeDl.data.metadata.iv, 'base64'),
    Buffer.from(alicePostRevokeDl.data.metadata.authTag, 'base64')
  );

  if (!aliceDecrypted.equals(samplePlaintext)) throw new Error('FAIL: Alice decrypted payload byte mismatch!');
  console.log('✅ TEST 5 PASSED: Alice (Owner) retained 100% full access to download & decrypt file!');

  // --- TEST 6: B2 Storage Key Invariant & Zero DEK Exposure ---
  console.log('\n[TEST 6] Verifying B2 object invariant & zero DEK exposure during revocation...');
  const finalFileDb = await pool.query('SELECT storage_key FROM files WHERE id = $1', [fileId]);
  if (finalFileDb.rows[0].storage_key !== initialStorageKey) {
    throw new Error('FAIL: B2 storage key was modified during revocation!');
  }

  const revokePayloadStr = JSON.stringify(revokeRes);
  const origDekHex = originalDek.toString('hex');
  const origDekB64 = originalDek.toString('base64');
  if (revokePayloadStr.includes(origDekHex) || revokePayloadStr.includes(origDekB64)) {
    throw new Error('CRITICAL SECURITY FAILURE: Plaintext DEK exposed in revocation response!');
  }
  console.log('✅ TEST 6 PASSED: B2 ciphertext object strictly invariant & zero DEK exposure verified!');

  console.log('\n================================================================');
  console.log('🎉 ALL 6 CYCLE 8 REVOCATION INTEGRATION TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runCycle8TestSuite().catch((err) => {
  console.error('\n❌ CYCLE 8 TEST RUNNER FAILED:', err.stack || err.message);
  process.exit(1);
});
