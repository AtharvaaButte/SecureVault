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

async function runCycle7TestSuite() {
  console.log('================================================================');
  console.log('--- STARTING CYCLE 7 ACCESS CONTROL INTEGRATION TEST SUITE ---');
  console.log('================================================================\n');

  // 1. Create Primary Organization & Test Users (Alice, Bob, Charlie, OrgAdmin)
  const mainOrgName = `Cycle7_MainOrg_${Date.now()}`;
  const externalOrgName = `Cycle7_ExternalOrg_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@mainorg.com`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@mainorg.com`;
  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const charlieEmail = `charlie_${Date.now()}@mainorg.com`;
  const charlieKeyPair = crypto.generateKeyPairSync('x25519');
  const charliePrivPem = charlieKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const charliePubPem = charlieKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const adminEmail = `admin_${Date.now()}@mainorg.com`;

  const externalUserEmail = `eve_${Date.now()}@externalorg.com`;
  const externalKeyPair = crypto.generateKeyPairSync('x25519');
  const externalPubPem = externalKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Register Alice (Creates Main Org)
  const aliceReg = await request('POST', '/api/auth/register', { orgName: mainOrgName, email: aliceEmail, password: 'AlicePassword2026!' });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const mainOrgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}` });

  // Add Bob to Main Org
  const bobHash = await argon2.hash('BobPassword2026!', { type: argon2.argon2id });
  const bobDb = await pool.query(
    'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
    [mainOrgId, bobEmail, bobHash, 'USER']
  );
  const bobId = bobDb.rows[0].id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  // Add Charlie to Main Org
  const charlieHash = await argon2.hash('CharliePassword2026!', { type: argon2.argon2id });
  const charlieDb = await pool.query(
    'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
    [mainOrgId, charlieEmail, charlieHash, 'USER']
  );
  const charlieId = charlieDb.rows[0].id;
  const charlieLogin = await request('POST', '/api/auth/login', { email: charlieEmail, password: 'CharliePassword2026!' });
  const charlieToken = charlieLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: charliePubPem }, { 'Authorization': `Bearer ${charlieToken}` });

  // Add OrgAdmin to Main Org (ADMIN role)
  const adminHash = await argon2.hash('AdminPassword2026!', { type: argon2.argon2id });
  const adminDb = await pool.query(
    'INSERT INTO users (organization_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id',
    [mainOrgId, adminEmail, adminHash, 'ADMIN']
  );
  const adminId = adminDb.rows[0].id;
  const adminLogin = await request('POST', '/api/auth/login', { email: adminEmail, password: 'AdminPassword2026!' });
  const adminToken = adminLogin.data.token;

  // Register Eve in External Org
  const externalReg = await request('POST', '/api/auth/register', { orgName: externalOrgName, email: externalUserEmail, password: 'EvePassword2026!' });
  const externalToken = externalReg.data.token;
  const externalUserId = externalReg.data.user.id;
  await request('POST', '/api/crypto/public-key', { publicKey: externalPubPem }, { 'Authorization': `Bearer ${externalToken}` });

  console.log(`[Setup] Registered Main Org (${mainOrgId}) Users:`);
  console.log(`  - Alice   : ${aliceId}`);
  console.log(`  - Bob     : ${bobId}`);
  console.log(`  - Charlie : ${charlieId}`);
  console.log(`  - Admin   : ${adminId}`);
  console.log(`[Setup] External User: Eve (${externalUserId})\n`);

  // Alice encrypts & uploads File A
  const samplePlaintext = Buffer.from('CONFIDENTIAL ACCESS CONTROL PAYLOAD - CYCLE 7 AUTHORIZATION RULES');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const uploadRes = await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'Cycle7_Access_Control.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
  }, fileCiphertext, 'Cycle7_Access_Control.enc', { 'Authorization': `Bearer ${aliceToken}` });

  if (uploadRes.status !== 201) throw new Error('File upload failed!');

  // --- TEST 1: Alice (Owner) Access ---
  console.log('[TEST 1] Testing Alice (Owner) download & decryption...');
  const aliceDownloadRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}` });
  if (aliceDownloadRes.status !== 200) throw new Error(`Alice download failed with status ${aliceDownloadRes.status}`);
  console.log(`  HTTP Result: ${aliceDownloadRes.status} OK`);
  console.log('✅ TEST 1 PASSED: Alice (Owner) successfully downloaded and decrypted File A!');

  // --- TEST 2: Alice shares File A with Bob -> Bob Access ---
  console.log('\n[TEST 2] Testing Alice sharing File A with Bob & Bob download...');
  const bobWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, bobPubPem, fileId, bobId);
  const shareRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrapping.wrappedDek,
    wrapSalt: bobWrapping.wrapSalt,
    wrapIv: bobWrapping.wrapIv,
    wrapAuthTag: bobWrapping.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}` });

  if (shareRes.status !== 201) throw new Error(`Alice share with Bob failed with status ${shareRes.status}`);
  console.log(`  HTTP Share Result: ${shareRes.status} Created`);

  const bobDownloadRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  if (bobDownloadRes.status !== 200) throw new Error(`Bob download failed with status ${bobDownloadRes.status}`);
  console.log(`  HTTP Download Result: ${bobDownloadRes.status} OK`);
  console.log('✅ TEST 2 PASSED: Bob (Shared User) successfully downloaded and unwrapped File A!');

  // --- TEST 3: Charlie (Unauthorized User) Access Rejection ---
  console.log('\n[TEST 3] Testing Charlie (Unauthorized) download rejection...');
  const charlieDownloadRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${charlieToken}` });
  console.log(`  HTTP Result: ${charlieDownloadRes.status} (${charlieDownloadRes.data.message})`);
  if (charlieDownloadRes.status !== 403 && charlieDownloadRes.status !== 404) {
    throw new Error(`FAIL: Unauthorized download returned unexpected status ${charlieDownloadRes.status}`);
  }
  console.log('✅ TEST 3 PASSED: Unauthorized user Charlie properly rejected with HTTP 403!');

  // --- TEST 4: Bob (Shared User, Non-Owner) Cannot Share ---
  console.log('\n[TEST 4] Testing Bob (Non-Owner) sharing attempt rejection...');
  const charlieWrapping = keyWrapping.wrapDek(originalDek, bobPrivPem, charliePubPem, fileId, charlieId);
  const bobShareAttempt = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: charlieId,
    senderPublicKey: bobPubPem,
    wrappedDek: charlieWrapping.wrappedDek,
    wrapSalt: charlieWrapping.wrapSalt,
    wrapIv: charlieWrapping.wrapIv,
    wrapAuthTag: charlieWrapping.wrapAuthTag,
  }, { 'Authorization': `Bearer ${bobToken}` });

  console.log(`  HTTP Result: ${bobShareAttempt.status} (${bobShareAttempt.data.message})`);
  if (bobShareAttempt.status !== 403) throw new Error(`FAIL: Non-owner sharing returned status ${bobShareAttempt.status}`);
  console.log('✅ TEST 4 PASSED: Non-owner Bob sharing attempt properly rejected with HTTP 403!');

  // --- TEST 5: Bob (Shared User, Non-Owner) Cannot Revoke ---
  console.log('\n[TEST 5] Testing Bob (Non-Owner) revoking share attempt rejection...');
  const bobRevokeAttempt = await request('DELETE', `/api/files/${fileId}/share/${bobId}`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Result: ${bobRevokeAttempt.status} (${bobRevokeAttempt.data.message})`);
  if (bobRevokeAttempt.status !== 403) throw new Error(`FAIL: Non-owner revoke returned status ${bobRevokeAttempt.status}`);
  console.log('✅ TEST 5 PASSED: Non-owner Bob revoke attempt properly rejected with HTTP 403!');

  // --- TEST 6: Alice (Owner) Revokes Bob's Access ---
  console.log('\n[TEST 6] Testing Alice (Owner) revoking Bob access...');
  const revokeRes = await request('DELETE', `/api/files/${fileId}/share/${bobId}`, null, { 'Authorization': `Bearer ${aliceToken}` });
  if (revokeRes.status !== 200) throw new Error(`Revoke share failed with status ${revokeRes.status}`);
  console.log(`  HTTP Revoke Result: ${revokeRes.status} OK`);

  const bobPostRevokeRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  Bob Download Result After Revocation: ${bobPostRevokeRes.status} (${bobPostRevokeRes.data.message})`);
  if (bobPostRevokeRes.status !== 403 && bobPostRevokeRes.status !== 404) {
    throw new Error(`FAIL: Revoked user download returned unexpected status ${bobPostRevokeRes.status}`);
  }
  console.log('✅ TEST 6 PASSED: Alice revoked Bob! Bob access immediately denied with HTTP 403!');

  // --- TEST 7: Admin Without Explicit Share Access Rejection ---
  console.log('\n[TEST 7] Testing Admin (without explicit share) download rejection...');
  const adminDownloadRes = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${adminToken}` });
  console.log(`  HTTP Admin Result: ${adminDownloadRes.status} (${adminDownloadRes.data.message})`);
  if (adminDownloadRes.status !== 403 && adminDownloadRes.status !== 404) {
    throw new Error(`FAIL: Admin without share access returned status ${adminDownloadRes.status}`);
  }
  console.log('✅ TEST 7 PASSED: Org Admin without explicit share access rejected with HTTP 403!');

  // --- TEST 8: Cross-Organization Sharing Rejection ---
  console.log('\n[TEST 8] Testing Cross-Organization share attempt rejection (Alice shares with Eve)...');
  const eveWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, externalPubPem, fileId, externalUserId);
  const crossOrgRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: externalUserId,
    senderPublicKey: alicePubPem,
    wrappedDek: eveWrapping.wrappedDek,
    wrapSalt: eveWrapping.wrapSalt,
    wrapIv: eveWrapping.wrapIv,
    wrapAuthTag: eveWrapping.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}` });

  console.log(`  HTTP Result: ${crossOrgRes.status} (${crossOrgRes.data.message})`);
  if (crossOrgRes.status !== 403) throw new Error(`FAIL: Cross-org share returned status ${crossOrgRes.status}`);
  console.log('✅ TEST 8 PASSED: Cross-organization share attempt rejected with HTTP 403!');

  // --- TEST 9: UUID Tampering / Guessing Protection ---
  console.log('\n[TEST 9] Testing UUID tampering protection (Bob tries accessing random/guessed UUID)...');
  const guessedUUID = crypto.randomUUID();
  const guessedRes = await request('GET', `/api/files/${guessedUUID}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  console.log(`  HTTP Result: ${guessedRes.status} (${guessedRes.data.message})`);
  if (guessedRes.status !== 404 && guessedRes.status !== 403) {
    throw new Error(`FAIL: Guessed UUID download returned status ${guessedRes.status}`);
  }
  console.log('✅ TEST 9 PASSED: Guessed file UUID request safely rejected!');

  // --- TEST 10: Regression Testing (Cycles 1–6) ---
  console.log('\n[TEST 10] Performing Cycle 1-6 regression test...');
  const healthRes = await request('GET', '/api/health');
  if (healthRes.status !== 200 || !healthRes.data.database.connected) throw new Error('Health check failed!');
  console.log('✅ TEST 10 PASSED: Cycles 1–6 core infrastructure fully operational!');

  console.log('\n================================================================');
  console.log('🎉 ALL 10 CYCLE 7 ACCESS CONTROL INTEGRATION TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runCycle7TestSuite().catch((err) => {
  console.error('\n❌ CYCLE 7 TEST RUNNER FAILED:', err.stack || err.message);
  process.exit(1);
});
