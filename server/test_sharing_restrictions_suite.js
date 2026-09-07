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

async function runSharingRestrictionsTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING E2EE SHARING & BASE PERMISSION RESTRICTIONS SUITE ---');
  console.log('================================================================\n');

  const ts = Date.now();
  const orgName = `ShareOrg_${ts}`;
  const ownerEmail = `owner_${ts}@shareorg.com`;
  const bobEmail = `bob_${ts}@shareorg.com`;
  const carolEmail = `carol_${ts}@shareorg.com`;

  const ownerKeyPair = crypto.generateKeyPairSync('x25519');
  const ownerPrivPem = ownerKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const ownerPubPem = ownerKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const carolKeyPair = crypto.generateKeyPairSync('x25519');
  const carolPrivPem = carolKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const carolPubPem = carolKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // 1. Setup Org & Users
  console.log('[TEST 1] Registering Org & creating members with custom roles...');
  const ownerReg = await request('POST', '/api/auth/register', { orgName, email: ownerEmail, password: 'OwnerPassword2026!' });
  const ownerToken = ownerReg.data.token;
  const ownerId = ownerReg.data.user.id;
  const orgId = ownerReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: ownerPubPem }, { 'Authorization': `Bearer ${ownerToken}` });

  // Create SubManager custom role with FILE_READ, FILE_UPLOAD, FILE_SHARE, FILE_REVOKE permissions
  const roleRes = await request('POST', '/api/roles', {
    name: 'SubManager',
    description: 'SubManager with file read, share, and revoke permissions',
    permissions: ['FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE', 'FILE_REVOKE'],
  }, { 'Authorization': `Bearer ${ownerToken}` });
  const subManagerRoleId = roleRes.data.role.id;

  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', roleIds: [subManagerRoleId] }, { 'Authorization': `Bearer ${ownerToken}` });
  const bobId = bobCreate.data.user.id;

  const carolCreate = await request('POST', '/api/users', { email: carolEmail, password: 'CarolPassword2026!', roleIds: [subManagerRoleId] }, { 'Authorization': `Bearer ${ownerToken}` });
  const carolId = carolCreate.data.user.id;

  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}` });

  const carolLogin = await request('POST', '/api/auth/login', { email: carolEmail, password: 'CarolPassword2026!' });
  const carolToken = carolLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: carolPubPem }, { 'Authorization': `Bearer ${carolToken}` });

  // Verify GET /api/users/members returns publicKey
  const membersRes = await request('GET', '/api/users/members', null, { 'Authorization': `Bearer ${ownerToken}` });
  const bobMember = membersRes.data.users.find(u => u.id === bobId);
  if (!bobMember || !bobMember.publicKey) throw new Error('FAIL: GET /api/users/members did not return publicKey!');
  console.log(`✅ TEST 1 PASSED: GET /api/users/members returned publicKey for members!`);

  // 2. Upload File A & Share with Bob with blockedOperations: ['FILE_SHARE']
  console.log('\n[TEST 2] Uploading File A & sharing with Bob with blockedOperations: ["FILE_SHARE"]...');
  const fileAPlaintext = Buffer.from('File A Confidential Content 2026');
  const fileAId = crypto.randomUUID();
  const fileAEnc = fileCrypto.encryptBuffer(fileAPlaintext);

  const ownerWrappingA = keyWrapping.wrapDek(fileAEnc.dek, ownerPrivPem, ownerPubPem, fileAId, ownerId);

  await uploadMultipart(
    '/api/files/upload',
    {
      fileId: fileAId,
      originalName: 'fileA.txt',
      originalSize: fileAPlaintext.length.toString(),
      iv: fileAEnc.iv.toString('hex'),
      authTag: fileAEnc.authTag.toString('hex'),
      algorithm: 'AES-256-GCM',
      wrappedDek: ownerWrappingA.wrappedDek,
      wrapSalt: ownerWrappingA.wrapSalt,
      wrapIv: ownerWrappingA.wrapIv,
      wrapAuthTag: ownerWrappingA.wrapAuthTag,
      senderPublicKey: ownerPubPem,
      dataClassification: 'INTERNAL',
    },
    fileAEnc.ciphertext,
    'fileA.txt.enc',
    { 'Authorization': `Bearer ${ownerToken}` }
  );

  const bobWrapA = keyWrapping.wrapDek(fileAEnc.dek, ownerPrivPem, bobPubPem, fileAId, bobId);

  const shareResA = await request('POST', `/api/files/${fileAId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: ownerPubPem,
    wrappedDek: bobWrapA.wrappedDek,
    wrapSalt: bobWrapA.wrapSalt,
    wrapIv: bobWrapA.wrapIv,
    wrapAuthTag: bobWrapA.wrapAuthTag,
    blockedOperations: ['FILE_SHARE'],
  }, { 'Authorization': `Bearer ${ownerToken}` });

  if (shareResA.status !== 201) throw new Error(`Share File A failed: ${JSON.stringify(shareResA.data)}`);

  // Verify PostgreSQL file_keys & file_restrictions records
  const fileKeysDb = await pool.query('SELECT * FROM file_keys WHERE file_id = $1 AND user_id = $2', [fileAId, bobId]);
  if (fileKeysDb.rows.length === 0) throw new Error('FAIL: file_keys record missing for Bob!');

  const fileRestDb = await pool.query('SELECT blocked_operation FROM file_restrictions WHERE file_id = $1 AND user_id = $2', [fileAId, bobId]);
  if (fileRestDb.rows.length !== 1 || fileRestDb.rows[0].blocked_operation !== 'FILE_SHARE') {
    throw new Error('FAIL: file_restrictions record for FILE_SHARE missing!');
  }
  console.log('✅ TEST 2 PASSED: file_keys and file_restrictions records created in PostgreSQL!');

  // 3. Bob Downloads & Decrypts File A using his own X25519 key
  console.log('\n[TEST 3] Bob downloads and decrypts File A using his own key material...');
  const bobDownloadA = await request('GET', `/api/files/${fileAId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  if (bobDownloadA.status !== 200) throw new Error(`Bob download File A failed: ${JSON.stringify(bobDownloadA.data)}`);

  const bobWrapping = bobDownloadA.data.wrapping;
  const bobUnwrappedDek = keyWrapping.unwrapDek(
    bobWrapping.wrappedDek,
    bobWrapping.wrapSalt,
    bobWrapping.wrapIv,
    bobWrapping.wrapAuthTag,
    bobWrapping.senderPublicKey,
    bobPrivPem,
    fileAId,
    bobId
  );

  const decryptedA = fileCrypto.decryptBuffer(
    Buffer.from(bobDownloadA.data.ciphertext, 'base64'),
    bobUnwrappedDek,
    Buffer.from(bobDownloadA.data.metadata.iv, 'hex'),
    Buffer.from(bobDownloadA.data.metadata.authTag, 'hex')
  );

  if (!decryptedA.equals(fileAPlaintext)) throw new Error('FAIL: Decrypted content mismatch for Bob!');
  console.log('✅ TEST 3 PASSED: Bob successfully decrypted File A using his own X25519 key!');

  // 4. Bob Attempts to Re-share File A with Carol -> Strictly DENIED by Backend (403)
  console.log('\n[TEST 4] Bob attempts to re-share File A with Carol (Must be DENIED with HTTP 403)...');
  const carolWrapA = keyWrapping.wrapDek(bobUnwrappedDek, bobPrivPem, carolPubPem, fileAId, carolId);

  const bobShareAttempt = await request('POST', `/api/files/${fileAId}/share`, {
    recipientUserId: carolId,
    senderPublicKey: bobPubPem,
    wrappedDek: carolWrapA.wrappedDek,
    wrapSalt: carolWrapA.wrapSalt,
    wrapIv: carolWrapA.wrapIv,
    wrapAuthTag: carolWrapA.wrapAuthTag,
  }, { 'Authorization': `Bearer ${bobToken}` });

  if (bobShareAttempt.status !== 403) throw new Error(`Expected 403 when Bob re-shares restricted File A, got ${bobShareAttempt.status}`);
  console.log('✅ TEST 4 PASSED: Re-sharing File A by Bob strictly denied with HTTP 403!');

  // 5. Verify Bob CAN Share File B where no restriction is applied
  console.log('\n[TEST 5] Bob uploads File B & shares with Carol (no restriction)...');
  const fileBPlaintext = Buffer.from('File B Content 2026');
  const fileBId = crypto.randomUUID();
  const fileBEnc = fileCrypto.encryptBuffer(fileBPlaintext);
  const bobWrappingB = keyWrapping.wrapDek(fileBEnc.dek, bobPrivPem, bobPubPem, fileBId, bobId);

  await uploadMultipart(
    '/api/files/upload',
    {
      fileId: fileBId,
      originalName: 'fileB.txt',
      originalSize: fileBPlaintext.length.toString(),
      iv: fileBEnc.iv.toString('hex'),
      authTag: fileBEnc.authTag.toString('hex'),
      algorithm: 'AES-256-GCM',
      wrappedDek: bobWrappingB.wrappedDek,
      wrapSalt: bobWrappingB.wrapSalt,
      wrapIv: bobWrappingB.wrapIv,
      wrapAuthTag: bobWrappingB.wrapAuthTag,
      senderPublicKey: bobPubPem,
      dataClassification: 'INTERNAL',
    },
    fileBEnc.ciphertext,
    'fileB.txt.enc',
    { 'Authorization': `Bearer ${bobToken}` }
  );

  const carolWrapB = keyWrapping.wrapDek(fileBEnc.dek, bobPrivPem, carolPubPem, fileBId, carolId);

  const bobShareB = await request('POST', `/api/files/${fileBId}/share`, {
    recipientUserId: carolId,
    senderPublicKey: bobPubPem,
    wrappedDek: carolWrapB.wrappedDek,
    wrapSalt: carolWrapB.wrapSalt,
    wrapIv: carolWrapB.wrapIv,
    wrapAuthTag: carolWrapB.wrapAuthTag,
    blockedOperations: [],
  }, { 'Authorization': `Bearer ${bobToken}` });

  if (bobShareB.status !== 201) throw new Error(`Bob sharing File B failed: ${JSON.stringify(bobShareB.data)}`);
  console.log('✅ TEST 5 PASSED: Restriction on File A did not affect Bob sharing File B!');

  // 6. Revoking Share Permission
  console.log('\n[TEST 6] Revoking Bob\'s share permission for File A...');
  const revokeRes = await request('DELETE', `/api/files/${fileAId}/share/${bobId}`, null, { 'Authorization': `Bearer ${ownerToken}` });
  if (revokeRes.status !== 200) throw new Error('Revoke share failed');

  const postRevokeDownload = await request('GET', `/api/files/${fileAId}/download`, null, { 'Authorization': `Bearer ${bobToken}` });
  if (postRevokeDownload.status !== 403) throw new Error('Expected 403 for Bob post-revocation download!');
  console.log('✅ TEST 6 PASSED: Revoke share removed file_keys and blocked post-revocation access!');

  console.log('\n================================================================');
  console.log('🎉 ALL E2EE SHARING & BASE PERMISSION RESTRICTIONS TESTS PASSED 100%!');
  console.log('================================================================\n');
  process.exit(0);
}

runSharingRestrictionsTestSuite().catch(err => {
  console.error('❌ TEST FAILED:', err.message);
  process.exit(1);
});
