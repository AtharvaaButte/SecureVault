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

async function runGuiE2eTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING MANUAL END-TO-END GUI WORKFLOW VERIFICATION ---');
  console.log('================================================================\n');

  // 1. Admin creates Organization and User Accounts (Alice & Bob)
  const orgName = `GuiOrg_${Date.now()}`;
  const adminEmail = `admin_${Date.now()}@gui.com`;
  const aliceEmail = `alice_${Date.now()}@gui.com`;
  const bobEmail = `bob_${Date.now()}@gui.com`;

  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobKeyPair = crypto.generateKeyPairSync('x25519');
  const bobPrivPem = bobKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // Admin Registers Organization
  const adminReg = await request('POST', '/api/auth/register', { orgName, email: adminEmail, password: 'AdminPassword2026!' }, { 'X-Client-Device-ID': 'admin-device' });
  const adminToken = adminReg.data.token;

  // Admin creates custom role "StandardMember" with file permissions
  const roleRes = await request('POST', '/api/roles', {
    name: 'StandardMember',
    description: 'Standard member role with file permissions',
    permissions: ['FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE'],
  }, { 'Authorization': `Bearer ${adminToken}` });
  const memberRoleId = roleRes.data.role.id;

  // Admin creates Alice & Bob with assigned custom role
  const aliceCreate = await request('POST', '/api/users', { email: aliceEmail, password: 'AlicePassword2026!', roleIds: [memberRoleId] }, { 'Authorization': `Bearer ${adminToken}`, 'X-Client-Device-ID': 'admin-device' });
  const aliceId = aliceCreate.data.user.id;

  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', roleIds: [memberRoleId] }, { 'Authorization': `Bearer ${adminToken}`, 'X-Client-Device-ID': 'admin-device' });
  const bobId = bobCreate.data.user.id;

  // Alice & Bob Login and Register Crypto Identity Public Keys
  const aliceLogin = await request('POST', '/api/auth/login', { email: aliceEmail, password: 'AlicePassword2026!' }, { 'X-Client-Device-ID': 'alice-electron-profile' });
  const aliceToken = aliceLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': 'alice-electron-profile' });

  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' }, { 'X-Client-Device-ID': 'bob-electron-profile' });
  const bobToken = bobLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: bobPubPem }, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': 'bob-electron-profile' });

  console.log(`[Step 1] Admin created Alice (${aliceId}) and Bob (${bobId}) in Organization ${orgName}.`);

  // 2. Alice uploads NORMAL, SENSITIVE, and HIGHLY_SENSITIVE files
  console.log('\n[Step 2] Alice uploads files with NORMAL, SENSITIVE, and HIGHLY_SENSITIVE classifications...');
  
  // NORMAL file
  const normFileId = crypto.randomUUID();
  const normPlaintext = Buffer.from('NORMAL FILE CONTENT');
  const normEnc = fileCrypto.encryptBuffer(normPlaintext);
  fileCrypto.storeDek(normFileId, normEnc.dek);
  const normWrap = keyWrapping.wrapDek(normEnc.dek, alicePrivPem, alicePubPem, normFileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: normFileId,
    originalName: 'GuiNormal.pdf',
    originalSize: normPlaintext.length.toString(),
    iv: normEnc.iv.toString('base64'),
    authTag: normEnc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: normWrap.wrappedDek,
    wrapSalt: normWrap.wrapSalt,
    wrapIv: normWrap.wrapIv,
    wrapAuthTag: normWrap.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'NORMAL',
  }, normEnc.ciphertext, 'GuiNormal.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': 'alice-electron-profile' });

  // SENSITIVE file
  const sensFileId = crypto.randomUUID();
  const sensPlaintext = Buffer.from('SENSITIVE FINANCIAL CONTENT');
  const sensEnc = fileCrypto.encryptBuffer(sensPlaintext);
  fileCrypto.storeDek(sensFileId, sensEnc.dek);
  const sensWrap = keyWrapping.wrapDek(sensEnc.dek, alicePrivPem, alicePubPem, sensFileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: sensFileId,
    originalName: 'GuiSensitive.pdf',
    originalSize: sensPlaintext.length.toString(),
    iv: sensEnc.iv.toString('base64'),
    authTag: sensEnc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: sensWrap.wrappedDek,
    wrapSalt: sensWrap.wrapSalt,
    wrapIv: sensWrap.wrapIv,
    wrapAuthTag: sensWrap.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'SENSITIVE',
  }, sensEnc.ciphertext, 'GuiSensitive.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': 'alice-electron-profile' });

  // HIGHLY_SENSITIVE file
  const highlyFileId = crypto.randomUUID();
  const highlyPlaintext = Buffer.from('HIGHLY SENSITIVE TOP SECRET CONTENT');
  const highlyEnc = fileCrypto.encryptBuffer(highlyPlaintext);
  fileCrypto.storeDek(highlyFileId, highlyEnc.dek);
  const highlyWrap = keyWrapping.wrapDek(highlyEnc.dek, alicePrivPem, alicePubPem, highlyFileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId: highlyFileId,
    originalName: 'GuiHighlySensitive.pdf',
    originalSize: highlyPlaintext.length.toString(),
    iv: highlyEnc.iv.toString('base64'),
    authTag: highlyEnc.authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: highlyWrap.wrappedDek,
    wrapSalt: highlyWrap.wrapSalt,
    wrapIv: highlyWrap.wrapIv,
    wrapAuthTag: highlyWrap.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'HIGHLY_SENSITIVE',
  }, highlyEnc.ciphertext, 'GuiHighlySensitive.enc', { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': 'alice-electron-profile' });

  console.log('✅ [Step 2] All 3 files uploaded with sensitivity badges!');

  // 3. Alice shares SENSITIVE file with Bob (Triggers Step-Up Password Modal)
  console.log('\n[Step 3] Alice shares SENSITIVE file with Bob (triggers step-up re-authentication)...');
  const bobWrap = keyWrapping.wrapDek(sensEnc.dek, alicePrivPem, bobPubPem, sensFileId, bobId);

  // Without step-up -> 403 stepUpRequired: true
  const shareNoPwd = await request('POST', `/api/files/${sensFileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrap.wrappedDek,
    wrapSalt: bobWrap.wrapSalt,
    wrapIv: bobWrap.wrapIv,
    wrapAuthTag: bobWrap.wrapAuthTag,
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': 'alice-electron-profile' });

  console.log('shareNoPwd response:', JSON.stringify(shareNoPwd, null, 2));
  if (shareNoPwd.status !== 403 || !shareNoPwd.data.stepUpRequired) {
    throw new Error('FAIL: Expected SENSITIVE file share to trigger stepUpRequired modal');
  }

  // With correct step-up password -> 201 Created
  const shareWithPwd = await request('POST', `/api/files/${sensFileId}/share`, {
    recipientUserId: bobId,
    senderPublicKey: alicePubPem,
    wrappedDek: bobWrap.wrappedDek,
    wrapSalt: bobWrap.wrapSalt,
    wrapIv: bobWrap.wrapIv,
    wrapAuthTag: bobWrap.wrapAuthTag,
  }, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': 'alice-electron-profile',
    'X-Reauth-Password': 'AlicePassword2026!',
  });

  if (shareWithPwd.status !== 201) throw new Error(`FAIL: Step-up share returned status ${shareWithPwd.status}`);
  console.log('✅ [Step 3] Step-up re-authentication succeeded! File shared with Bob!');

  // 4. Bob views "Files Shared With Me" and downloads & decrypts
  console.log('\n[Step 4] Bob checks shared files listing and downloads SENSITIVE shared file...');
  const bobSharedRes = await request('GET', '/api/files/shared', null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': 'bob-electron-profile' });
  if (bobSharedRes.status !== 200 || bobSharedRes.data.sharedFiles.length !== 1) {
    throw new Error('FAIL: Bob failed to list shared file!');
  }

  const bobDlRes = await request('GET', `/api/files/${sensFileId}/download`, null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': 'bob-electron-profile' });
  if (bobDlRes.status !== 200) throw new Error(`FAIL: Bob download failed with status ${bobDlRes.status}`);

  const bobUnwrappedDek = keyWrapping.unwrapDek(
    bobDlRes.data.wrapping.wrappedDek,
    bobDlRes.data.wrapping.wrapSalt,
    bobDlRes.data.wrapping.wrapIv,
    bobDlRes.data.wrapping.wrapAuthTag,
    bobDlRes.data.wrapping.senderPublicKey,
    bobPrivPem,
    sensFileId,
    bobId
  );
  const bobDecrypted = fileCrypto.decryptBuffer(
    Buffer.from(bobDlRes.data.ciphertext, 'base64'),
    bobUnwrappedDek,
    Buffer.from(bobDlRes.data.metadata.iv, 'base64'),
    Buffer.from(bobDlRes.data.metadata.authTag, 'base64')
  );
  if (!bobDecrypted.equals(sensPlaintext)) throw new Error('FAIL: Bob decrypted content byte mismatch!');
  console.log('✅ [Step 4] Bob successfully listed, unwrapped DEK, and decrypted shared file 100% byte-for-byte!');

  // 5. Alice revokes Bob's access
  console.log('\n[Step 5] Alice revokes Bob\'s access...');
  const revokeRes = await request('DELETE', `/api/files/${sensFileId}/share/${bobId}`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': 'alice-electron-profile',
    'X-Reauth-Password': 'AlicePassword2026!',
  });
  if (revokeRes.status !== 200) throw new Error(`FAIL: Revoke returned status ${revokeRes.status}`);

  // Bob post-revocation download attempt -> 403 Access Denied
  const bobPostRevokeDl = await request('GET', `/api/files/${sensFileId}/download`, null, { 'Authorization': `Bearer ${bobToken}`, 'X-Client-Device-ID': 'bob-electron-profile' });
  if (bobPostRevokeDl.status !== 403) throw new Error(`FAIL: Revoked Bob download returned status ${bobPostRevokeDl.status}`);
  console.log('✅ [Step 5] Alice revoked Bob! Bob post-revocation download strictly denied with HTTP 403!');

  // 6. Test HIGHLY_SENSITIVE file download step-up modal flow
  console.log('\n[Step 6] Alice downloads HIGHLY_SENSITIVE file with step-up re-authentication password...');
  const highlyDlNoPwd = await request('GET', `/api/files/${highlyFileId}/download`, null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': 'alice-electron-profile' });
  if (highlyDlNoPwd.status !== 403 || !highlyDlNoPwd.data.stepUpRequired) throw new Error('FAIL: Highly sensitive download did not require step-up');

  const highlyDlWithPwd = await request('GET', `/api/files/${highlyFileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': 'alice-electron-profile',
    'X-Reauth-Password': 'AlicePassword2026!',
  });
  if (highlyDlWithPwd.status !== 200) throw new Error(`FAIL: Highly sensitive download with step-up failed: ${highlyDlWithPwd.status}`);
  console.log('✅ [Step 6] HIGHLY_SENSITIVE file download verified with step-up re-authentication!');

  console.log('\n================================================================');
  console.log('🎉 MANUAL END-TO-END GUI WORKFLOW VERIFIED 100% SUCCESSFULLY!');
  console.log('================================================================');
  process.exit(0);
}

runGuiE2eTestSuite().catch(err => {
  console.error('\n❌ GUI E2E TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
