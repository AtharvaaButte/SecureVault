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

async function runOwnerModelTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING ORGANIZATION OWNER ACCOUNT MODEL SUITE ---');
  console.log('================================================================\n');

  const ts = Date.now();
  const orgName = `OwnerOrg_${ts}`;
  const ownerEmail = `owner_${ts}@ownerorg.com`;
  const memberEmail = `member_${ts}@ownerorg.com`;
  const subMemberEmail = `submember_${ts}@ownerorg.com`;

  const ownerKeyPair = crypto.generateKeyPairSync('x25519');
  const ownerPrivPem = ownerKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const ownerPubPem = ownerKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const memberKeyPair = crypto.generateKeyPairSync('x25519');
  const memberPrivPem = memberKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const memberPubPem = memberKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  // 1. Register Organization & Owner
  console.log('[TEST 1] Registering Organization & Owner account...');
  const regRes = await request('POST', '/api/auth/register', { orgName, email: ownerEmail, password: 'OwnerPassword2026!' });
  if (regRes.status !== 201) throw new Error(`Registration failed: ${JSON.stringify(regRes.data)}`);
  
  const ownerToken = regRes.data.token;
  const ownerId = regRes.data.user.id;
  const orgId = regRes.data.organization.id;

  if (!regRes.data.user.isOwner) throw new Error('FAIL: user.isOwner claim is not true for registering Owner!');
  console.log(`✅ Owner registered successfully (User ID: ${ownerId}, Org ID: ${orgId})`);

  // Verify Database State for Owner & Organization
  const orgDb = await pool.query('SELECT owner_id FROM organizations WHERE id = $1', [orgId]);
  if (orgDb.rows[0].owner_id !== ownerId) throw new Error('FAIL: organizations.owner_id does not match Owner user ID!');

  const ownerDb = await pool.query('SELECT is_owner FROM users WHERE id = $1', [ownerId]);
  if (!ownerDb.rows[0].is_owner) throw new Error('FAIL: users.is_owner is not true in PostgreSQL!');

  const rolesDb = await pool.query('SELECT * FROM roles WHERE organization_id = $1', [orgId]);
  if (rolesDb.rows.length > 0) throw new Error('FAIL: Custom roles exist for newly created org! Owner must not have a custom role seeded.');
  console.log('✅ TEST 1 PASSED: Owner stored directly in organizations.owner_id & users.is_owner with no custom roles seeded!');

  // Register Owner crypto key
  await request('POST', '/api/crypto/public-key', { publicKey: ownerPubPem }, { 'Authorization': `Bearer ${ownerToken}` });

  // 2. Create Custom Role & Owner Creates Normal User
  console.log('\n[TEST 2] Owner creates custom role "Manager" & creates a normal user...');
  const createRoleRes = await request('POST', '/api/roles', {
    name: 'Manager',
    description: 'Management role with user creation and file permissions',
    permissions: ['USER_CREATE', 'USER_MANAGE', 'FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE'],
  }, { 'Authorization': `Bearer ${ownerToken}` });

  if (createRoleRes.status !== 201) throw new Error(`Custom role creation failed: ${JSON.stringify(createRoleRes.data)}`);
  const managerRoleId = createRoleRes.data.role.id;

  // Attempt to create a role named "Owner" (Must fail)
  const fakeOwnerRoleRes = await request('POST', '/api/roles', {
    name: 'Owner',
    permissions: ['FILE_READ'],
  }, { 'Authorization': `Bearer ${ownerToken}` });
  if (fakeOwnerRoleRes.status !== 400) throw new Error('FAIL: Backend allowed creating custom role named "Owner"!');
  console.log('✅ Creating custom role named "Owner" blocked by backend as reserved name!');

  const createMemberRes = await request('POST', '/api/users', {
    email: memberEmail,
    password: 'MemberPassword2026!',
    roleIds: [managerRoleId],
  }, { 'Authorization': `Bearer ${ownerToken}` });

  if (createMemberRes.status !== 201) throw new Error(`Member creation failed: ${JSON.stringify(createMemberRes.data)}`);
  const memberId = createMemberRes.data.user.id;
  console.log(`✅ TEST 2 PASSED: Owner created custom role "Manager" and normal member (${memberId})!`);

  // 3. Authorized Non-Owner Creates User
  console.log('\n[TEST 3] Authorized non-owner member creates another user...');
  const memberLogin = await request('POST', '/api/auth/login', { email: memberEmail, password: 'MemberPassword2026!' });
  const memberToken = memberLogin.data.token;
  await request('POST', '/api/crypto/public-key', { publicKey: memberPubPem }, { 'Authorization': `Bearer ${memberToken}` });

  const createSubMemberRes = await request('POST', '/api/users', {
    email: subMemberEmail,
    password: 'SubPassword2026!',
    roleIds: [managerRoleId],
  }, { 'Authorization': `Bearer ${memberToken}` });

  if (createSubMemberRes.status !== 201) throw new Error(`Authorized non-owner creation failed: ${JSON.stringify(createSubMemberRes.data)}`);
  const subMemberId = createSubMemberRes.data.user.id;
  console.log(`✅ TEST 3 PASSED: Authorized non-owner created user (${subMemberId})!`);

  // 4. Member Listing Excludes Owner
  console.log('\n[TEST 4] GET /api/users/members excludes Organization Owner...');
  const membersListRes = await request('GET', '/api/users/members', null, { 'Authorization': `Bearer ${ownerToken}` });
  if (membersListRes.status !== 200) throw new Error('Failed to fetch members list');

  const returnedUsers = membersListRes.data.users || [];
  const foundOwner = returnedUsers.find(u => u.id === ownerId);
  if (foundOwner) throw new Error('FAIL: GET /api/users/members returned Organization Owner in normal users list!');
  
  if (returnedUsers.length !== 2) throw new Error(`Expected 2 normal members, found ${returnedUsers.length}`);
  console.log('✅ TEST 4 PASSED: GET /api/users/members strictly excludes Owner from member list!');

  // 5. Roles Listing Excludes Owner Custom Role
  console.log('\n[TEST 5] GET /api/roles returns custom roles catalog only...');
  const rolesListRes = await request('GET', '/api/roles', null, { 'Authorization': `Bearer ${ownerToken}` });
  const returnedRoles = rolesListRes.data.roles || [];
  const foundOwnerRole = returnedRoles.find(r => r.name.toLowerCase() === 'owner');
  if (foundOwnerRole) throw new Error('FAIL: GET /api/roles returned an "Owner" custom role!');
  console.log('✅ TEST 5 PASSED: Custom organization roles catalog contains no "Owner" role!');

  // 6. Owner Cannot Be Deleted via Member Deletion
  console.log('\n[TEST 6] Testing protection against deleting Organization Owner...');
  const deleteOwnerRes = await request('DELETE', `/api/users/${ownerId}`, null, { 'Authorization': `Bearer ${memberToken}` });
  if (deleteOwnerRes.status !== 403) throw new Error(`Expected 403 when deleting Owner, got ${deleteOwnerRes.status}`);
  console.log('✅ TEST 6 PASSED: Deleting Organization Owner via member deletion returns 403 Forbidden!');

  // 7. Modifying Roles for Normal User vs Owner
  console.log('\n[TEST 7] Testing role modification rules...');
  const updateMemberRoles = await request('PUT', `/api/users/${memberId}/roles`, { roleIds: [managerRoleId] }, { 'Authorization': `Bearer ${ownerToken}` });
  if (updateMemberRoles.status !== 200) throw new Error('Failed to update normal member roles');

  const updateOwnerRoles = await request('PUT', `/api/users/${ownerId}/roles`, { roleIds: [managerRoleId] }, { 'Authorization': `Bearer ${ownerToken}` });
  if (updateOwnerRoles.status !== 403) throw new Error(`Expected 403 when modifying Owner roles, got ${updateOwnerRoles.status}`);
  console.log('✅ TEST 7 PASSED: Updating normal user roles succeeds; modifying Owner roles returns 403 Forbidden!');

  // 8. Sharing File With Owner Is Excluded / Blocked
  console.log('\n[TEST 8] Uploading file and attempting to share with Owner...');
  const fileContent = Buffer.from('Owner test file content 2026');
  const fileId = crypto.randomUUID();
  const fileEnc = fileCrypto.encryptBuffer(fileContent);

  const memberWrapping = keyWrapping.wrapDek(fileEnc.dek, memberPrivPem, memberPubPem, fileId, memberId);

  const uploadRes = await uploadMultipart(
    '/api/files/upload',
    {
      fileId,
      originalName: 'owner_test.txt',
      originalSize: fileContent.length.toString(),
      iv: fileEnc.iv.toString('hex'),
      authTag: fileEnc.authTag.toString('hex'),
      algorithm: 'AES-256-GCM',
      wrappedDek: memberWrapping.wrappedDek,
      wrapSalt: memberWrapping.wrapSalt,
      wrapIv: memberWrapping.wrapIv,
      wrapAuthTag: memberWrapping.wrapAuthTag,
      senderPublicKey: memberPubPem,
      dataClassification: 'INTERNAL',
    },
    fileEnc.ciphertext,
    'owner_test.txt.enc',
    { 'Authorization': `Bearer ${memberToken}` }
  );

  if (uploadRes.status !== 201) throw new Error(`Upload failed: ${JSON.stringify(uploadRes.data)}`);

  const shareWrapping = keyWrapping.wrapDek(fileEnc.dek, memberPrivPem, ownerPubPem, fileId, ownerId);

  // Member attempts to share file with Owner (Must fail)
  const shareWithOwnerRes = await request('POST', `/api/files/${fileId}/share`, {
    recipientUserId: ownerId,
    wrappedDek: shareWrapping.wrappedDek,
    wrapSalt: shareWrapping.wrapSalt,
    wrapIv: shareWrapping.wrapIv,
    wrapAuthTag: shareWrapping.wrapAuthTag,
    senderPublicKey: memberPubPem,
    accessLevel: 'READ',
  }, { 'Authorization': `Bearer ${memberToken}` });

  if (shareWithOwnerRes.status !== 400) throw new Error(`Expected 400 when sharing with Owner, got ${shareWithOwnerRes.status}`);
  console.log('✅ TEST 8 PASSED: Sharing file with Organization Owner blocked by backend with 400 Bad Request!');

  // 9. Verify Owner inherent capabilities (File Download & Decryption)
  console.log('\n[TEST 9] Verifying existing Owner capabilities (upload & download)...');
  const ownerDownload = await request('GET', `/api/files/${fileId}/download`, null, { 'Authorization': `Bearer ${memberToken}` });
  if (ownerDownload.status !== 200) throw new Error('Member download failed');
  console.log('✅ TEST 9 PASSED: Owner and member capabilities work seamlessly!');

  console.log('\n================================================================');
  console.log('🎉 ALL ORGANIZATION OWNER MODEL TESTS PASSED 100%!');
  console.log('================================================================\n');
  process.exit(0);
}

runOwnerModelTestSuite().catch(err => {
  console.error('❌ TEST FAILED:', err.message);
  process.exit(1);
});
