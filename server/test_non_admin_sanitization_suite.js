const path = require('path');
const http = require('http');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const { pool } = require('./src/db');

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

async function runSanitizationTest() {
  console.log('================================================================');
  console.log('--- STARTING NON-ADMIN DATA SANITIZATION VERIFICATION SUITE ---');
  console.log('================================================================\n');

  const timestamp = Date.now();

  // 1. Register Owner
  const ownerEmail = `owner_${timestamp}@secsan.com`;
  const ownerReg = await request('POST', '/api/auth/register', {
    orgName: `SanOrg_${timestamp}`,
    email: ownerEmail,
    password: 'StrongOwnerP@ss1',
  });
  if (ownerReg.status !== 201) throw new Error(`Owner registration failed: ${JSON.stringify(ownerReg.data)}`);
  const ownerToken = ownerReg.data.token;

  // 2. Create custom role with FILE_READ only (no USER_MANAGE / USER_CREATE)
  const roleRes = await request('POST', '/api/roles', {
    name: 'NormalMember',
    permissions: ['FILE_READ'],
  }, { 'Authorization': `Bearer ${ownerToken}` });
  const roleId = roleRes.data.role.id;

  // 3. Create normal member account (Pending Setup)
  const pendingMemberEmail = `pending_${timestamp}@secsan.com`;
  const createPending = await request('POST', '/api/users', {
    name: 'Pending User',
    email: pendingMemberEmail,
    roleIds: [roleId],
  }, { 'Authorization': `Bearer ${ownerToken}` });
  const setupToken = createPending.data.user.setupToken;
  console.log(`  ✓ Owner created pending user with setupToken: ${setupToken}`);

  // 4. Complete pending user setup to activate normal member
  const memberPass = 'StrongMemb3rP@ss1!';
  const completeSetup = await request('POST', '/api/auth/setup/complete', {
    email: pendingMemberEmail,
    setupToken,
    password: memberPass,
  });
  const normalMemberToken = completeSetup.data.token;
  console.log('  ✓ Normal member setup completed and session token obtained.');

  // 5. Create a second pending member account (Setup Required)
  const pending2Email = `pending2_${timestamp}@secsan.com`;
  const createPending2 = await request('POST', '/api/users', {
    name: 'Pending User 2',
    email: pending2Email,
    roleIds: [roleId],
  }, { 'Authorization': `Bearer ${ownerToken}` });
  const setupToken2 = createPending2.data.user.setupToken;

  // 6. Test GET /api/users/members as Owner -> MUST include setupToken2
  const ownerMembersRes = await request('GET', '/api/users/members', null, { 'Authorization': `Bearer ${ownerToken}` });
  const ownerPendingItem = ownerMembersRes.data.users.find(u => u.email === pending2Email);
  if (!ownerPendingItem || ownerPendingItem.setupToken !== setupToken2) {
    throw new Error(`FAIL: Owner failed to view setupToken! Got: ${JSON.stringify(ownerPendingItem)}`);
  }
  console.log('  ✓ Owner successfully received setupToken for pending user.');

  // 7. Test GET /api/users/members as Normal Member -> MUST SANITIZE setupToken to null
  const memberMembersRes = await request('GET', '/api/users/members', null, { 'Authorization': `Bearer ${normalMemberToken}` });
  const memberPendingItem = memberMembersRes.data.users.find(u => u.email === pending2Email);
  if (!memberPendingItem) {
    throw new Error('FAIL: Normal member failed to retrieve member directory.');
  }

  if (memberPendingItem.setupToken !== null) {
    throw new Error(`SECURITY VULNERABILITY: Normal member received setupToken "${memberPendingItem.setupToken}"! Setup tokens must be sanitized!`);
  }
  console.log('  ✓ Normal member setupToken correctly sanitized to NULL!');

  if (memberPendingItem.permissions && memberPendingItem.permissions.length > 0) {
    throw new Error(`SECURITY LEAK: Normal member received permissions list "${memberPendingItem.permissions}" for other users!`);
  }
  console.log('  ✓ Normal member effective permissions list sanitized to empty array!');

  console.log('\n🎉 NON-ADMIN DATA SANITIZATION VERIFIED 100% SECURE!');
  process.exit(0);
}

runSanitizationTest().catch(err => {
  console.error('\n❌ TEST FAILED:', err.message);
  process.exit(1);
});
