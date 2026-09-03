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

async function testAdminCreateUserFlow() {
  console.log('--- TESTING ADMIN CREATE USER API FLOW ---');
  
  const orgName = `AdminTestOrg_${Date.now()}`;
  const adminEmail = `admin_${Date.now()}@admintest.org`;
  const newUserEmail = `newuser_${Date.now()}@admintest.org`;

  // 1. Register Admin
  const regRes = await request('POST', '/api/auth/register', { orgName, email: adminEmail, password: 'AdminPassword2026!' });
  if (regRes.status !== 201) throw new Error(`Admin registration failed: ${JSON.stringify(regRes.data)}`);
  
  const adminToken = regRes.data.token;
  const adminOrgId = regRes.data.organization.id;
  console.log(`✅ Admin registered in Org (${adminOrgId}): ${adminEmail}`);

  // 2. Admin creates new user via POST /api/users
  const createRes = await request('POST', '/api/users', { email: newUserEmail, password: 'UserPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${adminToken}` });
  if (createRes.status !== 201) throw new Error(`User creation failed (Status ${createRes.status}): ${JSON.stringify(createRes.data)}`);
  
  const createdUserId = createRes.data.user.id;
  console.log(`✅ Admin created new user via POST /api/users: ${createdUserId} (${newUserEmail})`);

  // 3. Verify in PostgreSQL
  const dbUser = await pool.query('SELECT id, email, organization_id, role FROM users WHERE id = $1', [createdUserId]);
  if (dbUser.rows.length === 0) throw new Error('FAIL: Created user missing from PostgreSQL!');
  if (dbUser.rows[0].organization_id !== adminOrgId) throw new Error('FAIL: Created user organization mismatch!');

  console.log(`✅ PostgreSQL Verification: User exists in database with organization_id=${dbUser.rows[0].organization_id} and role=${dbUser.rows[0].role}`);

  // 4. Admin lists org members via GET /api/users/members
  const membersRes = await request('GET', '/api/users/members', null, { 'Authorization': `Bearer ${adminToken}` });
  if (membersRes.status !== 200) throw new Error(`List members failed: ${JSON.stringify(membersRes.data)}`);

  const foundInMembers = membersRes.data.users.find(u => u.id === createdUserId);
  if (!foundInMembers) throw new Error('FAIL: Created user not returned by GET /api/users/members!');

  console.log('✅ GET /api/users/members Verification: Created user present in Admin organization member list!');
  console.log('\n🎉 ALL ADMIN CREATE USER TESTS PASSED 100%!');
  process.exit(0);
}

testAdminCreateUserFlow().catch(err => {
  console.error('❌ TEST FAILED:', err.message);
  process.exit(1);
});
