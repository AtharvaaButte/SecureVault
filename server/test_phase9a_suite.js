const path = require('path');
const http = require('http');
const jwt = require('jsonwebtoken');
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

async function runPhase9ATestSuite() {
  console.log('================================================================');
  console.log('--- STARTING PHASE 9A IDENTITY & REQUEST VERIFICATION SUITE ---');
  console.log('================================================================\n');

  const secret = process.env.JWT_SECRET;
  const orgName = `Phase9A_Org_${Date.now()}`;
  const aliceEmail = `alice_${Date.now()}@phase9a.org`;

  // --- TEST 1: Missing Token Rejection (HTTP 401) ---
  console.log('[TEST 1] Testing sensitive endpoint with NO Authorization header...');
  const noTokenRes = await request('GET', '/api/files');
  console.log(`  HTTP Result: ${noTokenRes.status} (${noTokenRes.data.message})`);
  if (noTokenRes.status !== 401) throw new Error(`FAIL: Missing token returned status ${noTokenRes.status}`);
  console.log('✅ TEST 1 PASSED: Unauthenticated request rejected with HTTP 401!');

  // --- TEST 2: Invalid / Expired Token Rejection (HTTP 401) ---
  console.log('\n[TEST 2] Testing sensitive endpoint with invalid/forged JWT...');
  const forgedToken = jwt.sign({ userId: 'fake-id', orgId: 'fake-org', role: 'ADMIN' }, 'WRONG_SECRET_KEY');
  const invalidTokenRes = await request('GET', '/api/files', null, { 'Authorization': `Bearer ${forgedToken}` });
  console.log(`  HTTP Result: ${invalidTokenRes.status} (${invalidTokenRes.data.message})`);
  if (invalidTokenRes.status !== 401) throw new Error(`FAIL: Forged token returned status ${invalidTokenRes.status}`);
  console.log('✅ TEST 2 PASSED: Forged/invalid token rejected with HTTP 401!');

  // --- TEST 3: Frontend-Supplied Identity Override Prevention ---
  console.log('\n[TEST 3] Testing frontend attempt to override userId/orgId in request body...');
  const regRes = await request('POST', '/api/auth/register', { orgName, email: aliceEmail, password: 'AlicePassword2026!' });
  const aliceToken = regRes.data.token;
  const aliceId = regRes.data.user.id;

  // Alice tries sending a request with malicious userId override in body
  const bodyOverrideRes = await request('GET', '/api/auth/me', { userId: 'victim-user-id', orgId: 'victim-org-id' }, { 'Authorization': `Bearer ${aliceToken}` });
  console.log(`  HTTP Result: ${bodyOverrideRes.status} (Authenticated Email: ${bodyOverrideRes.data.user.email})`);
  if (bodyOverrideRes.data.user.id !== aliceId) {
    throw new Error('CRITICAL FAILURE: Server accepted client-supplied userId override!');
  }
  console.log('✅ TEST 3 PASSED: Server derived identity ONLY from verified server-side JWT context!');

  // --- TEST 4: Device / Session Context Verification ---
  console.log('\n[TEST 4] Testing Device Context verification (X-Client-Device-ID header mismatch)...');
  const tokenWithDevice = jwt.sign({ userId: aliceId, orgId: regRes.data.organization.id, role: 'ADMIN', deviceId: 'device-laptop-alice' }, secret);

  // Match device ID header -> OK
  const deviceMatchRes = await request('GET', '/api/files', null, {
    'Authorization': `Bearer ${tokenWithDevice}`,
    'X-Client-Device-ID': 'device-laptop-alice',
  });
  if (deviceMatchRes.status !== 200) throw new Error(`Device match request failed with status ${deviceMatchRes.status}`);

  // Mismatch device ID header -> HTTP 401
  const deviceMismatchRes = await request('GET', '/api/files', null, {
    'Authorization': `Bearer ${tokenWithDevice}`,
    'X-Client-Device-ID': 'stolen-device-charlie',
  });
  console.log(`  Device Mismatch Result: ${deviceMismatchRes.status} (${deviceMismatchRes.data.message})`);
  if (deviceMismatchRes.status !== 401) throw new Error(`FAIL: Mismatched device ID returned status ${deviceMismatchRes.status}`);
  console.log('✅ TEST 4 PASSED: Device context mismatch properly rejected with HTTP 401!');

  // --- TEST 5: Fail-Closed Context Validation ---
  console.log('\n[TEST 5] Testing fail-closed context validation (token missing orgId claim)...');
  const incompleteToken = jwt.sign({ userId: aliceId, role: 'USER' }, secret); // missing orgId
  const failClosedRes = await request('GET', '/api/files', null, { 'Authorization': `Bearer ${incompleteToken}` });
  console.log(`  HTTP Fail-Closed Result: ${failClosedRes.status} (${failClosedRes.data.message})`);
  if (failClosedRes.status !== 401) throw new Error(`FAIL: Incomplete token returned status ${failClosedRes.status}`);
  console.log('✅ TEST 5 PASSED: Incomplete context token strictly failed closed with HTTP 401!');

  console.log('\n================================================================');
  console.log('🎉 ALL PHASE 9A IDENTITY VERIFICATION TESTS PASSED 100%!');
  console.log('================================================================');
  process.exit(0);
}

runPhase9ATestSuite().catch(err => {
  console.error('\n❌ PHASE 9A TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
