const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { initGeoLocationService, extractLocation, isLocalOrPrivateIp } = require('./src/services/geoLocationService');

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

async function runGeoIP2LocationTestSuite() {
  console.log('================================================================');
  console.log('--- STARTING IP2LOCATION LITE GEO-CONTEXT INTEGRATION SUITE ---');
  console.log('================================================================\n');

  // Initialize service
  initGeoLocationService();

  // --- TEST 1: Local & Private IP Address Handling ---
  console.log('[TEST 1] Testing local/private IP address detection...');
  const localIps = ['127.0.0.1', '::1', '192.168.1.100', '10.0.4.15', '172.16.0.5'];
  for (const ip of localIps) {
    const isLocal = isLocalOrPrivateIp(ip);
    if (!isLocal) throw new Error(`FAIL: IP ${ip} should be recognized as local/private.`);
  }

  const reqLocal = { socket: { remoteAddress: '127.0.0.1' }, headers: {} };
  const locLocal = extractLocation(reqLocal);
  console.log(`  Local IP Location Context: IP=${locLocal.ip}, Label=${locLocal.regionLabel}, isLocal=${locLocal.isLocal}`);
  if (!locLocal.isLocal || locLocal.regionLabel !== 'LOCAL/DEV') {
    throw new Error('FAIL: Local IP should return regionLabel LOCAL/DEV');
  }
  console.log('✅ TEST 1 PASSED: Local/private IPs detected and handled gracefully!');

  // --- TEST 2: IP2Location BIN Database Lookup ---
  console.log('\n[TEST 2] Testing IP2Location LITE DB3 BIN lookup for public IP (8.8.8.8)...');
  const reqPublic = { headers: { 'x-forwarded-for': '8.8.8.8' }, socket: { remoteAddress: '8.8.8.8' } };
  const locPublic = extractLocation(reqPublic);
  console.log(`  Public IP Location Context: IP=${locPublic.ip}, Country=${locPublic.country}, State=${locPublic.state}, City=${locPublic.city}, Label=${locPublic.regionLabel}`);
  if (!locPublic.country || !locPublic.state || !locPublic.city || locPublic.regionLabel.includes('INVALID')) {
    throw new Error(`FAIL: IP2Location lookup returned invalid format: ${locPublic.regionLabel}`);
  }
  console.log('✅ TEST 2 PASSED: IP2Location LITE DB3 BIN lookup returned approximate Country, State, and City!');

  // --- TEST 3: Allowed Location Access under Organization Policy ---
  console.log('\n[TEST 3] Testing access from allowed location under organization policy...');
  const orgName = `GeoOrg_${Date.now()}`;
  const adminEmail = `admin_${Date.now()}@geo.com`;
  const regRes = await request('POST', '/api/auth/register', { orgName, email: adminEmail, password: 'AdminPassword2026!' });
  const token = regRes.data.token;

  // Add allowed location IN / Maharashtra / Mumbai
  await request('POST', '/api/policies/locations', { allowed_country: 'IN', allowed_state: 'Maharashtra', allowed_city: 'ALL' }, { 'Authorization': `Bearer ${token}` });

  // Access from allowed location (Mumbai, Maharashtra, IN)
  const allowedRes = await request('GET', '/api/policies', null, {
    'Authorization': `Bearer ${token}`,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
  });
  console.log(`  Allowed Location HTTP Status: ${allowedRes.status}`);
  if (allowedRes.status !== 200) {
    throw new Error(`FAIL: Allowed location request failed with status ${allowedRes.status}`);
  }
  console.log('✅ TEST 3 PASSED: Request from allowed location granted access normally!');

  // --- TEST 4: Disallowed Location Policy Evaluation ---
  console.log('\n[TEST 4] Testing request from disallowed location (San Francisco, California, US)...');
  const disallowedRes = await request('GET', '/api/policies', null, {
    'Authorization': `Bearer ${token}`,
    'X-Client-Country': 'US',
    'X-Client-State': 'California',
    'X-Client-City': 'San Francisco',
  });
  console.log(`  Disallowed Location Result: Status=${disallowedRes.status}, StepUpRequired=${disallowedRes.data.stepUpRequired}`);
  if (disallowedRes.status !== 403 || !disallowedRes.data.stepUpRequired) {
    throw new Error('FAIL: Disallowed location should trigger step-up requirement with HTTP 403');
  }
  console.log('✅ TEST 4 PASSED: Disallowed location triggered step-up re-authentication!');

  // --- TEST 5: Security Audit Log Verification ---
  console.log('\n[TEST 5] Verifying location context in security audit logs...');
  const auditRes = await request('GET', '/api/audit', null, { 'Authorization': `Bearer ${token}` });
  console.log(`  Audit Logs Count: ${auditRes.data.logs?.length}`);
  if (auditRes.status !== 200 || !auditRes.data.logs || auditRes.data.logs.length === 0) {
    throw new Error('FAIL: Audit log retrieval failed');
  }
  const latestLog = auditRes.data.logs[0];
  console.log(`  Latest Audit Event: ${latestLog.event_type}, LocationLabel=${latestLog.location_label}`);
  if (!latestLog.location_label) {
    throw new Error('FAIL: Audit log record missing location_label');
  }
  console.log('✅ TEST 5 PASSED: Location context recorded cleanly in tamper-evident audit logs!');

  console.log('\n================================================================');
  console.log('🎉 ALL 5 IP2LOCATION LITE GEO-CONTEXT TESTS PASSED 100%!');
  console.log('================================================================\n');
}

runGeoIP2LocationTestSuite().catch(err => {
  console.error('\n❌ GEO-CONTEXT TEST SUITE FAILED:', err.message);
  process.exit(1);
});
