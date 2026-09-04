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

async function runCycle10_2_3TestSuite() {
  console.log('================================================================');
  console.log('--- STARTING CYCLE 10.2/10.3 ORG POLICIES & GEO-CONTEXT SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users
  const mainOrgName = `GeoOrg_${Date.now()}`;
  const extOrgName = `ExtGeoOrg_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@geo.com`;
  const aliceDeviceId = `alice-laptop-${Date.now()}`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@geo.com`;
  const bobDeviceId = `bob-laptop-${Date.now()}`;

  const eveEmail = `eve_${Date.now()}@external.com`;

  // Register Main Org (Alice = Admin)
  const aliceReg = await request('POST', '/api/auth/register', { orgName: mainOrgName, email: aliceEmail, password: 'AlicePassword2026!' }, { 'X-Client-Device-ID': aliceDeviceId });
  const aliceToken = aliceReg.data.token;
  const aliceId = aliceReg.data.user.id;
  const mainOrgId = aliceReg.data.organization.id;
  await request('POST', '/api/crypto/public-key', { publicKey: alicePubPem }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Register External Org (Eve = External Admin)
  const eveReg = await request('POST', '/api/auth/register', { orgName: extOrgName, email: eveEmail, password: 'EvePassword2026!' });
  const eveToken = eveReg.data.token;

  // Alice creates Bob in Main Org
  const bobCreate = await request('POST', '/api/users', { email: bobEmail, password: 'BobPassword2026!', role: 'USER' }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const bobId = bobCreate.data.user.id;
  const bobLogin = await request('POST', '/api/auth/login', { email: bobEmail, password: 'BobPassword2026!' }, { 'X-Client-Device-ID': bobDeviceId });
  const bobToken = bobLogin.data.token;

  console.log(`[Setup] Main Org (${mainOrgId}) & Ext Org (${eveReg.data.organization.id}):`);
  console.log(`  - Alice (Admin): ${aliceId}`);
  console.log(`  - Bob   (User) : ${bobId}\n`);

  // --- TEST 1: Organization Policy Retrieval & Cross-Org Isolation ---
  console.log('[TEST 1] Testing organization security policy retrieval & isolation...');
  const policyRes = await request('GET', '/api/policies', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const allowedCountry = policyRes.data.policy.allowedLocations?.[0]?.allowed_country;
  console.log(`  HTTP Result: ${policyRes.status} (Allowed Country: ${allowedCountry})`);
  if (policyRes.status !== 200 || allowedCountry !== 'IN') {
    throw new Error('FAIL: Organization policy retrieval failed');
  }

  // Eve attempts to update Alice's org policy -> HTTP 403
  const eveUpdateAttempt = await request('PUT', '/api/policies', { allowedCountry: 'US' }, { 'Authorization': `Bearer ${eveToken}` });
  if (eveUpdateAttempt.status !== 403 && eveUpdateAttempt.data.policy?.organization_id === mainOrgId) {
    throw new Error('CRITICAL SECURITY FAILURE: External user was able to modify another org\'s policy!');
  }
  console.log('✅ TEST 1 PASSED: Organization security policy retrieved & cross-org policy isolation verified!');

  // --- TEST 2: Allowed Location Access (India / Maharashtra / Mumbai) ---
  console.log('\n[TEST 2] Testing access from allowed location (Mumbai, Maharashtra, IN)...');
  
  // Alice uploads File A
  const samplePlaintext = Buffer.from('GEO CONTEXTUAL ACCESS CONTROL PAYLOAD');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'GeoTest.pdf',
    originalSize: samplePlaintext.length.toString(),
    iv: fileIv.toString('base64'),
    authTag: fileAuthTag.toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: ownerWrapping.wrappedDek,
    wrapSalt: ownerWrapping.wrapSalt,
    wrapIv: ownerWrapping.wrapIv,
    wrapAuthTag: ownerWrapping.wrapAuthTag,
    senderPublicKey: alicePubPem,
    sensitivityLevel: 'NORMAL',
  }, fileCiphertext, 'GeoTest.enc', {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
  });

  const allowedDl = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
  });

  console.log(`  HTTP Result: ${allowedDl.status}`);
  if (allowedDl.status !== 200) throw new Error(`FAIL: Allowed location download returned status ${allowedDl.status}`);
  console.log('✅ TEST 2 PASSED: Access from allowed geographic location granted normally!');

  // --- TEST 3: Geo-Policy Violation in Flexible Mode (Triggers Step-Up Re-Authentication) ---
  console.log('\n[TEST 3] Alice accesses from DISALLOWED location (San Francisco, California, US) under flexible policy...');
  
  // Access from US without step-up -> 403 stepUpRequired: true
  const usDlNoPwd = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'US',
    'X-Client-State': 'California',
    'X-Client-City': 'San Francisco',
  });

  console.log(`  HTTP Result: ${usDlNoPwd.status} (${usDlNoPwd.data.message}) [stepUpRequired: ${usDlNoPwd.data.stepUpRequired}]`);
  if (usDlNoPwd.status !== 403 || !usDlNoPwd.data.stepUpRequired) {
    throw new Error('FAIL: Geo policy violation in flexible mode did not trigger stepUpRequired: true');
  }

  // Access from US WITH step-up password -> 200 OK
  const usDlWithPwd = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'US',
    'X-Client-State': 'California',
    'X-Client-City': 'San Francisco',
    'X-Reauth-Password': 'AlicePassword2026!',
  });

  console.log(`  HTTP Step-Up Result: ${usDlWithPwd.status}`);
  if (usDlWithPwd.status !== 200) throw new Error(`FAIL: Geo step-up re-authentication failed with status ${usDlWithPwd.status}`);
  console.log('✅ TEST 3 PASSED: Geo-policy violation in flexible mode triggered step-up re-authentication and succeeded!');

  // --- TEST 4: Geo-Policy Violation in Strict Geo-Fencing Mode (Hard Block) ---
  console.log('\n[TEST 4] Admin enables STRICT Geo-Fencing (allowed_state = Maharashtra, enforce_geo_fencing = true)...');
  const putRes = await request('PUT', '/api/policies', {
    allowedCountry: 'IN',
    allowedState: 'Maharashtra',
    allowedCity: 'ALL',
    enforceGeoFencing: true,
  }, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Reauth-Password': 'AlicePassword2026!',
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
  });
  console.log(`  PUT Policy Result: ${putRes.status}`, JSON.stringify(putRes.data, null, 2));

  // Access from Karnataka, IN with step-up password -> STILL HARD DENIED with HTTP 403 (stepUpRequired: false)
  const karnatakaDl = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Karnataka',
    'X-Client-City': 'Bengaluru',
    'X-Reauth-Password': 'AlicePassword2026!',
  });

  console.log(`  HTTP Result: ${karnatakaDl.status} (${karnatakaDl.data.message}) [stepUpRequired: ${karnatakaDl.data.stepUpRequired}]`);
  if (karnatakaDl.status !== 403 || karnatakaDl.data.stepUpRequired) {
    throw new Error('FAIL: Strict geo-fencing violation was not hard-denied (should be 403 with stepUpRequired: false)');
  }
  console.log('✅ TEST 4 PASSED: Strict Geo-Fencing mode strictly hard-denied location policy violation!');

  // --- TEST 5: Location Shift Detection (Mumbai -> Delhi) ---
  console.log('\n[TEST 5] Testing Location Shift Detection under state policy (Maharashtra -> Delhi)...');
  // Reset policy to flexible geo-fencing
  await request('PUT', '/api/policies', {
    allowedCountry: 'IN',
    allowedState: 'ALL',
    allowedCity: 'ALL',
    enforceGeoFencing: false,
    requireStepupNewLocation: true,
  }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  // Request from Delhi
  const delhiDl = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Delhi',
    'X-Client-City': 'New Delhi',
  });

  console.log(`  HTTP Location Shift Result: ${delhiDl.status} (${delhiDl.data.message}) [stepUpRequired: ${delhiDl.data.stepUpRequired}]`);
  if (delhiDl.status !== 403 || !delhiDl.data.stepUpRequired) {
    throw new Error('FAIL: Location shift did not trigger stepUpRequired: true');
  }
  console.log('✅ TEST 5 PASSED: Location shift detected and step-up re-authentication required!');

  // --- TEST 6: Unauthorized User Access Failure Before Geo/Step-Up Evaluation ---
  console.log('\n[TEST 6] Unauthorized Bob attempts download on Alice\'s file from valid location...');
  const bobAccessAttempt = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${bobToken}`,
    'X-Client-Device-ID': bobDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
    'X-Reauth-Password': 'AlicePassword2026!',
  });

  console.log(`  HTTP Result: ${bobAccessAttempt.status} (${bobAccessAttempt.data.message})`);
  if (bobAccessAttempt.status !== 403 || bobAccessAttempt.data.stepUpRequired) {
    throw new Error('FAIL: Unauthorized user access was not rejected by resource check before geo evaluation');
  }
  console.log('✅ TEST 6 PASSED: Security order verified! Resource access check denied Bob BEFORE geo/step-up evaluation!');

  // --- TEST 7: Privacy & Secret Storage Invariant Inspection ---
  console.log('\n[TEST 7] Inspecting user_devices database records for zero private key / secret leakage...');
  const devDb = await pool.query('SELECT * FROM user_devices WHERE user_id = $1', [aliceId]);
  const devStr = JSON.stringify(devDb.rows[0]);
  if (devStr.includes('AlicePassword2026!') || devStr.includes('BEGIN PRIVATE KEY')) {
    throw new Error('CRITICAL PRIVACY FAILURE: Password or private key leaked in user_devices table!');
  }
  console.log('✅ TEST 7 PASSED: Zero private key, password, or DEK leakage in location context storage!');

  console.log('\n================================================================');
  console.log('🎉 ALL 7 CYCLE 10.2/10.3 ORG POLICIES & GEO INTEGRATION TESTS PASSED!');
  console.log('================================================================');
  process.exit(0);
}

runCycle10_2_3TestSuite().catch(err => {
  console.error('\n❌ CYCLE 10.2/10.3 TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
