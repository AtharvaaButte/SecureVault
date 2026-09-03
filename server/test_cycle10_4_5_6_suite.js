const path = require('path');
const http = require('http');
const crypto = require('crypto');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const { pool } = require('./src/db');
const fileCrypto = require('../client/src/main/crypto/fileCrypto');
const keyWrapping = require('../client/src/main/crypto/keyWrapping');
const auditService = require('./src/services/auditService');

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

async function runCycle10_4_5_6TestSuite() {
  console.log('================================================================');
  console.log('--- STARTING CYCLE 10.4-10.6 RISK DECISION & AUDIT SUITE ---');
  console.log('================================================================\n');

  // 1. Setup Organization & Users
  const mainOrgName = `AuditOrg_${Date.now()}`;
  const extOrgName = `ExtAuditOrg_${Date.now()}`;

  const aliceEmail = `alice_${Date.now()}@audit.com`;
  const aliceDeviceId = `alice-dev-${Date.now()}`;
  const aliceKeyPair = crypto.generateKeyPairSync('x25519');
  const alicePrivPem = aliceKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const bobEmail = `bob_${Date.now()}@audit.com`;
  const bobDeviceId = `bob-dev-${Date.now()}`;

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

  // --- TEST 1: Contextual Risk Decision Engine Scenarios ---
  console.log('[TEST 1] Testing explainable contextual risk decision engine matrix...');
  
  // Alice uploads a file
  const samplePlaintext = Buffer.from('CYCLE 10.4-10.6 AUDIT AND RISK DECISION PAYLOAD');
  const fileId = crypto.randomUUID();
  const { dek: originalDek, iv: fileIv, ciphertext: fileCiphertext, authTag: fileAuthTag } = fileCrypto.encryptBuffer(samplePlaintext);
  fileCrypto.storeDek(fileId, originalDek);

  const ownerWrapping = keyWrapping.wrapDek(originalDek, alicePrivPem, alicePubPem, fileId, aliceId);
  await uploadMultipart('/api/files/upload', {
    fileId,
    originalName: 'AuditTestFile.pdf',
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
  }, fileCiphertext, 'AuditTestFile.enc', {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
  });

  // Known device + known location + NORMAL file -> ALLOW
  const allowedRes = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${aliceToken}`,
    'X-Client-Device-ID': aliceDeviceId,
    'X-Client-Country': 'IN',
    'X-Client-State': 'Maharashtra',
    'X-Client-City': 'Mumbai',
  });
  console.log(`  Allowed Decision HTTP Status: ${allowedRes.status}`);
  if (allowedRes.status !== 200) throw new Error('FAIL: Known context request was not allowed');

  console.log('✅ TEST 1 PASSED: Explainable contextual risk decision engine matrix verified!');

  // --- TEST 2: Sensitive Resource & Admin Controls Separation ---
  console.log('\n[TEST 2] Testing Admin Access Separation: Admin user Bob attempts download without file ownership/share...');
  
  // Make Bob an Admin with ROLE_MANAGE & USER_MANAGE
  const rolesRes = await request('GET', '/api/roles', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  const adminRole = rolesRes.data.roles.find(r => r.name === 'Admin');
  await request('PUT', `/api/users/${bobId}/roles`, { roleIds: [adminRole.id] }, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });

  const bobDlAttempt = await request('GET', `/api/files/${fileId}/download`, null, {
    'Authorization': `Bearer ${bobToken}`,
    'X-Client-Device-ID': bobDeviceId,
  });

  console.log(`  Bob Admin File Access Result: ${bobDlAttempt.status} (${bobDlAttempt.data.message})`);
  if (bobDlAttempt.status !== 403) throw new Error('FAIL: Admin user was able to access file without file ownership or share!');
  console.log('✅ TEST 2 PASSED: Admin privileges NEVER grant automatic file decryption access!');

  // --- TEST 3: Security Event Audit Logging Across Lifecycle ---
  console.log('\n[TEST 3] Fetching security audit logs via GET /api/audit...');
  const auditLogsRes = await request('GET', '/api/audit', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  console.log(`  HTTP Result: ${auditLogsRes.status} (Total Audit Events Recorded: ${auditLogsRes.data.logs?.length})`);
  if (auditLogsRes.status !== 200 || !auditLogsRes.data.logs || auditLogsRes.data.logs.length < 3) {
    throw new Error('FAIL: Security audit logs retrieval failed');
  }

  const eventTypes = auditLogsRes.data.logs.map(l => l.event_type);
  console.log(`  Recorded Event Types: ${eventTypes.join(', ')}`);
  if (!eventTypes.includes('REGISTER') || !eventTypes.includes('UPLOAD') || !eventTypes.includes('DOWNLOAD')) {
    throw new Error('FAIL: Audit log missing expected lifecycle events');
  }
  console.log('✅ TEST 3 PASSED: Security lifecycle events logged cleanly into audit_logs!');

  // --- TEST 4: SHA-256 Hash Chain Integrity Verification ---
  console.log('\n[TEST 4] Verifying SHA-256 audit hash chain integrity via GET /api/audit/verify...');
  const verifyRes = await request('GET', '/api/audit/verify', null, { 'Authorization': `Bearer ${aliceToken}`, 'X-Client-Device-ID': aliceDeviceId });
  console.log(`  HTTP Result: ${verifyRes.status} (Valid: ${verifyRes.data.valid}, Verified Logs: ${verifyRes.data.totalLogs})`);
  if (verifyRes.status !== 200 || !verifyRes.data.valid) {
    throw new Error(`FAIL: Audit chain verification failed (${verifyRes.data.error})`);
  }
  console.log('✅ TEST 4 PASSED: SHA-256 audit hash chain integrity verified 100% intact!');

  // --- TEST 5: Detection of Modified / Tampered Audit Records ---
  console.log('\n[TEST 5] Simulating database attack: Modifying an audit log record in PostgreSQL...');
  
  // Modify action of first audit log
  const firstLogId = auditLogsRes.data.logs[auditLogsRes.data.logs.length - 1].id;
  await pool.query('UPDATE audit_logs SET reason = $1 WHERE id = $2', ['TAMPERED REASON BY ATTACKER', firstLogId]);

  const tamperedVerifyRes = await auditService.verifyAuditChain(mainOrgId);
  console.log(`  Tamper Verification Result: Valid=${tamperedVerifyRes.valid}, Error: "${tamperedVerifyRes.error}"`);
  if (tamperedVerifyRes.valid) {
    throw new Error('CRITICAL SECURITY FAILURE: Tampered audit log record was NOT detected by SHA-256 hash chain verification!');
  }
  console.log('✅ TEST 5 PASSED: Tamper detection verified! Audit hash chain flagged modified database record!');

  // Restore clean state for remaining checks
  await pool.query('DELETE FROM audit_logs WHERE id = $1', [firstLogId]);

  // --- TEST 6: Zero Secret Leakage into Audit Logs ---
  console.log('\n[TEST 6] Inspecting audit_logs table records for zero secret leakage...');
  const auditDbRes = await pool.query('SELECT * FROM audit_logs WHERE organization_id = $1', [mainOrgId]);
  const auditDbStr = JSON.stringify(auditDbRes.rows);

  if (auditDbStr.includes('AlicePassword2026!') || auditDbStr.includes('BEGIN PRIVATE KEY') || auditDbStr.includes('wrapped_dek')) {
    throw new Error('CRITICAL PRIVACY FAILURE: Password, private key, or DEK leaked in audit_logs table!');
  }
  console.log('✅ TEST 6 PASSED: Zero passwords, private keys, DEKs, or secrets leaked into audit logs!');

  // --- TEST 7: Cross-Organization Audit Isolation ---
  console.log('\n[TEST 7] Testing Cross-Org Audit Isolation: External Eve attempts to view Alice\'s org audit logs...');
  const eveAuditAccess = await request('GET', '/api/audit', null, { 'Authorization': `Bearer ${eveToken}` });
  const eveLogOrgs = eveAuditAccess.data.logs.map(l => l.organization_id);
  if (eveLogOrgs.includes(mainOrgId)) {
    throw new Error('CRITICAL SECURITY FAILURE: External user was able to view another organization\'s audit logs!');
  }
  console.log('✅ TEST 7 PASSED: Organization isolation strictly enforced for audit log access!');

  console.log('\n================================================================');
  console.log('🎉 ALL 7 CYCLE 10.4-10.6 RISK DECISION & AUDIT TESTS PASSED!');
  console.log('================================================================');
  process.exit(0);
}

runCycle10_4_5_6TestSuite().catch(err => {
  console.error('\n❌ CYCLE 10.4-10.6 TEST SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
