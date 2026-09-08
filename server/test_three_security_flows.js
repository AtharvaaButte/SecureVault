const path = require('path');
const http = require('http');
const crypto = require('crypto');

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

async function runThreeSecurityFlowsTest() {
  console.log('================================================================');
  console.log('--- STARTING 3 SECUREVAULT SECURITY FLOWS VERIFICATION SUITE ---');
  console.log('================================================================\n');

  // --- 1. STRONG PASSWORD VALIDATION TESTS ---
  console.log('[FLOW 1] Testing Strong Password Validation Enforcements...');

  const weakPasswords = [
    { pass: 'short', reason: 'Length < 8' },
    { pass: 'nouppercase1!', reason: 'Missing uppercase' },
    { pass: 'NOLOWERCASE1!', reason: 'Missing lowercase' },
    { pass: 'NoNumberSpec!', reason: 'Missing number' },
    { pass: 'NoSpecial1234', reason: 'Missing special character' },
  ];

  for (const item of weakPasswords) {
    const weakReg = await request('POST', '/api/auth/register', {
      orgName: 'WeakOrg',
      email: `weak_${Date.now()}@test.com`,
      password: item.pass,
    });
    if (weakReg.status !== 400) {
      throw new Error(`FAIL: Weak password "${item.pass}" (${item.reason}) was NOT rejected! Status: ${weakReg.status}`);
    }
    console.log(`  ✓ Weak password "${item.pass}" (${item.reason}) correctly rejected with HTTP 400: "${weakReg.data.message}"`);
  }

  // Register with strong password
  const timestamp = Date.now();
  const ownerEmail = `owner_${timestamp}@secvault.com`;
  const ownerPass = 'StrongOwnerP@ss1';
  const ownerReg = await request('POST', '/api/auth/register', {
    orgName: `SecOrg_${timestamp}`,
    name: 'Vault Owner',
    email: ownerEmail,
    password: ownerPass,
  });

  if (ownerReg.status !== 201) {
    throw new Error(`FAIL: Strong password owner registration failed with status ${ownerReg.status}: ${JSON.stringify(ownerReg.data)}`);
  }
  const ownerToken = ownerReg.data.token;
  const ownerId = ownerReg.data.user.id;
  console.log('✅ FLOW 1 PASSED: Strong password validation enforced end-to-end!\n');

  // --- 2. ACCOUNT SETUP / SETUP TOKEN FLOW TESTS ---
  console.log('[FLOW 2] Testing Account Setup & Setup Token Lifecycle Flow...');

  // Create role for member
  const roleRes = await request('POST', '/api/roles', {
    name: 'SecMember',
    permissions: ['FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE'],
  }, { 'Authorization': `Bearer ${ownerToken}` });
  const roleId = roleRes.data.role.id;

  // Admin creates pending user without password
  const pendingEmail = `pending_${timestamp}@secvault.com`;
  const createPending = await request('POST', '/api/users', {
    name: 'Pending Member',
    email: pendingEmail,
    roleIds: [roleId],
  }, { 'Authorization': `Bearer ${ownerToken}` });

  if (createPending.status !== 201 || createPending.data.user.status !== 'SETUP_REQUIRED') {
    throw new Error(`FAIL: Admin user creation without password failed: ${JSON.stringify(createPending.data)}`);
  }

  const setupToken = createPending.data.user.setupToken;
  console.log(`  ✓ Member created with status SETUP_REQUIRED (Setup Token: ${setupToken})`);

  // Attempt login before setup -> MUST BE DENIED 403 setupRequired
  const preLogin = await request('POST', '/api/auth/login', { email: pendingEmail, password: 'AnyPassword123!' });
  if (preLogin.status !== 403 || !preLogin.data.setupRequired) {
    throw new Error(`FAIL: Pre-setup login returned status ${preLogin.status} instead of 403 setupRequired`);
  }
  console.log(`  ✓ Pre-setup login denied with 403 setupRequired: "${preLogin.data.message}"`);

  // Validate setup token via POST /api/auth/setup/verify
  const setupCheck = await request('POST', '/api/auth/setup/verify', { email: pendingEmail, setupToken });
  if (setupCheck.status !== 200 || !setupCheck.data.valid) {
    throw new Error(`FAIL: Setup token check failed: ${JSON.stringify(setupCheck.data)}`);
  }
  console.log('  ✓ Setup token verified successfully via POST /api/auth/setup/verify');

  // Complete setup with weak password -> MUST BE REJECTED 400
  const weakSetup = await request('POST', '/api/auth/setup/complete', { email: pendingEmail, setupToken, password: 'weak' });
  if (weakSetup.status !== 400) {
    throw new Error(`FAIL: Account setup with weak password was not rejected: ${weakSetup.status}`);
  }
  console.log(`  ✓ Setup with weak password rejected with 400: "${weakSetup.data.message}"`);

  // Complete setup with strong password
  const memberPass = 'StrongMemb3rP@ss!';
  const completeSetup = await request('POST', '/api/auth/setup/complete', {
    email: pendingEmail,
    setupToken,
    password: memberPass,
    securityHint: 'Favorite security algorithm: AES-256',
  });

  if (completeSetup.status !== 200) {
    throw new Error(`FAIL: Complete setup failed with status ${completeSetup.status}: ${JSON.stringify(completeSetup.data)}`);
  }
  console.log('  ✓ Account setup completed successfully! Status updated to ACTIVE.');

  // Attempt setup token reuse -> MUST BE DENIED 400
  const reuseCheck = await request('POST', '/api/auth/setup/complete', { email: pendingEmail, setupToken, password: memberPass });
  if (reuseCheck.status !== 400) {
    throw new Error(`FAIL: Reusing completed setup token was not denied: ${reuseCheck.status}`);
  }
  console.log('  ✓ Setup token single-use enforced; reuse attempt denied with 400.');

  // Login after setup completion -> MUST SUCCEED
  const postLogin = await request('POST', '/api/auth/login', { email: pendingEmail, password: memberPass });
  if (postLogin.status !== 200 || !postLogin.data.token) {
    throw new Error(`FAIL: Login after setup completion failed: ${JSON.stringify(postLogin.data)}`);
  }
  const memberToken = postLogin.data.token;
  const memberId = postLogin.data.user.id;
  console.log('✅ FLOW 2 PASSED: Account setup token lifecycle verified 100%!\n');

  // --- 3. FILE CLASSIFICATION + STEP-UP AUTHENTICATION TESTS ---
  console.log('[FLOW 3] Testing Data Classification & Step-Up Re-Authentication Flow...');

  const keyPair = crypto.generateKeyPairSync('x25519');
  const pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });
  await request('POST', '/api/crypto/public-key', { publicKey: pubPem }, { 'Authorization': `Bearer ${memberToken}` });

  // 3a. Upload PUBLIC file -> Download requires NO step-up
  const pubFileId = crypto.randomUUID();
  const pubPlaintext = Buffer.from('PUBLIC DATA PAYLOAD');
  await uploadMultipart('/api/files/upload', {
    fileId: pubFileId,
    originalName: 'PublicDoc.txt',
    originalSize: pubPlaintext.length.toString(),
    iv: Buffer.alloc(12).toString('base64'),
    authTag: Buffer.alloc(16).toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: 'dummy_wrapped_dek',
    wrapSalt: 'dummy_salt',
    wrapIv: 'dummy_iv',
    wrapAuthTag: 'dummy_tag',
    senderPublicKey: pubPem,
    sensitivityLevel: 'PUBLIC',
  }, pubPlaintext, 'PublicDoc.enc', { 'Authorization': `Bearer ${memberToken}` });

  const pubDl = await request('GET', `/api/files/${pubFileId}/download`, null, { 'Authorization': `Bearer ${memberToken}` });
  if (pubDl.status !== 200) {
    throw new Error(`FAIL: PUBLIC file download failed with status ${pubDl.status}`);
  }
  console.log('  ✓ PUBLIC file downloaded without step-up re-authentication!');

  // 3b. Upload INTERNAL file -> Download requires NO step-up
  const intFileId = crypto.randomUUID();
  const intPlaintext = Buffer.from('INTERNAL DATA PAYLOAD');
  await uploadMultipart('/api/files/upload', {
    fileId: intFileId,
    originalName: 'InternalDoc.txt',
    originalSize: intPlaintext.length.toString(),
    iv: Buffer.alloc(12).toString('base64'),
    authTag: Buffer.alloc(16).toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: 'dummy_wrapped_dek',
    wrapSalt: 'dummy_salt',
    wrapIv: 'dummy_iv',
    wrapAuthTag: 'dummy_tag',
    senderPublicKey: pubPem,
    sensitivityLevel: 'INTERNAL',
  }, intPlaintext, 'InternalDoc.enc', { 'Authorization': `Bearer ${memberToken}` });

  const intDl = await request('GET', `/api/files/${intFileId}/download`, null, { 'Authorization': `Bearer ${memberToken}` });
  if (intDl.status !== 200) {
    throw new Error(`FAIL: INTERNAL file download failed with status ${intDl.status}`);
  }
  console.log('  ✓ INTERNAL file downloaded without step-up re-authentication!');

  // 3c. Upload CONFIDENTIAL file -> Download without X-Reauth-Password MUST RETURN 403 stepUpRequired
  const confFileId = crypto.randomUUID();
  const confPlaintext = Buffer.from('CONFIDENTIAL DATA PAYLOAD');
  await uploadMultipart('/api/files/upload', {
    fileId: confFileId,
    originalName: 'ConfidentialDoc.txt',
    originalSize: confPlaintext.length.toString(),
    iv: Buffer.alloc(12).toString('base64'),
    authTag: Buffer.alloc(16).toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: 'dummy_wrapped_dek',
    wrapSalt: 'dummy_salt',
    wrapIv: 'dummy_iv',
    wrapAuthTag: 'dummy_tag',
    senderPublicKey: pubPem,
    sensitivityLevel: 'CONFIDENTIAL',
  }, confPlaintext, 'ConfidentialDoc.enc', { 'Authorization': `Bearer ${memberToken}` });

  const confNoPwd = await request('GET', `/api/files/${confFileId}/download`, null, { 'Authorization': `Bearer ${memberToken}` });
  if (confNoPwd.status !== 403 || !confNoPwd.data.stepUpRequired) {
    throw new Error(`FAIL: CONFIDENTIAL download without step-up password returned status ${confNoPwd.status}`);
  }
  console.log(`  ✓ CONFIDENTIAL download without step-up password correctly blocked with 403 stepUpRequired: "${confNoPwd.data.message}"`);

  // Download with WRONG X-Reauth-Password -> DENIED 403
  const confWrongPwd = await request('GET', `/api/files/${confFileId}/download`, null, {
    'Authorization': `Bearer ${memberToken}`,
    'X-Reauth-Password': 'WrongPassword123!',
  });
  if (confWrongPwd.status !== 403 || confWrongPwd.data.decisionCode !== 'DENY_INVALID_STEP_UP_PASSWORD') {
    throw new Error(`FAIL: CONFIDENTIAL download with wrong step-up password returned status ${confWrongPwd.status}`);
  }
  console.log(`  ✓ CONFIDENTIAL download with wrong step-up password correctly DENIED with 403: "${confWrongPwd.data.message}"`);

  // Download with CORRECT X-Reauth-Password -> SUCCEED 200
  const confRightPwd = await request('GET', `/api/files/${confFileId}/download`, null, {
    'Authorization': `Bearer ${memberToken}`,
    'X-Reauth-Password': memberPass,
  });
  if (confRightPwd.status !== 200) {
    throw new Error(`FAIL: CONFIDENTIAL download with correct step-up password failed: ${confRightPwd.status}`);
  }
  console.log('  ✓ CONFIDENTIAL download with valid step-up password SUCCEEDED!');

  // 3d. Upload HIGHLY_CONFIDENTIAL file -> Download without X-Reauth-Password MUST RETURN 403 stepUpRequired
  const highlyFileId = crypto.randomUUID();
  const highlyPlaintext = Buffer.from('HIGHLY CONFIDENTIAL DATA PAYLOAD');
  await uploadMultipart('/api/files/upload', {
    fileId: highlyFileId,
    originalName: 'HighlyConfidentialDoc.txt',
    originalSize: highlyPlaintext.length.toString(),
    iv: Buffer.alloc(12).toString('base64'),
    authTag: Buffer.alloc(16).toString('base64'),
    algorithm: 'AES-256-GCM',
    wrappedDek: 'dummy_wrapped_dek',
    wrapSalt: 'dummy_salt',
    wrapIv: 'dummy_iv',
    wrapAuthTag: 'dummy_tag',
    senderPublicKey: pubPem,
    sensitivityLevel: 'HIGHLY_CONFIDENTIAL',
  }, highlyPlaintext, 'HighlyConfidentialDoc.enc', { 'Authorization': `Bearer ${memberToken}` });

  const highlyNoPwd = await request('GET', `/api/files/${highlyFileId}/download`, null, { 'Authorization': `Bearer ${memberToken}` });
  if (highlyNoPwd.status !== 403 || !highlyNoPwd.data.stepUpRequired) {
    throw new Error(`FAIL: HIGHLY_CONFIDENTIAL download without step-up password returned status ${highlyNoPwd.status}`);
  }
  console.log(`  ✓ HIGHLY_CONFIDENTIAL download without step-up password correctly blocked with 403 stepUpRequired: "${highlyNoPwd.data.message}"`);

  // Download with CORRECT X-Reauth-Password -> SUCCEED 200
  const highlyRightPwd = await request('GET', `/api/files/${highlyFileId}/download`, null, {
    'Authorization': `Bearer ${memberToken}`,
    'X-Reauth-Password': memberPass,
  });
  if (highlyRightPwd.status !== 200) {
    throw new Error(`FAIL: HIGHLY_CONFIDENTIAL download with correct step-up password failed: ${highlyRightPwd.status}`);
  }
  console.log('  ✓ HIGHLY_CONFIDENTIAL download with valid step-up password SUCCEEDED!');

  console.log('✅ FLOW 3 PASSED: File Data Classification & Step-Up Re-Authentication verified 100%!\n');

  console.log('================================================================');
  console.log('🎉 ALL 3 SECUREVAULT SECURITY FLOWS VERIFIED 100% SUCCESSFULLY!');
  console.log('================================================================');
  process.exit(0);
}

runThreeSecurityFlowsTest().catch(err => {
  console.error('\n❌ THREE SECURITY FLOWS SUITE FAILED:', err.stack || err.message);
  process.exit(1);
});
