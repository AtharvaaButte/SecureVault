const crypto = require('crypto');

const BASE_URL = 'http://localhost:5000/api';

function uploadMultipart(pathName, fields, fileBuffer, fileName, headers = {}) {
  return new Promise((resolve, reject) => {
    const http = require('http');
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
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data || '{}') });
        } catch (e) {
          resolve({ status: res.statusCode, raw: data });
        }
      });
    });
    req.on('error', reject);
    req.write(fullBody);
    req.end();
  });
}

async function runTests() {
  console.log('================================================================');
  console.log('--- STARTING ACCOUNT ACTIVATION & SETUP LIFECYCLE TEST SUITE ---');
  console.log('================================================================\n');

  try {
    const timestamp = Date.now();
    const orgName = `ActivationOrg_${timestamp}`;
    const ownerEmail = `owner_${timestamp}@vault.com`;
    const ownerPassword = 'OwnerPassword123!';

    // 1. Register Organization & Owner
    console.log('[TEST 1] Registering Organization & Owner account...');
    const regRes = await fetch(`${BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        orgName,
        name: 'Organization Owner',
        email: ownerEmail,
        password: ownerPassword,
      }),
    });
    const regData = await regRes.json();
    if (!regRes.ok) throw new Error(`Owner registration failed: ${regData.message}`);
    const ownerToken = regData.token;
    const orgId = regData.organization.id;
    console.log(`✅ TEST 1 PASSED: Owner registered with status ACTIVE (Org ID: ${orgId})\n`);

    // Register Owner's X25519 Public Key
    const ownerKeyPair = crypto.generateKeyPairSync('x25519');
    const ownerPubKey = ownerKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
    const ownerPrivKey = ownerKeyPair.privateKey;

    await fetch(`${BASE_URL}/crypto/public-key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({ publicKey: ownerPubKey }),
    });

    // 2. Owner creates custom role and normal member without password (SETUP_REQUIRED)
    console.log('[TEST 2] Owner creates custom role and pending user without password...');
    const roleRes = await fetch(`${BASE_URL}/roles`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({
        name: `Role_${timestamp}`,
        description: 'Standard member role',
        permissions: ['FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE'],
      }),
    });
    const roleData = await roleRes.json();
    const roleId = roleData.role.id;

    const memberEmail = `pending_${timestamp}@vault.com`;
    const createUserRes = await fetch(`${BASE_URL}/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({
        name: 'Pending Member',
        email: memberEmail,
        roleIds: [roleId],
      }),
    });
    const createUserData = await createUserRes.json();
    if (!createUserRes.ok) throw new Error(`User creation failed: ${createUserData.message}`);

    const newUser = createUserData.user;
    const setupToken = newUser.setupToken;
    if (!setupToken) throw new Error('Setup token was not generated for new user.');
    if (newUser.status !== 'SETUP_REQUIRED') throw new Error(`Expected status SETUP_REQUIRED, received ${newUser.status}`);
    console.log(`✅ TEST 2 PASSED: User created with status SETUP_REQUIRED (Token: ${setupToken})\n`);

    // 3. Login attempt before setup (Must be DENIED with 403)
    console.log('[TEST 3] Attempting login before setup completion (Must be DENIED)...');
    const preLoginRes = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: memberEmail, password: 'AnyPassword123!' }),
    });
    const preLoginData = await preLoginRes.json();
    if (preLoginRes.status !== 403 || !preLoginData.setupRequired) {
      throw new Error(`Expected 403 setupRequired, received status ${preLoginRes.status}`);
    }
    console.log(`✅ TEST 3 PASSED: Pre-setup login denied with HTTP 403 setupRequired: "${preLoginData.message}"\n`);

    // 4. File sharing attempt to pending user (Must be DENIED with 400)
    console.log('[TEST 4] Uploading file and attempting share with pending user (Must be DENIED)...');
    const uploadRes = await uploadMultipart('/api/files/upload', {
      originalName: 'SecretDoc.txt',
      dataClassification: 'INTERNAL',
      iv: 'fake_iv',
      authTag: 'fake_tag',
    }, Buffer.from('Test File Content'), 'SecretDoc.txt', {
      'Authorization': `Bearer ${ownerToken}`,
    });

    if (uploadRes.status !== 201) {
      console.log('Upload error response:', uploadRes);
      throw new Error(`File upload failed with status ${uploadRes.status}`);
    }
    const fileId = uploadRes.data.file.id;

    const sharePreRes = await fetch(`${BASE_URL}/files/${fileId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({
        recipientUserId: newUser.id,
        wrappedDek: 'fake_dek',
        wrapSalt: 'fake_salt',
        wrapIv: 'fake_iv',
        wrapAuthTag: 'fake_auth_tag',
        senderPublicKey: ownerPubKey,
        accessLevel: 'FULL',
      }),
    });
    const sharePreData = await sharePreRes.json();
    if (sharePreRes.status !== 400 || !sharePreData.message.includes('not completed account setup')) {
      throw new Error(`Expected 400 "not completed account setup", received status ${sharePreRes.status}: ${sharePreData.message}`);
    }
    console.log(`✅ TEST 4 PASSED: File sharing to pending user denied with 400: "${sharePreData.message}"\n`);

    // 5. Validate setup token GET /api/auth/setup/:token
    console.log('[TEST 5] Validating setup token via GET /api/auth/setup/:token...');
    const checkTokenRes = await fetch(`${BASE_URL}/auth/setup/${setupToken}`);
    const checkTokenData = await checkTokenRes.json();
    if (!checkTokenRes.ok || !checkTokenData.valid) {
      throw new Error(`Setup token validation failed: ${checkTokenData.message}`);
    }
    console.log(`✅ TEST 5 PASSED: Setup token validated for user ${checkTokenData.user.name} (${checkTokenData.user.email})\n`);

    // 6. Complete account setup via POST /api/auth/setup/:token with password & X25519 public key
    console.log('[TEST 6] Completing account setup (setting password & registering X25519 key)...');
    const memberKeyPair = crypto.generateKeyPairSync('x25519');
    const memberPubKey = memberKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
    const memberPrivKey = memberKeyPair.privateKey;
    const memberPassword = 'MemberPassword123!';

    const completeSetupRes = await fetch(`${BASE_URL}/auth/setup/${setupToken}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        password: memberPassword,
        publicKey: memberPubKey,
        securityHint: 'My favorite security book',
      }),
    });
    const completeSetupData = await completeSetupRes.json();
    if (!completeSetupRes.ok || completeSetupData.user.status !== 'ACTIVE') {
      throw new Error(`Setup completion failed: ${completeSetupData.message}`);
    }
    console.log(`✅ TEST 6 PASSED: Account setup completed successfully. Status updated to ACTIVE.\n`);

    // 7. Setup token reuse attempt (Must be DENIED)
    console.log('[TEST 7] Attempting to reuse completed setup token (Must be DENIED)...');
    const reuseRes = await fetch(`${BASE_URL}/auth/setup/${setupToken}`);
    const reuseData = await reuseRes.json();
    if (reuseRes.status !== 400) {
      throw new Error(`Expected 400 for token reuse, received status ${reuseRes.status}`);
    }
    console.log(`✅ TEST 7 PASSED: Setup token single-use enforced: "${reuseData.message}"\n`);

    // 8. Normal Login after setup (Must SUCCEED)
    console.log('[TEST 8] Logging in after setup completion (Must SUCCEED)...');
    const postLoginRes = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: memberEmail, password: memberPassword }),
    });
    const postLoginData = await postLoginRes.json();
    if (!postLoginRes.ok || !postLoginData.token) {
      throw new Error(`Post-setup login failed: ${postLoginData.message}`);
    }
    const memberToken = postLoginData.token;
    console.log(`✅ TEST 8 PASSED: Login succeeded for ACTIVE user ${postLoginData.user.email}\n`);

    // 9. File sharing to activated user (Must SUCCEED)
    console.log('[TEST 9] Sharing encrypted file with newly activated user (Must SUCCEED)...');
    // Compute X25519 DH shared secret
    const sharedSecret = crypto.diffieHellman({
      privateKey: ownerPrivKey,
      publicKey: memberKeyPair.publicKey,
    });
    const derivedKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('SecureVault_DEK_Wrap_v1'), 32);

    const dek = crypto.randomBytes(32);
    const wrapIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, wrapIv);
    const wrappedDek = Buffer.concat([cipher.update(dek), cipher.final()]).toString('base64');
    const wrapAuthTag = cipher.getAuthTag().toString('base64');

    const sharePostRes = await fetch(`${BASE_URL}/files/${fileId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({
        recipientUserId: newUser.id,
        wrappedDek,
        wrapSalt: crypto.randomBytes(16).toString('base64'),
        wrapIv: wrapIv.toString('base64'),
        wrapAuthTag,
        senderPublicKey: ownerPubKey,
        accessLevel: 'FULL',
      }),
    });
    const sharePostData = await sharePostRes.json();
    if (!sharePostRes.ok) throw new Error(`Post-activation sharing failed: ${sharePostData.message}`);
    console.log(`✅ TEST 9 PASSED: File successfully shared with activated member!\n`);

    // 10. Recipient unwraps and decrypts shared DEK
    console.log('[TEST 10] Recipient unwrapping DEK and verifying access...');
    const memberSharedRes = await fetch(`${BASE_URL}/files/shared`, {
      headers: { 'Authorization': `Bearer ${memberToken}` },
    });
    const memberSharedData = await memberSharedRes.json();
    if (!memberSharedRes.ok || memberSharedData.sharedFiles.length === 0) {
      throw new Error('Member shared files list is empty.');
    }

    const item = memberSharedData.sharedFiles[0];
    const recSharedSecret = crypto.diffieHellman({
      privateKey: memberPrivKey,
      publicKey: ownerKeyPair.publicKey,
    });
    const recDerivedKey = crypto.hkdfSync('sha256', recSharedSecret, Buffer.alloc(0), Buffer.from('SecureVault_DEK_Wrap_v1'), 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', recDerivedKey, Buffer.from(item.wrapping.wrapIv, 'base64'));
    decipher.setAuthTag(Buffer.from(item.wrapping.wrapAuthTag, 'base64'));
    const unwrappedDek = Buffer.concat([decipher.update(Buffer.from(item.wrapping.wrappedDek, 'base64')), decipher.final()]);

    if (unwrappedDek.toString('hex') !== dek.toString('hex')) {
      throw new Error('Unwrapped DEK does not match original DEK.');
    }
    console.log(`✅ TEST 10 PASSED: DEK unwrapped & verified byte-for-byte by activated member!\n`);

    // 11. Verify GET /api/users/members returns status ACTIVE and publicKeyRegistered true
    console.log('[TEST 11] Verifying member status in member management API...');
    const membersRes = await fetch(`${BASE_URL}/users/members`, {
      headers: { 'Authorization': `Bearer ${ownerToken}` },
    });
    const membersData = await membersRes.json();
    const targetMember = membersData.users.find(u => u.id === newUser.id);
    if (!targetMember) throw new Error('Activated member not found in members list.');
    if (targetMember.status !== 'ACTIVE' || !targetMember.publicKeyRegistered) {
      throw new Error(`Expected ACTIVE status & publicKeyRegistered true, received status: ${targetMember.status}, publicKeyRegistered: ${targetMember.publicKeyRegistered}`);
    }
    console.log(`✅ TEST 11 PASSED: Member management API confirms status: ${targetMember.status}, E2EE Key Registered: ${targetMember.publicKeyRegistered}\n`);

    console.log('================================================================');
    console.log('🎉 ALL ACCOUNT ACTIVATION & SETUP LIFECYCLE TESTS PASSED 100%!');
    console.log('================================================================\n');

  } catch (error) {
    console.error('❌ TEST FAILED:', error.message);
    process.exit(1);
  }
}

runTests();
