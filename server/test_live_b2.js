const http = require('http');
const crypto = require('crypto');
const { pool } = require('./src/db');
const { getFromB2, bucketName, s3Client } = require('./src/storage/s3Client');

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
      res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(data || '{}') }));
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

async function runLiveB2Verification() {
  console.log('================================================================');
  console.log('--- STARTING LIVE BACKBLAZE B2 CLOUD UPLOAD VERIFICATION ---');
  console.log('================================================================');

  if (!s3Client) {
    throw new Error('S3 Client is not initialized! Credentials missing in server/.env.');
  }

  const testEmail = `b2_live_user_${Date.now()}@securevault.org`;

  // 1. Authenticate User (Cycle 1)
  console.log('\n[Step 1] Creating test user account...');
  const regRes = await request('POST', '/api/auth/register', {
    orgName: 'Backblaze Live Test Org',
    email: testEmail,
    password: 'MasterSecretPassword2026!',
  });

  if (regRes.status !== 201 || !regRes.data.token) {
    throw new Error(`User registration failed! HTTP Status: ${regRes.status}`);
  }
  const token = regRes.data.token;
  const userId = regRes.data.user.id;
  console.log('✅ Account created successfully. User ID:', userId);

  // 2. Perform AES-256-GCM local encryption (Cycle 3)
  console.log('\n[Step 2] Performing local AES-256-GCM encryption...');
  const plaintextSample = Buffer.from('CONFIDENTIAL BACKBLAZE B2 TEST PAYLOAD - SECUREVAULT 2026 TOP SECRET!');
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintextSample), cipher.final()]);
  const authTag = cipher.getAuthTag();

  console.log('Plaintext Size :', plaintextSample.length, 'bytes');
  console.log('Ciphertext Size:', ciphertext.length, 'bytes');
  console.log('IV (Base64)    :', iv.toString('base64'));
  console.log('AuthTag Base64 :', authTag.toString('base64'));

  // 3. Upload Ciphertext to Express -> Backblaze B2 (Cycle 4)
  console.log('\n[Step 3] Uploading ciphertext to Express server -> Backblaze B2 bucket...');
  const uploadRes = await uploadMultipart('/api/files/upload', {
    originalName: 'live_test.pdf',
    originalSize: plaintextSample.length.toString(),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    algorithm: 'AES-256-GCM',
  }, ciphertext, 'live_test.enc', { 'Authorization': `Bearer ${token}` });

  console.log('Upload HTTP Status:', uploadRes.status);
  console.log('Upload Response   :', uploadRes.data);

  if (uploadRes.status !== 201 || !uploadRes.data.file) {
    throw new Error(`Cloud upload failed! Response: ${JSON.stringify(uploadRes.data)}`);
  }
  const uploadedFile = uploadRes.data.file;
  console.log('✅ HTTP 201 Created: Ciphertext uploaded to Backblaze B2 successfully!');
  console.log('   Storage Key:', uploadedFile.storageKey);

  // 4. Verify Object Existence & Content in Real Backblaze B2 Bucket
  console.log(`\n[Step 4] Fetching uploaded object directly from Backblaze B2 bucket ("${bucketName}")...`);
  const b2FetchedBuffer = await getFromB2(uploadedFile.storageKey);

  console.log('Fetched B2 Object Size:', b2FetchedBuffer.length, 'bytes');

  if (!b2FetchedBuffer || !b2FetchedBuffer.equals(ciphertext)) {
    throw new Error('MISMATCH: Content downloaded from Backblaze B2 does not match uploaded ciphertext!');
  }

  if (b2FetchedBuffer.includes('CONFIDENTIAL BACKBLAZE')) {
    throw new Error('SECURITY VIOLATION: Backblaze B2 object contains unencrypted plaintext!');
  }
  console.log('✅ VERIFIED REAL B2 OBJECT: Object exists in Backblaze B2 bucket.');
  console.log('✅ VERIFIED CIPHERTEXT INTEGRITY: B2 object contains EXACT ciphertext, 0 plaintext bytes.');

  // 5. Verify PostgreSQL Database Metadata Record
  console.log('\n[Step 5] Querying PostgreSQL database files table...');
  const dbRes = await pool.query('SELECT * FROM files WHERE id = $1', [uploadedFile.id]);
  const dbRow = dbRes.rows[0];

  console.log('Database File Row ID :', dbRow.id);
  console.log('Database Storage Key :', dbRow.storage_key);

  if (!dbRow || dbRow.owner_id !== userId || dbRow.storage_key !== uploadedFile.storageKey) {
    throw new Error('PostgreSQL database record does not match upload metadata!');
  }

  if (dbRow.iv !== iv.toString('base64') || dbRow.auth_tag !== authTag.toString('base64')) {
    throw new Error('PostgreSQL encryption IV or auth tag mismatch!');
  }

  const dbJson = JSON.stringify(dbRow);
  if (dbJson.includes('CONFIDENTIAL') || dbJson.includes(dek.toString('hex'))) {
    throw new Error('SECURITY VIOLATION: PostgreSQL stores plaintext or DEK!');
  }
  console.log('✅ VERIFIED POSTGRESQL METADATA: File record matches B2 object storage key; 0 DEK/plaintext stored.');

  // 6. Security Boundary Verification
  console.log('\n[Step 6] Testing Security Boundaries...');
  const responseStr = JSON.stringify(uploadRes.data);
  if (responseStr.includes(dek.toString('base64')) || responseStr.includes('CONFIDENTIAL')) {
    throw new Error('SECURITY VIOLATION: Express backend leaked DEK or plaintext in response!');
  }

  const listRes = await request('GET', '/api/files', null, { 'Authorization': `Bearer ${token}` });
  const listStr = JSON.stringify(listRes.data);
  if (listStr.includes('accessKeyId') || listStr.includes('secretAccessKey') || listStr.includes('B2_APPLICATION_KEY')) {
    throw new Error('SECURITY VIOLATION: B2 credentials returned in API response!');
  }
  console.log('✅ VERIFIED SECURITY BOUNDARIES: Backend received only ciphertext; zero credentials/DEKs leaked to client.');

  // 7. Authorization & Listing Verification
  console.log('\n[Step 7] Testing File Listing & Unauthenticated Rejection...');
  const unauthRes = await request('GET', '/api/files');
  if (unauthRes.status !== 401) {
    throw new Error('Unauthenticated access was allowed!');
  }
  console.log('✅ VERIFIED AUTHENTICATION: Unauthenticated access properly rejected (HTTP 401).');
  console.log('✅ VERIFIED FILE LISTING: User retrieved file metadata (Total files:', listRes.data.files.length, ')');

  console.log('\n================================================================');
  console.log('🎉 REAL BACKBLAZE B2 CLOUD INTEGRATION VERIFIED SUCCESSFULLY!');
  console.log('================================================================');
  process.exit(0);
}

runLiveB2Verification().catch(err => {
  console.error('\n❌ LIVE BACKBLAZE B2 VERIFICATION FAILED:', err.stack || err.message);
  process.exit(1);
});
