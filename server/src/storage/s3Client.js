const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const dotenv = require('dotenv');

dotenv.config();

const endpoint = process.env.B2_ENDPOINT || 'https://s3.us-east-005.backblazeb2.com';
const region = process.env.B2_REGION || 'us-east-005';
const accessKeyId = process.env.B2_KEY_ID || process.env.B2_ACCESS_KEY_ID;
const secretAccessKey = process.env.B2_APPLICATION_KEY || process.env.B2_SECRET_ACCESS_KEY;
const bucketName = process.env.B2_BUCKET_NAME || 'securevault-bucket';

let s3Client = null;

if (accessKeyId && secretAccessKey) {
  s3Client = new S3Client({
    endpoint,
    region,
    credentials: {
      accessKeyId,
      secretAccessKey,
    },
    forcePathStyle: true,
  });
} else {
  console.warn('[B2 Storage] Notice: B2 credentials omitted or using dev environment. Initialized storage wrapper.');
}

// In-memory fallback mock storage for tests if B2 API keys are not supplied in local environment
const mockB2Bucket = new Map();

/**
 * Uploads ciphertext Buffer to Backblaze B2 bucket (or fallback local mock).
 */
async function uploadToB2(storageKey, ciphertextBuffer, contentType = 'application/octet-stream') {
  if (s3Client) {
    const command = new PutObjectCommand({
      Bucket: bucketName,
      Key: storageKey,
      Body: ciphertextBuffer,
      ContentType: contentType,
    });
    await s3Client.send(command);
    return { storageKey, bucket: bucketName };
  } else {
    mockB2Bucket.set(storageKey, {
      body: ciphertextBuffer,
      contentType,
      uploadedAt: new Date(),
    });
    return { storageKey, bucket: 'mock-b2-bucket' };
  }
}

/**
 * Downloads ciphertext Buffer from Backblaze B2 bucket (or fallback local mock).
 */
async function getFromB2(storageKey) {
  if (s3Client) {
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: storageKey,
    });
    const response = await s3Client.send(command);
    const chunks = [];
    for await (const chunk of response.Body) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } else {
    const item = mockB2Bucket.get(storageKey);
    if (!item) throw new Error(`Object not found in storage: ${storageKey}`);
    return item.body;
  }
}

module.exports = {
  s3Client,
  bucketName,
  uploadToB2,
  getFromB2,
};
