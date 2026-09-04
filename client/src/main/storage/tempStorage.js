const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const fileCrypto = require('../crypto/fileCrypto');

/**
 * Ensures the temporary directory exists inside userData path.
 */
function getTempDir(app) {
  const tempDir = path.join(app.getPath('userData'), 'temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }
  return tempDir;
}

/**
 * Saves encrypted ciphertext to temporary storage.
 */
function saveEncryptedFile(tempDir, fileId, ciphertextBuffer) {
  const encFilePath = path.join(tempDir, `${fileId}.enc`);
  fs.writeFileSync(encFilePath, ciphertextBuffer);
  return encFilePath;
}

/**
 * Saves algorithm & file metadata JSON to temporary storage (no DEKs or private keys).
 */
function saveMetadata(tempDir, metadata) {
  const metaFilePath = path.join(tempDir, `${metadata.id}.json`);
  fs.writeFileSync(metaFilePath, JSON.stringify(metadata, null, 2), 'utf-8');
  return metaFilePath;
}

/**
 * Reads encrypted ciphertext Buffer from temporary storage.
 */
function readEncryptedFile(tempDir, fileId) {
  const encFilePath = path.join(tempDir, `${fileId}.enc`);
  if (!fs.existsSync(encFilePath)) {
    throw new Error(`Encrypted file missing for ID ${fileId}`);
  }
  return fs.readFileSync(encFilePath);
}

/**
 * Reads metadata JSON from temporary storage.
 */
function readMetadata(tempDir, fileId) {
  const metaFilePath = path.join(tempDir, `${fileId}.json`);
  if (!fs.existsSync(metaFilePath)) {
    throw new Error(`Metadata missing for ID ${fileId}`);
  }
  return JSON.parse(fs.readFileSync(metaFilePath, 'utf-8'));
}

/**
 * Saves decrypted buffer to temporary output file.
 */
function saveDecryptedFile(tempDir, fileId, originalName, decryptedBuffer) {
  const decFilePath = path.join(tempDir, `${fileId}_decrypted_${originalName}`);
  fs.writeFileSync(decFilePath, decryptedBuffer);
  return decFilePath;
}

/**
 * Reads plaintext local file, encrypts with AES-256-GCM using fileCrypto, stores DEK in memory,
 * and saves ciphertext + metadata to temporary storage.
 */
function storeAndEncryptFile(filePath, tempDir) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File does not exist: ${filePath}`);
  }

  const plainBuffer = fs.readFileSync(filePath);
  const fileId = crypto.randomUUID();
  const originalName = path.basename(filePath);
  const originalSize = plainBuffer.length;

  const encResult = fileCrypto.encryptBuffer(plainBuffer);
  fileCrypto.storeDek(fileId, encResult.dek);

  const ivBase64 = encResult.iv.toString('base64');
  const authTagBase64 = encResult.authTag.toString('base64');

  saveEncryptedFile(tempDir, fileId, encResult.ciphertext);

  const metadata = {
    id: fileId,
    originalName,
    originalSize,
    encryptedSize: encResult.ciphertext.length,
    algorithm: 'AES-256-GCM',
    iv: ivBase64,
    authTag: authTagBase64,
    createdAt: new Date().toISOString(),
  };

  saveMetadata(tempDir, metadata);

  return {
    fileId,
    originalName,
    originalSize,
    encryptedSize: encResult.ciphertext.length,
    algorithm: 'AES-256-GCM',
    iv: ivBase64,
    authTag: authTagBase64,
  };
}

/**
 * Reads encrypted file and metadata from temporary storage, retrieves DEK from memory,
 * and decrypts using fileCrypto.
 */
function decryptTempFile(tempDir, fileId) {
  const metadata = readMetadata(tempDir, fileId);
  const ciphertextBuffer = readEncryptedFile(tempDir, fileId);
  const dek = fileCrypto.getDek(fileId);

  if (!dek) {
    throw new Error(`Data Encryption Key (DEK) not found in memory for file ${fileId}`);
  }

  const iv = Buffer.from(metadata.iv, 'base64');
  const authTag = Buffer.from(metadata.authTag, 'base64');

  const decryptedBuffer = fileCrypto.decryptBuffer(ciphertextBuffer, dek, iv, authTag);

  return {
    decryptedBuffer,
    metadata,
  };
}

module.exports = {
  getTempDir,
  saveEncryptedFile,
  saveMetadata,
  readEncryptedFile,
  readMetadata,
  saveDecryptedFile,
  storeAndEncryptFile,
  decryptTempFile,
};
