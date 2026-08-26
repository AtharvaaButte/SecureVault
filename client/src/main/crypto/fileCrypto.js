const crypto = require('crypto');

// In-memory DEK store for Cycle 3 (fileId -> Buffer(32)). DEKs NEVER written to disk or network.
const inMemoryDekStore = new Map();

/**
 * Generates a fresh 256-bit (32-byte) random Data Encryption Key.
 */
function generateDek() {
  return crypto.randomBytes(32);
}

/**
 * Stores DEK in memory for a given file ID.
 */
function storeDek(fileId, dek) {
  inMemoryDekStore.set(fileId, dek);
}

/**
 * Retrieves DEK from memory for a given file ID.
 */
function getDek(fileId) {
  return inMemoryDekStore.get(fileId);
}

/**
 * Generates a fresh 96-bit (12-byte) random IV for AES-256-GCM.
 */
function generateIv() {
  return crypto.randomBytes(12);
}

/**
 * Encrypts a plaintext Buffer using AES-256-GCM with a fresh DEK and IV.
 */
function encryptBuffer(plaintextBuffer, dek = null) {
  const finalDek = dek || generateDek();
  const iv = generateIv();

  const cipher = crypto.createCipheriv('aes-256-gcm', finalDek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    dek: finalDek,
    iv,
    ciphertext,
    authTag,
  };
}

/**
 * Decrypts an AES-256-GCM ciphertext Buffer. Throws if authentication tag verification fails.
 */
function decryptBuffer(ciphertextBuffer, dek, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
}

module.exports = {
  generateDek,
  storeDek,
  getDek,
  generateIv,
  encryptBuffer,
  decryptBuffer,
};
