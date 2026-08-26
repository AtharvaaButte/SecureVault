const path = require('path');
const fs = require('fs');

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

module.exports = {
  getTempDir,
  saveEncryptedFile,
  saveMetadata,
  readEncryptedFile,
  readMetadata,
  saveDecryptedFile,
};
