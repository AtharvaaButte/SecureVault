const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

/**
 * Opens native file dialog to select a local file.
 */
async function selectLocalFile(dialog, mainWindow) {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    title: 'Select File to Encrypt',
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  const selectedPath = result.filePaths[0];
  const stats = fs.statSync(selectedPath);

  return {
    filePath: selectedPath,
    fileName: path.basename(selectedPath),
    fileSize: stats.size,
  };
}

/**
 * Reads local file into Buffer.
 */
function readFileBuffer(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File does not exist: ${filePath}`);
  }
  return fs.readFileSync(filePath);
}

/**
 * Gets file stats.
 */
function getFileStats(filePath) {
  return fs.statSync(filePath);
}

/**
 * Performs byte-for-byte & SHA-256 integrity verification between original and decrypted files.
 */
function verifyFileIntegrity(originalPath, decryptedPath) {
  if (!fs.existsSync(originalPath) || !fs.existsSync(decryptedPath)) {
    return { identical: false, error: 'One or both files do not exist for comparison.' };
  }

  const origBuffer = fs.readFileSync(originalPath);
  const decBuffer = fs.readFileSync(decryptedPath);

  const origHash = crypto.createHash('sha256').update(origBuffer).digest('hex');
  const decHash = crypto.createHash('sha256').update(decBuffer).digest('hex');

  const isIdentical = (origHash === decHash) && (origBuffer.equals(decBuffer));

  return {
    identical: isIdentical,
    originalHash: origHash,
    decryptedHash: decHash,
    originalSize: origBuffer.length,
    decryptedSize: decBuffer.length,
  };
}

module.exports = {
  selectLocalFile,
  readFileBuffer,
  getFileStats,
  verifyFileIntegrity,
};
