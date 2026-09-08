const crypto = require('crypto');

const PROTOCOL_INFO = Buffer.from('SecureVault-DEK-Wrap-v1', 'utf-8');

/**
 * Builds a deterministic AAD Buffer binding the wrapped DEK to the protocol, file ID, and recipient user ID.
 */
function buildWrapAad(fileId, recipientUserId) {
  const normFileId = String(fileId || '').trim().toLowerCase();
  const normUserId = String(recipientUserId || '').trim().toLowerCase();
  return Buffer.from(`SecureVault-DEK-Wrap-v1:${normFileId}:${normUserId}`, 'utf-8');
}

/**
 * Derives a 256-bit AES wrapping key using X25519 DH key agreement and HKDF-SHA-256.
 */
function deriveWrappingKey(privateKeyPem, publicKeyPem, saltBuffer) {
  const cleanPriv = String(privateKeyPem || '').trim().replace(/\r\n/g, '\n');
  const cleanPub = String(publicKeyPem || '').trim().replace(/\r\n/g, '\n');

  const privKeyObj = crypto.createPrivateKey(cleanPriv);
  const pubKeyObj = crypto.createPublicKey(cleanPub);

  const sharedSecret = crypto.diffieHellman({
    privateKey: privKeyObj,
    publicKey: pubKeyObj,
  });

  return crypto.hkdfSync(
    'sha256',
    sharedSecret,
    saltBuffer,
    PROTOCOL_INFO,
    32
  );
}

/**
 * Wraps a file's 32-byte DEK for a recipient user using X25519 + HKDF-SHA-256 + AES-256-GCM + AAD.
 */
function wrapDek(dekBuffer, senderPrivateKeyPem, recipientPublicKeyPem, fileId, recipientUserId) {
  if (!Buffer.isBuffer(dekBuffer) || dekBuffer.length !== 32) {
    throw new Error('Invalid DEK Buffer. Must be 32 bytes.');
  }

  const wrapSalt = crypto.randomBytes(16);
  const wrapIv = crypto.randomBytes(12);

  const wrappingKey = deriveWrappingKey(senderPrivateKeyPem, recipientPublicKeyPem, wrapSalt);
  const aadBuffer = buildWrapAad(fileId, recipientUserId);

  const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, wrapIv);
  cipher.setAAD(aadBuffer);

  const wrappedDek = Buffer.concat([cipher.update(dekBuffer), cipher.final()]);
  const wrapAuthTag = cipher.getAuthTag();

  return {
    wrappedDek: wrappedDek.toString('base64'),
    wrapSalt: wrapSalt.toString('base64'),
    wrapIv: wrapIv.toString('base64'),
    wrapAuthTag: wrapAuthTag.toString('base64'),
  };
}

/**
 * Unwraps a recipient's wrapped DEK using X25519 + HKDF-SHA-256 + AES-256-GCM + AAD.
 */
function unwrapDek(wrappedDekBase64, wrapSaltBase64, wrapIvBase64, wrapAuthTagBase64, senderPublicKeyPem, recipientPrivateKeyPem, fileId, recipientUserId) {
  const wrappedDek = Buffer.from(wrappedDekBase64, 'base64');
  const wrapSalt = Buffer.from(wrapSaltBase64, 'base64');
  const wrapIv = Buffer.from(wrapIvBase64, 'base64');
  const wrapAuthTag = Buffer.from(wrapAuthTagBase64, 'base64');

  const wrappingKey = deriveWrappingKey(recipientPrivateKeyPem, senderPublicKeyPem, wrapSalt);
  const aadBuffer = buildWrapAad(fileId, recipientUserId);

  const decipher = crypto.createDecipheriv('aes-256-gcm', wrappingKey, wrapIv);
  decipher.setAAD(aadBuffer);
  decipher.setAuthTag(wrapAuthTag);

  let unwrappedDek;
  try {
    unwrappedDek = Buffer.concat([decipher.update(wrappedDek), decipher.final()]);
  } catch (err) {
    console.error('[unwrapDek Authentication Failure]:', err.message);
    throw new Error('Failed to decrypt shared file key. The recipient key pair does not match the key used during file sharing.');
  }

  if (!unwrappedDek || unwrappedDek.length !== 32) {
    throw new Error('Unwrapped DEK length mismatch.');
  }

  return unwrappedDek;
}

module.exports = {
  buildWrapAad,
  deriveWrappingKey,
  wrapDek,
  unwrapDek,
};
