const { app, BrowserWindow, ipcMain, safeStorage, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// --- DEV PROFILE ISOLATION (development/testing only) ---
// Launch: electron . --profile=alice   or   --profile=bob
// Also accepted: --profile alice   and   SECUREVAULT_PROFILE=alice
// Each profile gets its own Electron userData directory so JWT/session,
// safeStorage-protected private keys, and identity files stay independent.
// With no --profile argument, behaviour is unchanged.
function resolveDevProfileName() {
  const eqArg = process.argv.find((a) => a.startsWith('--profile='));
  if (eqArg) return eqArg.slice('--profile='.length).trim();

  const flagIndex = process.argv.indexOf('--profile');
  if (flagIndex !== -1) {
    const value = process.argv[flagIndex + 1];
    if (value && !value.startsWith('-')) return value.trim();
  }

  if (process.env.SECUREVAULT_PROFILE) return process.env.SECUREVAULT_PROFILE.trim();
  return '';
}

const requestedProfile = resolveDevProfileName();
let devProfile = null;
if (requestedProfile) {
  if (!/^[A-Za-z0-9_-]+$/.test(requestedProfile)) {
    console.error(`[Profile] Invalid --profile "${requestedProfile}". Use only letters, numbers, hyphen, or underscore.`);
    process.exit(1);
  }
  const profileDir = path.join(app.getPath('userData'), 'profiles', requestedProfile);
  fs.mkdirSync(profileDir, { recursive: true });
  app.setPath('userData', profileDir);
  app.setPath('sessionData', profileDir);
  devProfile = requestedProfile;
  console.log(`[Profile] Dev profile "${devProfile}" active.`);
  console.log(`[Profile] userData → ${profileDir}`);
}

// Imported modules for separation of concerns
const fileCrypto = require('./crypto/fileCrypto');
const keyWrapping = require('./crypto/keyWrapping');
const tempStorage = require('./storage/tempStorage');
const fileService = require('./file/fileService');

let mainWindow = null;

const SESSION_FILE_PATH = path.join(app.getPath('userData'), 'session_token.enc');
const IDENTITY_KEY_PATH = path.join(app.getPath('userData'), 'identity_key.enc');
const IDENTITY_PUB_PATH = path.join(app.getPath('userData'), 'identity_pub.json');

if (devProfile) {
  console.log(`[Profile] session → ${SESSION_FILE_PATH}`);
  console.log(`[Profile] identity → ${IDENTITY_KEY_PATH}`);
}

// In-memory reference to unlocked private key (Cycle 2)
let localPrivateKeyPem = null;

// --- IPC Handlers for OS-secure persistent session storage (Cycle 1) ---
ipcMain.handle('save-session', async (_event, token) => {
  try {
    if (!token) return false;
    if (safeStorage.isEncryptionAvailable()) {
      const encryptedBuffer = safeStorage.encryptString(token);
      fs.writeFileSync(SESSION_FILE_PATH, encryptedBuffer);
      return true;
    } else {
      console.warn('[SafeStorage] OS Encryption unavailable. Falling back to encoding.');
      fs.writeFileSync(SESSION_FILE_PATH, Buffer.from(token, 'utf-8'));
      return true;
    }
  } catch (error) {
    console.error('[Session Save Error]:', error.message);
    return false;
  }
});

ipcMain.handle('get-session', async () => {
  try {
    if (!fs.existsSync(SESSION_FILE_PATH)) return null;
    const encryptedBuffer = fs.readFileSync(SESSION_FILE_PATH);
    if (safeStorage.isEncryptionAvailable()) {
      return safeStorage.decryptString(encryptedBuffer);
    } else {
      return encryptedBuffer.toString('utf-8');
    }
  } catch (error) {
    console.error('[Session Retrieve Error]:', error.message);
    return null;
  }
});

ipcMain.handle('clear-session', async () => {
  try {
    if (fs.existsSync(SESSION_FILE_PATH)) {
      fs.unlinkSync(SESSION_FILE_PATH);
    }
    return true;
  } catch (error) {
    console.error('[Session Clear Error]:', error.message);
    return false;
  }
});

// --- IPC Handlers for Local Cryptographic Identity (Cycle 2) ---
ipcMain.handle('get-identity-status', async () => {
  try {
    const keyExists = fs.existsSync(IDENTITY_KEY_PATH);
    const pubExists = fs.existsSync(IDENTITY_PUB_PATH);

    if (keyExists && pubExists) {
      const pubData = JSON.parse(fs.readFileSync(IDENTITY_PUB_PATH, 'utf-8'));
      return {
        hasIdentity: true,
        publicKey: pubData.publicKey,
      };
    }
    return {
      hasIdentity: false,
      publicKey: null,
    };
  } catch (error) {
    console.error('[Get Identity Status Error]:', error.message);
    return { hasIdentity: false, publicKey: null };
  }
});

ipcMain.handle('ensure-identity', async () => {
  try {
    const keyExists = fs.existsSync(IDENTITY_KEY_PATH);
    const pubExists = fs.existsSync(IDENTITY_PUB_PATH);

    if (keyExists && pubExists) {
      const encryptedPrivateKey = fs.readFileSync(IDENTITY_KEY_PATH);
      if (safeStorage.isEncryptionAvailable()) {
        localPrivateKeyPem = safeStorage.decryptString(encryptedPrivateKey);
      } else {
        localPrivateKeyPem = encryptedPrivateKey.toString('utf-8');
      }

      const pubData = JSON.parse(fs.readFileSync(IDENTITY_PUB_PATH, 'utf-8'));
      return {
        hasIdentity: true,
        publicKey: pubData.publicKey,
        createdNew: false,
      };
    }

    console.log('[Crypto] Generating new X25519 cryptographic key pair locally...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');

    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

    if (safeStorage.isEncryptionAvailable()) {
      const encryptedBuffer = safeStorage.encryptString(privateKeyPem);
      fs.writeFileSync(IDENTITY_KEY_PATH, encryptedBuffer);
    } else {
      fs.writeFileSync(IDENTITY_KEY_PATH, Buffer.from(privateKeyPem, 'utf-8'));
    }

    fs.writeFileSync(IDENTITY_PUB_PATH, JSON.stringify({ publicKey: publicKeyPem }), 'utf-8');
    localPrivateKeyPem = privateKeyPem;

    return {
      hasIdentity: true,
      publicKey: publicKeyPem,
      createdNew: true,
    };
  } catch (error) {
    console.error('[Ensure Identity Error]:', error.message);
    return {
      hasIdentity: false,
      publicKey: null,
      error: error.message,
    };
  }
});

// --- IPC Handlers for Local File Encryption (Cycle 3) ---
ipcMain.handle('select-file', async () => {
  try {
    return await fileService.selectLocalFile(dialog, mainWindow);
  } catch (error) {
    console.error('[Select File Error]:', error.message);
    return null;
  }
});

ipcMain.handle('encrypt-file', async (_event, filePath) => {
  try {
    const fileId = crypto.randomUUID();
    const fileName = path.basename(filePath);
    const stats = fileService.getFileStats(filePath);
    const plaintext = fileService.readFileBuffer(filePath);

    const { dek, iv, ciphertext, authTag } = fileCrypto.encryptBuffer(plaintext);
    fileCrypto.storeDek(fileId, dek);

    const tempDir = tempStorage.getTempDir(app);
    const encFilePath = tempStorage.saveEncryptedFile(tempDir, fileId, ciphertext);

    const metadata = {
      id: fileId,
      version: 1,
      algorithm: 'AES-256-GCM',
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      originalName: fileName,
      originalSize: stats.size,
      createdAt: new Date().toISOString(),
    };

    const metaFilePath = tempStorage.saveMetadata(tempDir, metadata);

    return {
      success: true,
      fileId,
      originalPath: filePath,
      encryptedPath: encFilePath,
      metadataPath: metaFilePath,
      metadata,
    };
  } catch (error) {
    console.error('[Encrypt File Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('decrypt-file', async (_event, fileId) => {
  try {
    const dek = fileCrypto.getDek(fileId);
    if (!dek) {
      throw new Error(`No in-memory DEK found for file ID ${fileId}`);
    }

    const tempDir = tempStorage.getTempDir(app);
    const metadata = tempStorage.readMetadata(tempDir, fileId);
    const ciphertext = tempStorage.readEncryptedFile(tempDir, fileId);

    const iv = Buffer.from(metadata.iv, 'base64');
    const authTag = Buffer.from(metadata.authTag, 'base64');

    const decryptedBuffer = fileCrypto.decryptBuffer(ciphertext, dek, iv, authTag);
    const decFilePath = tempStorage.saveDecryptedFile(tempDir, fileId, metadata.originalName, decryptedBuffer);

    return {
      success: true,
      fileId,
      decryptedPath: decFilePath,
      originalName: metadata.originalName,
      decryptedSize: decryptedBuffer.length,
    };
  } catch (error) {
    console.error('[Decrypt File Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('verify-file-integrity', async (_event, originalPath, decryptedPath) => {
  try {
    return fileService.verifyFileIntegrity(originalPath, decryptedPath);
  } catch (error) {
    console.error('[Verify Integrity Error]:', error.message);
    return { identical: false, error: error.message };
  }
});

ipcMain.handle('test-tamper-decryption', async (_event, fileId) => {
  try {
    const dek = fileCrypto.getDek(fileId);
    if (!dek) throw new Error('DEK not in memory');

    const tempDir = tempStorage.getTempDir(app);
    const metadata = tempStorage.readMetadata(tempDir, fileId);
    const ciphertext = tempStorage.readEncryptedFile(tempDir, fileId);

    const tamperedCiphertext = Buffer.from(ciphertext);
    tamperedCiphertext[0] = tamperedCiphertext[0] ^ 0xFF;

    const iv = Buffer.from(metadata.iv, 'base64');
    const authTag = Buffer.from(metadata.authTag, 'base64');

    fileCrypto.decryptBuffer(tamperedCiphertext, dek, iv, authTag);

    return { caughtTampering: false, error: 'Decryption succeeded on tampered data without auth failure!' };
  } catch (error) {
    return {
      caughtTampering: true,
      errorMessage: error.message,
    };
  }
});

ipcMain.handle('test-double-encryption', async (_event, filePath) => {
  try {
    const enc1 = await ipcMain.handle('encrypt-file', null, filePath);
    const enc2 = await ipcMain.handle('encrypt-file', null, filePath);

    const tempDir = tempStorage.getTempDir(app);
    const ciphertext1 = tempStorage.readEncryptedFile(tempDir, enc1.fileId);
    const ciphertext2 = tempStorage.readEncryptedFile(tempDir, enc2.fileId);

    const isUnique = !ciphertext1.equals(ciphertext2) && (enc1.metadata.iv !== enc2.metadata.iv);

    return {
      uniqueCiphertexts: isUnique,
      iv1: enc1.metadata.iv,
      iv2: enc2.metadata.iv,
    };
  } catch (error) {
    return { uniqueCiphertexts: false, error: error.message };
  }
});

// --- IPC Handler for Cloud Ciphertext Upload (Cycle 4 + Persistent DEK Recovery) ---
ipcMain.handle('upload-ciphertext', async (_event, { fileId, token }) => {
  try {
    const tempDir = tempStorage.getTempDir(app);
    const metadata = tempStorage.readMetadata(tempDir, fileId);
    const ciphertext = tempStorage.readEncryptedFile(tempDir, fileId);

    const formData = new FormData();
    formData.append('file', new Blob([ciphertext]), `${metadata.id}.enc`);
    formData.append('fileId', fileId);
    formData.append('originalName', metadata.originalName);
    formData.append('originalSize', metadata.originalSize.toString());
    formData.append('iv', metadata.iv);
    formData.append('authTag', metadata.authTag);
    formData.append('algorithm', metadata.algorithm);

    // Wrap DEK for owner so the owner can recover DEK after application restart
    const dek = fileCrypto.getDek(fileId);
    if (localPrivateKeyPem && fs.existsSync(IDENTITY_PUB_PATH) && dek) {
      const pubData = JSON.parse(fs.readFileSync(IDENTITY_PUB_PATH, 'utf-8'));
      const ownerPublicKey = pubData.publicKey;
      const tokenPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      const ownerUserId = tokenPayload.userId;

      const ownerWrapping = keyWrapping.wrapDek(
        dek,
        localPrivateKeyPem,
        ownerPublicKey,
        fileId,
        ownerUserId
      );

      formData.append('wrappedDek', ownerWrapping.wrappedDek);
      formData.append('wrapSalt', ownerWrapping.wrapSalt);
      formData.append('wrapIv', ownerWrapping.wrapIv);
      formData.append('wrapAuthTag', ownerWrapping.wrapAuthTag);
      formData.append('senderPublicKey', ownerPublicKey);
    }

    const response = await fetch('http://localhost:5000/api/files/upload', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      body: formData,
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Cloud upload failed');
    }

    return { success: true, file: data.file };
  } catch (error) {
    console.error('[Upload Ciphertext Error]:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC Handler for Cloud File Download & Local Decryption (Cycle 5 + Persistent DEK Recovery) ---
ipcMain.handle('download-decrypt-file', async (_event, { fileId, token }) => {
  try {
    // 1. Fetch encrypted ciphertext + metadata from Express backend
    const response = await fetch(`http://localhost:5000/api/files/${fileId}/download`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Failed to download encrypted file from cloud');
    }

    const { ciphertext, metadata, wrapping } = data;
    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');
    const iv = Buffer.from(metadata.iv, 'base64');
    const authTag = Buffer.from(metadata.authTag, 'base64');

    // 2. Retrieve DEK from Electron main-process memory or recover from backend wrapped key
    let dek = fileCrypto.getDek(fileId);
    if (!dek) {
      if (!wrapping) {
        throw new Error('No in-memory DEK found for this file and no wrapped key available on server.');
      }
      if (!localPrivateKeyPem) {
        throw new Error('Local cryptographic identity private key is not unlocked.');
      }

      const tokenPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      const currentUserId = tokenPayload.userId;

      dek = keyWrapping.unwrapDek(
        wrapping.wrappedDek,
        wrapping.wrapSalt,
        wrapping.wrapIv,
        wrapping.wrapAuthTag,
        wrapping.senderPublicKey,
        localPrivateKeyPem,
        fileId,
        currentUserId
      );

      fileCrypto.storeDek(fileId, dek);
      console.log(`[DEK Recovery] Successfully recovered DEK for file ${fileId} and stored in memory.`);
    }

    // 3. Decrypt ciphertext locally with AES-256-GCM
    const decryptedBuffer = fileCrypto.decryptBuffer(ciphertextBuffer, dek, iv, authTag);

    // 4. Prompt user with native Save File dialog
    const saveResult = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Decrypted File',
      defaultPath: metadata.originalName,
    });

    if (saveResult.canceled || !saveResult.filePath) {
      return { success: false, error: 'File save canceled by user.' };
    }

    // 5. Save decrypted buffer to user chosen path
    fs.writeFileSync(saveResult.filePath, decryptedBuffer);

    return {
      success: true,
      savedPath: saveResult.filePath,
      originalName: metadata.originalName,
      decryptedSize: decryptedBuffer.length,
    };
  } catch (error) {
    console.error('[Download & Decrypt Error]:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC Handlers for Cycle 4+ File Listing & Access Control ---
ipcMain.handle('get-user-files', async (_event, token) => {
  try {
    const response = await fetch('http://localhost:5000/api/files', {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to fetch user files');
    return { success: true, files: data.files };
  } catch (error) {
    console.error('[Get User Files Error]:', error.message);
    return { success: false, error: error.message, files: [] };
  }
});

// --- IPC Handlers for Cycle 6 E2EE File Sharing ---
ipcMain.handle('get-organization-users', async (_event, token) => {
  try {
    const response = await fetch('http://localhost:5000/api/users', {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to fetch users');
    return { success: true, users: data.users };
  } catch (error) {
    console.error('[Get Users Error]:', error.message);
    return { success: false, error: error.message, users: [] };
  }
});

ipcMain.handle('share-file', async (_event, { fileId, recipientUserId, recipientPublicKey, token }) => {
  try {
    if (!localPrivateKeyPem) {
      throw new Error('Local cryptographic identity private key is unlocked or missing.');
    }

    let dek = fileCrypto.getDek(fileId);

    // DEK Recovery for Share: If DEK is missing in memory (e.g. after app restart), recover it from backend wrapped owner DEK
    if (!dek) {
      console.log(`[DEK Recovery for Share] DEK missing from memory for file ${fileId}. Fetching owner wrapped key...`);
      const dlRes = await fetch(`http://localhost:5000/api/files/${fileId}/download`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const dlData = await dlRes.json();
      if (!dlRes.ok || !dlData.wrapping) {
        throw new Error(dlData.message || 'File DEK is not available in session memory and wrapped key retrieval failed.');
      }

      const tokenPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      const currentUserId = tokenPayload.userId;

      dek = keyWrapping.unwrapDek(
        dlData.wrapping.wrappedDek,
        dlData.wrapping.wrapSalt,
        dlData.wrapping.wrapIv,
        dlData.wrapping.wrapAuthTag,
        dlData.wrapping.senderPublicKey,
        localPrivateKeyPem,
        fileId,
        currentUserId
      );

      fileCrypto.storeDek(fileId, dek);
      console.log(`[DEK Recovery for Share] Successfully recovered DEK for file ${fileId} from owner wrapped key.`);
    }

    if (!fs.existsSync(IDENTITY_PUB_PATH)) {
      throw new Error('Local public key file missing.');
    }

    const pubData = JSON.parse(fs.readFileSync(IDENTITY_PUB_PATH, 'utf-8'));
    const senderPublicKey = pubData.publicKey;

    // Perform local key wrapping for recipient: X25519 DH + HKDF-SHA-256 + AES-256-GCM + AAD
    const wrappingPayload = keyWrapping.wrapDek(
      dek,
      localPrivateKeyPem,
      recipientPublicKey,
      fileId,
      recipientUserId
    );

    const response = await fetch(`http://localhost:5000/api/files/${fileId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        recipientUserId,
        senderPublicKey,
        wrappedDek: wrappingPayload.wrappedDek,
        wrapSalt: wrappingPayload.wrapSalt,
        wrapIv: wrappingPayload.wrapIv,
        wrapAuthTag: wrappingPayload.wrapAuthTag,
      }),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to share file');
    return { success: true, message: data.message };
  } catch (error) {
    console.error('[Share File Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('revoke-file-share', async (_event, { fileId, recipientUserId, token }) => {
  try {
    const response = await fetch(`http://localhost:5000/api/files/${fileId}/share/${recipientUserId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to revoke share');
    return { success: true, message: data.message };
  } catch (error) {
    console.error('[Revoke Share Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-file-shares', async (_event, { fileId, token }) => {
  try {
    const response = await fetch(`http://localhost:5000/api/files/${fileId}/shares`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to fetch shares');
    return { success: true, shares: data.shares };
  } catch (error) {
    console.error('[Get Shares Error]:', error.message);
    return { success: false, error: error.message, shares: [] };
  }
});

ipcMain.handle('get-shared-files', async (_event, token) => {
  try {
    const response = await fetch('http://localhost:5000/api/files/shared', {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to fetch shared files');
    return { success: true, sharedFiles: data.sharedFiles };
  } catch (error) {
    console.error('[Get Shared Files Error]:', error.message);
    return { success: false, error: error.message, sharedFiles: [] };
  }
});

ipcMain.handle('download-decrypt-shared-file', async (_event, { fileId, currentUserId, token }) => {
  try {
    if (!localPrivateKeyPem) {
      throw new Error('Local cryptographic identity private key is not available.');
    }

    // 1. Fetch file payload and wrapping metadata from backend
    const response = await fetch(`http://localhost:5000/api/files/${fileId}/download`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to download shared file payload');

    const { ciphertext, metadata, wrapping } = data;
    if (!wrapping) {
      throw new Error('Shared file wrapping metadata is missing.');
    }

    // 2. Local DEK unwrapping: X25519 DH + HKDF-SHA-256 + AES-256-GCM + AAD
    const unwrappedDek = keyWrapping.unwrapDek(
      wrapping.wrappedDek,
      wrapping.wrapSalt,
      wrapping.wrapIv,
      wrapping.wrapAuthTag,
      wrapping.senderPublicKey,
      localPrivateKeyPem,
      fileId,
      currentUserId
    );

    // 3. Store DEK in main-process memory
    fileCrypto.storeDek(fileId, unwrappedDek);

    // 4. Decrypt B2 ciphertext locally
    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');
    const ivBuffer = Buffer.from(metadata.iv, 'base64');
    const authTagBuffer = Buffer.from(metadata.authTag, 'base64');

    const decryptedBuffer = fileCrypto.decryptBuffer(ciphertextBuffer, unwrappedDek, ivBuffer, authTagBuffer);

    // 5. Prompt for save path & write plaintext file
    const saveResult = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Decrypted Shared File',
      defaultPath: metadata.originalName,
    });

    if (saveResult.canceled || !saveResult.filePath) {
      return { success: false, error: 'File save canceled by user.' };
    }

    fs.writeFileSync(saveResult.filePath, decryptedBuffer);

    return {
      success: true,
      savedPath: saveResult.filePath,
      originalName: metadata.originalName,
      decryptedSize: decryptedBuffer.length,
    };
  } catch (error) {
    console.error('[Download & Decrypt Shared File Error]:', error.message);
    return { success: false, error: error.message };
  }
});

function createWindow() {
  const windowTitle = devProfile ? `SecureVault [${devProfile}]` : 'SecureVault';
  mainWindow = new BrowserWindow({
    width: 950,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, '../preload/preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
    title: windowTitle,
  });

  const isDev = !app.isPackaged && process.env.NODE_ENV !== 'production';

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '../../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
