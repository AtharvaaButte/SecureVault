const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const keytar = require('keytar');

const fileCrypto = require('./crypto/fileCrypto');
const keyWrapping = require('./crypto/keyWrapping');
const tempStorage = require('./storage/tempStorage');

let mainWindow = null;
let localPrivateKeyPem = null;

// Profile isolation support (--profile=alice or --profile=bob)
const profileArg = process.argv.find(arg => arg.startsWith('--profile='));
const devProfile = profileArg ? profileArg.split('=')[1].trim().toLowerCase() : null;

if (devProfile) {
  const customUserDataPath = path.join(app.getPath('appData'), 'SecureVault-Profiles', devProfile);
  app.setPath('userData', customUserDataPath);
  console.log(`[Profile Isolation] Running Electron with profile: "${devProfile}" at ${customUserDataPath}`);
}

const SERVICE_NAME = 'SecureVault';
const ACCOUNT_NAME = devProfile ? `session_token_${devProfile}` : 'session_token';
const IDENTITY_PRIV_ACCOUNT = devProfile ? `identity_priv_key_${devProfile}` : 'identity_priv_key';

const IDENTITY_DIR = path.join(app.getPath('userData'), 'identity');
const IDENTITY_PUB_PATH = path.join(IDENTITY_DIR, 'public_key.json');

const getDeviceId = () => devProfile ? `electron-profile-${devProfile}` : `electron-default-device`;
const getDevicePlatform = () => `${process.platform}-${process.arch}`;

// SafeStorage fallback wrapper
async function saveSecret(account, secret) {
  try {
    await keytar.setPassword(SERVICE_NAME, account, secret);
  } catch (err) {
    console.warn('[SafeStorage Warning] Keytar failed, using local secure storage fallback:', err.message);
    const fallbackDir = path.join(app.getPath('userData'), '.secure_store');
    if (!fs.existsSync(fallbackDir)) fs.mkdirSync(fallbackDir, { recursive: true });
    const filePath = path.join(fallbackDir, `${account}.enc`);
    const enc = fileCrypto.encryptBuffer(Buffer.from(secret, 'utf-8'));
    fs.writeFileSync(filePath, JSON.stringify({
      iv: enc.iv.toString('base64'),
      authTag: enc.authTag.toString('base64'),
      ciphertext: enc.ciphertext.toString('base64'),
    }));
  }
}

async function getSecret(account) {
  try {
    const password = await keytar.getPassword(SERVICE_NAME, account);
    if (password) return password;
  } catch (err) {
    console.warn('[SafeStorage Warning] Keytar failed, trying local secure store fallback:', err.message);
  }

  const fallbackDir = path.join(app.getPath('userData'), '.secure_store');
  const filePath = path.join(fallbackDir, `${account}.enc`);
  if (fs.existsSync(filePath)) {
    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      const iv = Buffer.from(data.iv, 'base64');
      const authTag = Buffer.from(data.authTag, 'base64');
      const ciphertext = Buffer.from(data.ciphertext, 'base64');
      const staticFallbackKey = crypto.createHash('sha256').update(app.getPath('userData')).digest();
      const dec = fileCrypto.decryptBuffer(ciphertext, staticFallbackKey, iv, authTag);
      return dec.toString('utf-8');
    } catch (e) {
      console.error('[Fallback Secret Recovery Error]:', e.message);
    }
  }
  return null;
}

async function deleteSecret(account) {
  try {
    await keytar.deletePassword(SERVICE_NAME, account);
  } catch (err) {
    // Ignore keytar error
  }
  const fallbackDir = path.join(app.getPath('userData'), '.secure_store');
  const filePath = path.join(fallbackDir, `${account}.enc`);
  if (fs.existsSync(filePath)) {
    try { fs.unlinkSync(filePath); } catch (e) {}
  }
}

// --- IPC Handlers for Cycle 1 (Session Management) ---
ipcMain.handle('save-session', async (_event, token) => {
  try {
    await saveSecret(ACCOUNT_NAME, token);
    return { success: true };
  } catch (error) {
    console.error('[Save Session Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-session', async () => {
  try {
    const token = await getSecret(ACCOUNT_NAME);
    return token || null;
  } catch (error) {
    console.error('[Get Session Error]:', error.message);
    return null;
  }
});

ipcMain.handle('clear-session', async () => {
  try {
    await deleteSecret(ACCOUNT_NAME);
    return { success: true };
  } catch (error) {
    console.error('[Clear Session Error]:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC Handlers for Cycle 2 (Cryptographic Identity) ---
ipcMain.handle('get-identity-status', async () => {
  try {
    const hasPub = fs.existsSync(IDENTITY_PUB_PATH);
    const privSecret = await getSecret(IDENTITY_PRIV_ACCOUNT);
    const hasPriv = Boolean(privSecret);
    return { hasIdentity: hasPub && hasPriv, profile: devProfile || 'default' };
  } catch (error) {
    console.error('[Get Identity Status Error]:', error.message);
    return { hasIdentity: false, profile: devProfile || 'default' };
  }
});

ipcMain.handle('ensure-identity', async () => {
  try {
    if (!fs.existsSync(IDENTITY_DIR)) {
      fs.mkdirSync(IDENTITY_DIR, { recursive: true });
    }

    let privPem = await getSecret(IDENTITY_PRIV_ACCOUNT);
    let pubPem = null;

    if (!privPem || !fs.existsSync(IDENTITY_PUB_PATH)) {
      console.log('[Crypto Identity] Generating new X25519 keypair for local device...');
      const keyPair = crypto.generateKeyPairSync('x25519');
      privPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
      pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

      await saveSecret(IDENTITY_PRIV_ACCOUNT, privPem);
      fs.writeFileSync(IDENTITY_PUB_PATH, JSON.stringify({ publicKey: pubPem, createdAt: new Date().toISOString() }), 'utf-8');
      console.log('[Crypto Identity] Generated & safely stored X25519 identity keypair.');
    } else {
      const pubData = JSON.parse(fs.readFileSync(IDENTITY_PUB_PATH, 'utf-8'));
      pubPem = pubData.publicKey;
    }

    localPrivateKeyPem = privPem;

    return {
      hasIdentity: true,
      publicKey: pubPem,
      profile: devProfile || 'default',
    };
  } catch (error) {
    console.error('[Ensure Identity Error]:', error.message);
    return { hasIdentity: false, error: error.message };
  }
});

// --- IPC Handlers for Cycle 3 (Basic Local File Encryption) ---
ipcMain.handle('select-file', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      title: 'Select File for Local Encryption',
    });

    if (result.canceled || result.filePaths.length === 0) {
      return { canceled: true };
    }

    const filePath = result.filePaths[0];
    const stats = fs.statSync(filePath);
    return {
      canceled: false,
      filePath,
      fileName: path.basename(filePath),
      fileSize: stats.size,
    };
  } catch (error) {
    console.error('[Select File Error]:', error.message);
    return { canceled: true, error: error.message };
  }
});

ipcMain.handle('encrypt-file', async (_event, filePath) => {
  try {
    const tempDir = tempStorage.getTempDir(app);
    const result = tempStorage.storeAndEncryptFile(filePath, tempDir);
    return {
      success: true,
      fileId: result.fileId,
      originalName: result.originalName,
      originalSize: result.originalSize,
      encryptedSize: result.encryptedSize,
      algorithm: result.algorithm,
      iv: result.iv,
      authTag: result.authTag,
    };
  } catch (error) {
    console.error('[Local File Encryption Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('decrypt-file', async (_event, fileId) => {
  try {
    const tempDir = tempStorage.getTempDir(app);
    const result = tempStorage.decryptTempFile(tempDir, fileId);

    const saveResult = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Decrypted File',
      defaultPath: result.metadata.originalName,
    });

    if (saveResult.canceled || !saveResult.filePath) {
      return { success: false, error: 'File save canceled by user.' };
    }

    fs.writeFileSync(saveResult.filePath, result.decryptedBuffer);

    return {
      success: true,
      savedPath: saveResult.filePath,
      originalName: result.metadata.originalName,
      decryptedSize: result.decryptedBuffer.length,
    };
  } catch (error) {
    console.error('[Local File Decryption Error]:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC Handlers for Cloud Upload (Phase 9D with sensitivityLevel & reauthPassword) ---
ipcMain.handle('upload-ciphertext', async (_event, { fileId, dataClassification, sensitivityLevel, token, reauthPassword }) => {
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
    formData.append('dataClassification', dataClassification || sensitivityLevel || 'INTERNAL');
    formData.append('sensitivityLevel', dataClassification || sensitivityLevel || 'INTERNAL');

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

    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-Client-Device-ID': getDeviceId(),
      'X-Client-Platform': getDevicePlatform(),
    };
    if (reauthPassword) {
      headers['X-Reauth-Password'] = reauthPassword;
    }

    const response = await fetch('http://localhost:5000/api/files/upload', {
      method: 'POST',
      headers,
      body: formData,
    });

    const data = await response.json();
    if (!response.ok) {
      return {
        success: false,
        error: data.message || 'Cloud upload failed',
        status: response.statusCode || response.status,
        stepUpRequired: Boolean(data.stepUpRequired),
      };
    }

    return { success: true, file: data.file };
  } catch (error) {
    console.error('[Upload Ciphertext Error]:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC Handler for Cloud File Download & Local Decryption (Phase 9D) ---
ipcMain.handle('download-decrypt-file', async (_event, { fileId, token, reauthPassword }) => {
  try {
    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-Client-Device-ID': getDeviceId(),
      'X-Client-Platform': getDevicePlatform(),
    };
    if (reauthPassword) {
      headers['X-Reauth-Password'] = reauthPassword;
    }

    const response = await fetch(`http://localhost:5000/api/files/${fileId}/download`, { headers });
    const data = await response.json();

    if (!response.ok) {
      return {
        success: false,
        error: data.message || 'Failed to download encrypted file from cloud',
        status: response.status,
        stepUpRequired: Boolean(data.stepUpRequired),
      };
    }

    const { ciphertext, metadata, wrapping } = data;
    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');
    const iv = Buffer.from(metadata.iv, 'base64');
    const authTag = Buffer.from(metadata.authTag, 'base64');

    // Retrieve DEK from Electron main-process memory or recover from backend wrapped key
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
    }

    const decryptedBuffer = fileCrypto.decryptBuffer(ciphertextBuffer, dek, iv, authTag);

    const saveResult = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Decrypted File',
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
    console.error('[Download & Decrypt Error]:', error.message);
    return { success: false, error: error.message };
  }
});

// --- IPC Handlers for File Listing & Access Control ---
ipcMain.handle('get-user-files', async (_event, token) => {
  try {
    const response = await fetch('http://localhost:5000/api/files', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Client-Device-ID': getDeviceId(),
        'X-Client-Platform': getDevicePlatform(),
      },
    });
    const data = await response.json();
    if (!response.ok) return { success: false, error: data.message || 'Failed to fetch user files', status: response.status, files: [] };
    return { success: true, files: data.files };
  } catch (error) {
    console.error('[Get User Files Error]:', error.message);
    return { success: false, error: error.message, files: [] };
  }
});

ipcMain.handle('get-organization-users', async (_event, token) => {
  try {
    const response = await fetch('http://localhost:5000/api/users', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Client-Device-ID': getDeviceId(),
        'X-Client-Platform': getDevicePlatform(),
      },
    });
    const data = await response.json();
    if (!response.ok) return { success: false, error: data.message || 'Failed to fetch users', status: response.status, users: [] };
    return { success: true, users: data.users };
  } catch (error) {
    console.error('[Get Users Error]:', error.message);
    return { success: false, error: error.message, users: [] };
  }
});

ipcMain.handle('share-file', async (_event, { fileId, recipientUserId, recipientPublicKey, token, reauthPassword }) => {
  try {
    if (!localPrivateKeyPem) {
      throw new Error('Local cryptographic identity private key is missing.');
    }

    let dek = fileCrypto.getDek(fileId);

    if (!dek) {
      const headers = {
        'Authorization': `Bearer ${token}`,
        'X-Client-Device-ID': getDeviceId(),
        'X-Client-Platform': getDevicePlatform(),
      };
      if (reauthPassword) headers['X-Reauth-Password'] = reauthPassword;

      const dlRes = await fetch(`http://localhost:5000/api/files/${fileId}/download`, { headers });
      const dlData = await dlRes.json();
      if (!dlRes.ok) {
        return {
          success: false,
          error: dlData.message || 'Wrapped key retrieval failed',
          status: dlRes.status,
          stepUpRequired: Boolean(dlData.stepUpRequired),
        };
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
    }

    if (!fs.existsSync(IDENTITY_PUB_PATH)) {
      throw new Error('Local public key file missing.');
    }

    const pubData = JSON.parse(fs.readFileSync(IDENTITY_PUB_PATH, 'utf-8'));
    const senderPublicKey = pubData.publicKey;

    const wrappingPayload = keyWrapping.wrapDek(
      dek,
      localPrivateKeyPem,
      recipientPublicKey,
      fileId,
      recipientUserId
    );

    const shareHeaders = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'X-Client-Device-ID': getDeviceId(),
      'X-Client-Platform': getDevicePlatform(),
    };
    if (reauthPassword) shareHeaders['X-Reauth-Password'] = reauthPassword;

    const response = await fetch(`http://localhost:5000/api/files/${fileId}/share`, {
      method: 'POST',
      headers: shareHeaders,
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
    if (!response.ok) {
      return {
        success: false,
        error: data.message || 'Failed to share file',
        status: response.status,
        stepUpRequired: Boolean(data.stepUpRequired),
      };
    }
    return { success: true, message: data.message };
  } catch (error) {
    console.error('[Share File Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('revoke-file-share', async (_event, { fileId, recipientUserId, token, reauthPassword }) => {
  try {
    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-Client-Device-ID': getDeviceId(),
      'X-Client-Platform': getDevicePlatform(),
    };
    if (reauthPassword) headers['X-Reauth-Password'] = reauthPassword;

    const response = await fetch(`http://localhost:5000/api/files/${fileId}/share/${recipientUserId}`, {
      method: 'DELETE',
      headers,
    });
    const data = await response.json();
    if (!response.ok) {
      return {
        success: false,
        error: data.message || 'Failed to revoke share',
        status: response.status,
        stepUpRequired: Boolean(data.stepUpRequired),
      };
    }
    return { success: true, message: data.message };
  } catch (error) {
    console.error('[Revoke Share Error]:', error.message);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-file-shares', async (_event, { fileId, token }) => {
  try {
    const response = await fetch(`http://localhost:5000/api/files/${fileId}/shares`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Client-Device-ID': getDeviceId(),
        'X-Client-Platform': getDevicePlatform(),
      },
    });
    const data = await response.json();
    if (!response.ok) return { success: false, error: data.message || 'Failed to fetch shares', status: response.status, shares: [] };
    return { success: true, shares: data.shares };
  } catch (error) {
    console.error('[Get Shares Error]:', error.message);
    return { success: false, error: error.message, shares: [] };
  }
});

ipcMain.handle('get-shared-files', async (_event, token) => {
  try {
    const response = await fetch('http://localhost:5000/api/files/shared', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Client-Device-ID': getDeviceId(),
        'X-Client-Platform': getDevicePlatform(),
      },
    });
    const data = await response.json();
    if (!response.ok) return { success: false, error: data.message || 'Failed to fetch shared files', status: response.status, sharedFiles: [] };
    return { success: true, sharedFiles: data.sharedFiles };
  } catch (error) {
    console.error('[Get Shared Files Error]:', error.message);
    return { success: false, error: error.message, sharedFiles: [] };
  }
});

ipcMain.handle('download-decrypt-shared-file', async (_event, { fileId, currentUserId, token, reauthPassword }) => {
  try {
    if (!localPrivateKeyPem) {
      throw new Error('Local cryptographic identity private key is not available.');
    }

    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-Client-Device-ID': getDeviceId(),
      'X-Client-Platform': getDevicePlatform(),
    };
    if (reauthPassword) headers['X-Reauth-Password'] = reauthPassword;

    const response = await fetch(`http://localhost:5000/api/files/${fileId}/download`, { headers });
    const data = await response.json();

    if (!response.ok) {
      return {
        success: false,
        error: data.message || 'Failed to download shared file payload',
        status: response.status,
        stepUpRequired: Boolean(data.stepUpRequired),
      };
    }

    const { ciphertext, metadata, wrapping } = data;
    if (!wrapping) {
      throw new Error('Shared file wrapping metadata is missing.');
    }

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

    fileCrypto.storeDek(fileId, unwrappedDek);

    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');
    const ivBuffer = Buffer.from(metadata.iv, 'base64');
    const authTagBuffer = Buffer.from(metadata.authTag, 'base64');

    const decryptedBuffer = fileCrypto.decryptBuffer(ciphertextBuffer, unwrappedDek, ivBuffer, authTagBuffer);

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
    width: 1000,
    height: 750,
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
