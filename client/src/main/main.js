const { app, BrowserWindow, ipcMain, safeStorage, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Imported modules for separation of concerns
const fileCrypto = require('./crypto/fileCrypto');
const tempStorage = require('./storage/tempStorage');
const fileService = require('./file/fileService');

let mainWindow = null;

const SESSION_FILE_PATH = path.join(app.getPath('userData'), 'session_token.enc');
const IDENTITY_KEY_PATH = path.join(app.getPath('userData'), 'identity_key.enc');
const IDENTITY_PUB_PATH = path.join(app.getPath('userData'), 'identity_pub.json');

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

// Select a local file via native dialog
ipcMain.handle('select-file', async () => {
  try {
    return await fileService.selectLocalFile(dialog, mainWindow);
  } catch (error) {
    console.error('[Select File Error]:', error.message);
    return null;
  }
});

// Encrypt local file using AES-256-GCM and store in temp storage
ipcMain.handle('encrypt-file', async (_event, filePath) => {
  try {
    const fileId = crypto.randomUUID();
    const fileName = path.basename(filePath);
    const stats = fileService.getFileStats(filePath);
    const plaintext = fileService.readFileBuffer(filePath);

    // Encrypt using fileCrypto service (generates fresh 256-bit DEK & fresh 96-bit IV)
    const { dek, iv, ciphertext, authTag } = fileCrypto.encryptBuffer(plaintext);

    // Store DEK exclusively in memory
    fileCrypto.storeDek(fileId, dek);

    // Save encrypted ciphertext and metadata to temp directory
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

// Decrypt file using in-memory DEK & metadata from temp storage
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

    // Decrypt ciphertext using fileCrypto service (verifies authTag)
    const decryptedBuffer = fileCrypto.decryptBuffer(ciphertext, dek, iv, authTag);

    // Save decrypted output file to temp directory
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

// Verify byte-for-byte & SHA-256 integrity between original and decrypted files
ipcMain.handle('verify-file-integrity', async (_event, originalPath, decryptedPath) => {
  try {
    return fileService.verifyFileIntegrity(originalPath, decryptedPath);
  } catch (error) {
    console.error('[Verify Integrity Error]:', error.message);
    return { identical: false, error: error.message };
  }
});

// Test 2 & 3: Attempt decryption on tampered ciphertext/authTag (Must fail!)
ipcMain.handle('test-tamper-decryption', async (_event, fileId) => {
  try {
    const dek = fileCrypto.getDek(fileId);
    if (!dek) throw new Error('DEK not in memory');

    const tempDir = tempStorage.getTempDir(app);
    const metadata = tempStorage.readMetadata(tempDir, fileId);
    const ciphertext = tempStorage.readEncryptedFile(tempDir, fileId);

    // Corrupt the first byte of ciphertext
    const tamperedCiphertext = Buffer.from(ciphertext);
    tamperedCiphertext[0] = tamperedCiphertext[0] ^ 0xFF;

    const iv = Buffer.from(metadata.iv, 'base64');
    const authTag = Buffer.from(metadata.authTag, 'base64');

    // Attempt decryption (MUST throw exception!)
    fileCrypto.decryptBuffer(tamperedCiphertext, dek, iv, authTag);

    return { caughtTampering: false, error: 'Decryption succeeded on tampered data without auth failure!' };
  } catch (error) {
    return {
      caughtTampering: true,
      errorMessage: error.message,
    };
  }
});

// Test 4: Encrypt the same file twice to verify distinct IVs and non-identical ciphertexts
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

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 950,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, '../preload/preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
    title: 'SecureVault',
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
