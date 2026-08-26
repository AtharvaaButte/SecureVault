const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const { generateKeyPairSync } = require('crypto');

let mainWindow = null;

const SESSION_FILE_PATH = path.join(app.getPath('userData'), 'session_token.enc');
const IDENTITY_KEY_PATH = path.join(app.getPath('userData'), 'identity_key.enc');
const IDENTITY_PUB_PATH = path.join(app.getPath('userData'), 'identity_pub.json');

// In-memory reference to unlocked private key in main process (never sent to renderer or network)
let localPrivateKeyPem = null;

// --- IPC Handlers for OS-secure persistent session storage ---
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

// Get identity status without modifying state
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

// Ensure local identity exists (retrieve existing or generate new X25519 key pair locally)
ipcMain.handle('ensure-identity', async () => {
  try {
    const keyExists = fs.existsSync(IDENTITY_KEY_PATH);
    const pubExists = fs.existsSync(IDENTITY_PUB_PATH);

    if (keyExists && pubExists) {
      // Identity exists: unlock private key securely using OS safeStorage
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

    // Identity does not exist: Generate new X25519 key pair locally
    console.log('[Crypto] Generating new X25519 cryptographic key pair locally...');
    const { publicKey, privateKey } = generateKeyPairSync('x25519');

    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

    // Store private key using OS safeStorage
    if (safeStorage.isEncryptionAvailable()) {
      const encryptedBuffer = safeStorage.encryptString(privateKeyPem);
      fs.writeFileSync(IDENTITY_KEY_PATH, encryptedBuffer);
    } else {
      fs.writeFileSync(IDENTITY_KEY_PATH, Buffer.from(privateKeyPem, 'utf-8'));
    }

    // Store public key metadata locally
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
