const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow = null;
const SESSION_FILE_PATH = path.join(app.getPath('userData'), 'session_token.enc');

// IPC Handlers for OS-secure persistent session storage
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
