const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  version: process.versions.electron,

  // Cycle 1 Session IPC
  saveSession: (token) => ipcRenderer.invoke('save-session', token),
  getSession: () => ipcRenderer.invoke('get-session'),
  clearSession: () => ipcRenderer.invoke('clear-session'),

  // Cycle 2 Cryptographic Identity IPC
  getIdentityStatus: () => ipcRenderer.invoke('get-identity-status'),
  ensureIdentity: () => ipcRenderer.invoke('ensure-identity'),

  // Cycle 3 Basic Local File Encryption IPC
  selectFile: () => ipcRenderer.invoke('select-file'),
  encryptFile: (filePath) => ipcRenderer.invoke('encrypt-file', filePath),
  decryptFile: (fileId) => ipcRenderer.invoke('decrypt-file', fileId),
  verifyIntegrity: (origPath, decPath) => ipcRenderer.invoke('verify-file-integrity', origPath, decPath),
  testTamper: (fileId) => ipcRenderer.invoke('test-tamper-decryption', fileId),
  testDoubleEncrypt: (filePath) => ipcRenderer.invoke('test-double-encryption', filePath),
});
