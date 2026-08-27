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

  // Cycle 4 Cloud Ciphertext Upload IPC
  uploadCiphertext: (fileId, token) => ipcRenderer.invoke('upload-ciphertext', { fileId, token }),

  // Cycle 5 Cloud File Download & Local Decryption IPC
  downloadDecryptFile: (fileId, token) => ipcRenderer.invoke('download-decrypt-file', { fileId, token }),

  // Cycle 6 E2EE File Sharing IPC
  getOrganizationUsers: (token) => ipcRenderer.invoke('get-organization-users', token),
  shareFile: (fileId, recipientUserId, recipientPublicKey, token) => ipcRenderer.invoke('share-file', { fileId, recipientUserId, recipientPublicKey, token }),
  getSharedFiles: (token) => ipcRenderer.invoke('get-shared-files', token),
  downloadDecryptSharedFile: (fileId, currentUserId, token) => ipcRenderer.invoke('download-decrypt-shared-file', { fileId, currentUserId, token }),
});
