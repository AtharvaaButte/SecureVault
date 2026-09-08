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

  // Cycle 4 Cloud Ciphertext Upload IPC (Phase 9D with sensitivityLevel & reauthPassword)
  uploadCiphertext: (payload) => ipcRenderer.invoke('upload-ciphertext', payload),
  getUserFiles: (token) => ipcRenderer.invoke('get-user-files', token),

  // Cycle 5 Cloud File Download & Local Decryption IPC (Phase 9D with reauthPassword)
  downloadDecryptFile: (payload) => ipcRenderer.invoke('download-decrypt-file', payload),

  // File Management & Search IPC
  deleteFile: (payload) => ipcRenderer.invoke('delete-file', payload),
  searchOrganizationMembers: (payload) => ipcRenderer.invoke('search-organization-members', payload),

  // Cycle 6 & 7 & 9 E2EE File Sharing, Access Control & Risk-Based IPC
  getOrganizationUsers: (token) => ipcRenderer.invoke('get-organization-users', token),
  shareFile: (payload) => ipcRenderer.invoke('share-file', payload),
  revokeFileShare: (payload) => ipcRenderer.invoke('revoke-file-share', payload),
  getFileShares: (fileId, token) => ipcRenderer.invoke('get-file-shares', { fileId, token }),
  getSharedFiles: (token) => ipcRenderer.invoke('get-shared-files', token),
  downloadDecryptSharedFile: (payload) => ipcRenderer.invoke('download-decrypt-shared-file', payload),
  getUserPermissions: (token) => ipcRenderer.invoke('get-user-permissions', token),
});
