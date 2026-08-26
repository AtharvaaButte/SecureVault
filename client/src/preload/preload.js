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
});
