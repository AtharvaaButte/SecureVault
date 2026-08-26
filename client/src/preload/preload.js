const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  version: process.versions.electron,
  saveSession: (token) => ipcRenderer.invoke('save-session', token),
  getSession: () => ipcRenderer.invoke('get-session'),
  clearSession: () => ipcRenderer.invoke('clear-session'),
});
