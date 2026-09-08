import React, { useEffect, useState } from 'react';

// Layout Components
import Sidebar from './components/Layout/Sidebar';
import Header from './components/Layout/Header';

// Common Components
import Alert from './components/Common/Alert';
import LoadingSpinner from './components/Common/LoadingSpinner';
import Modal from './components/Common/Modal';

// Modal Components
import StepUpModal from './components/Modals/StepUpModal';
import FileShareModal from './components/Modals/FileShareModal';
import EditUserRolesModal from './components/Modals/EditUserRolesModal';
import CreateRoleModal from './components/Modals/CreateRoleModal';

// Pages
import DashboardPage from './pages/DashboardPage';
import FilesPage from './pages/FilesPage';
import MembersPage from './pages/MembersPage';
import RolesPage from './pages/RolesPage';
import PoliciesPage from './pages/PoliciesPage';
import AuditPage from './pages/AuditPage';
import AccountSetupPage from './pages/AccountSetupPage';

const API_BASE = 'http://localhost:5000/api';

function getFriendlyErrorMessage(err) {
  if (!err) return 'An unexpected error occurred.';
  const msg = typeof err === 'string' ? err : (err.message || String(err));

  if (msg.includes('Failed to fetch') || msg.includes('ERR_CONNECTION_REFUSED') || msg.includes('NetworkError')) {
    return 'Unable to connect to the SecureVault backend server. Please verify that the server is running on port 5000 and try again.';
  }
  if (msg.includes('jwt expired') || msg.includes('jwt malformed')) {
    return 'Your authentication session has expired. Please sign in again.';
  }
  return msg;
}

export default function App() {
  // Session & Identity Context
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  const [userPermissions, setUserPermissions] = useState([]);
  const [cryptoIdentity, setCryptoIdentity] = useState({ protected: false, registered: false, publicKey: null });

  // Active Setup Flow State
  const [activeSetupToken, setActiveSetupToken] = useState(() => {
    const path = window.location.pathname;
    if (path.startsWith('/setup/')) {
      return path.split('/setup/')[1];
    }
    return null;
  });

  // Active Tab: 'dashboard' | 'files' | 'members' | 'roles' | 'policies' | 'audit'
  const [navTab, setNavTab] = useState('dashboard');

  // File Vault State
  const [selectedFile, setSelectedFile] = useState(null);
  const [encryptResult, setEncryptResult] = useState(null);
  const [uploadClassification, setUploadClassification] = useState('INTERNAL');
  const [fileList, setFileList] = useState([]);
  const [sharedFileList, setSharedFileList] = useState([]);
  const [downloadStatus, setDownloadStatus] = useState({});
  const [sharedDownloadStatus, setSharedDownloadStatus] = useState({});
  const [fileShares, setFileShares] = useState({});
  const [userPermissionsCache, setUserPermissionsCache] = useState({});

  // Members & Roles State
  const [orgMembers, setOrgMembers] = useState([]);
  const [ownerInfo, setOwnerInfo] = useState(null);
  const [orgRoles, setOrgRoles] = useState([]);
  const [allPermissions, setAllPermissions] = useState([]);
  const [permissionAuditRecords, setPermissionAuditRecords] = useState([]);

  // Policies & Audit State
  const [orgPolicy, setOrgPolicy] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditVerification, setAuditVerification] = useState(null);

  // Modals & Popups State
  const [stepUpModal, setStepUpModal] = useState({ show: false, reason: '', pendingAction: null });
  const [activeShareModalFile, setActiveShareModalFile] = useState(null);
  const [editingUserModalTarget, setEditingUserModalTarget] = useState(null);
  const [showCreateRoleModal, setShowCreateRoleModal] = useState(false);
  const [showSetupTokenModal, setShowSetupTokenModal] = useState(false);
  const [setupTokenInput, setSetupTokenInput] = useState('');

  // UI System States
  const [authTab, setAuthTab] = useState('login'); // 'login' | 'register'
  const [loading, setLoading] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Auth Form State
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [regOrgName, setRegOrgName] = useState('');
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirmPassword, setRegConfirmPassword] = useState('');

  // Helper for JSON API calls & status checks
  const parseJsonResponse = async (res, fallbackMessage = 'Request failed') => {
    const contentType = res.headers.get('content-type');
    const isJson = contentType && contentType.includes('application/json');
    const data = isJson ? await res.json() : {};
    if (!res.ok) {
      const errObj = new Error(data.message || `${fallbackMessage} (${res.status} ${res.statusText})`);
      errObj.status = res.status;
      errObj.stepUpRequired = Boolean(data.stepUpRequired);
      errObj.setupRequired = Boolean(data.setupRequired);
      errObj.setupToken = data.setupToken || null;
      throw errObj;
    }
    return data;
  };

  const promptStepUp = (reason, actionCallback) => {
    setError(null);
    setStepUpModal({
      show: true,
      reason: reason || 'Step-up re-authentication required for this sensitive operation.',
      pendingAction: actionCallback,
    });
  };

  const handleStepUpSubmit = async (pwd) => {
    const action = stepUpModal.pendingAction;
    setStepUpModal({ show: false, reason: '', pendingAction: null });
    if (action) {
      action(pwd);
    }
  };

  // Setup Cryptographic X25519 Identity
  const setupCryptoIdentity = async (authToken, userObj = null) => {
    if (window.electronAPI) {
      try {
        const status = await window.electronAPI.getIdentityStatus();
        if (!status.hasIdentity || !status.publicKey) {
          const ensured = await window.electronAPI.ensureIdentity();
          setCryptoIdentity({ ...ensured, hasIdentity: true });
        } else {
          setCryptoIdentity({ ...status, hasIdentity: true });
        }
        return;
      } catch (err) {
        console.error('[Identity Setup Error]:', err.message);
      }
    }
    // Web / Browser mode fallback or when user key is registered on backend
    const pubKey = userObj?.publicKey || currentUser?.publicKey || 'X25519-KEY-REGISTERED';
    setCryptoIdentity({ hasIdentity: true, registered: true, publicKey: pubKey });
  };

  // Restore session from Electron storage on startup
  useEffect(() => {
    const restoreSession = async () => {
      if (window.electronAPI) {
        try {
          const savedToken = await window.electronAPI.getSession();
          if (savedToken) {
            setToken(savedToken);
            await setupCryptoIdentity(savedToken);
            await fetchAllData(savedToken);
          }
        } catch (e) {
          console.error('[Session Restore Error]:', e.message);
        }
      }
      setInitializing(false);
    };
    restoreSession();
  }, []);

  // Fetch all dashboard & domain data
  const fetchAllData = async (authToken) => {
    const currentTkn = authToken || token;
    if (!currentTkn) return;

    fetchUserProfile(currentTkn);
    fetchUserFiles(currentTkn);
    fetchSharedFiles(currentTkn);
    fetchOrgMembers(currentTkn);
    fetchOrgRoles(currentTkn);
    fetchAllPermissionsCatalog(currentTkn);
    fetchPermissionAuditView(currentTkn);
    fetchOrgPolicy(currentTkn);
    fetchAuditLogs(currentTkn);
  };

  const fetchUserProfile = async (authToken) => {
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch user profile');
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);
      setUserPermissions(data.user.permissions || []);
      setupCryptoIdentity(authToken, data.user);
    } catch (err) {
      console.error('[Fetch Profile Error]:', err.message);
    }
  };

  const fetchUserFiles = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      let files = [];
      if (window.electronAPI && typeof window.electronAPI.getUserFiles === 'function') {
        const res = await window.electronAPI.getUserFiles(tkn);
        if (res.success) files = res.files || [];
      } else {
        const res = await fetch(`${API_BASE}/files`, {
          headers: { 'Authorization': `Bearer ${tkn}` },
        });
        const data = await parseJsonResponse(res, 'Failed to fetch files');
        files = data.files || [];
      }
      setFileList(files);
    } catch (err) {
      console.error('[Fetch Files Error]:', err.message);
    }
  };

  const fetchSharedFiles = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      let sharedFiles = [];
      if (window.electronAPI && typeof window.electronAPI.getSharedFiles === 'function') {
        const res = await window.electronAPI.getSharedFiles(tkn);
        if (res.success) sharedFiles = res.sharedFiles || [];
      } else {
        const res = await fetch(`${API_BASE}/files/shared`, {
          headers: { 'Authorization': `Bearer ${tkn}` },
        });
        const data = await parseJsonResponse(res, 'Failed to fetch shared files');
        sharedFiles = data.sharedFiles || [];
      }
      setSharedFileList(sharedFiles);
    } catch (err) {
      console.error('[Fetch Shared Files Error]:', err.message);
    }
  };

  const fetchFileShares = async (fileId, authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      let shares = [];
      if (window.electronAPI && typeof window.electronAPI.getFileShares === 'function') {
        const res = await window.electronAPI.getFileShares(fileId, tkn);
        if (res.success) shares = res.shares || [];
      } else {
        const res = await fetch(`${API_BASE}/files/${fileId}/shares`, {
          headers: { 'Authorization': `Bearer ${tkn}` },
        });
        const data = await parseJsonResponse(res, 'Failed to fetch file shares');
        shares = data.shares || [];
      }
      setFileShares((prev) => ({ ...prev, [fileId]: shares }));
    } catch (err) {
      console.error('[Fetch File Shares Error]:', err.message);
    }
  };

  const fetchOrgMembers = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      const res = await fetch(`${API_BASE}/users/members`, {
        headers: { 'Authorization': `Bearer ${tkn}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch members');
      setOrgMembers(data.users || []);
      setOwnerInfo(data.owner || null);
    } catch (err) {
      console.error('[Fetch Members Error]:', err.message);
    }
  };

  const fetchUserPermissionsCache = async (targetUserId) => {
    if (!token || !targetUserId) return null;
    try {
      const res = await fetch(`${API_BASE}/users/${targetUserId}/permissions`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch user permissions');
      setUserPermissionsCache((prev) => ({ ...prev, [targetUserId]: data }));
      return data;
    } catch (err) {
      console.error('[Fetch User Permissions Error]:', err.message);
      return null;
    }
  };

  const fetchOrgRoles = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      const res = await fetch(`${API_BASE}/roles`, {
        headers: { 'Authorization': `Bearer ${tkn}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch roles');
      setOrgRoles(data.roles || []);
    } catch (err) {
      console.error('[Fetch Roles Error]:', err.message);
    }
  };

  const fetchAllPermissionsCatalog = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      const res = await fetch(`${API_BASE}/roles/permissions/catalog`, {
        headers: { 'Authorization': `Bearer ${tkn}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch catalog');
      setAllPermissions(data.permissions || []);
    } catch (err) {
      console.error('[Fetch Catalog Error]:', err.message);
    }
  };

  const fetchPermissionAuditView = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      const res = await fetch(`${API_BASE}/roles/audit/permissions`, {
        headers: { 'Authorization': `Bearer ${tkn}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch permission view');
      setPermissionAuditRecords(data.auditRecords || []);
    } catch (err) {
      console.error('[Fetch Permission View Error]:', err.message);
    }
  };

  const fetchOrgPolicy = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      const res = await fetch(`${API_BASE}/policies`, {
        headers: { 'Authorization': `Bearer ${tkn}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch policy');
      setOrgPolicy(data.policy || null);
    } catch (err) {
      console.error('[Fetch Policy Error]:', err.message);
    }
  };

  const fetchAuditLogs = async (authToken) => {
    const tkn = authToken || token;
    if (!tkn) return;
    try {
      const res = await fetch(`${API_BASE}/audit/logs`, {
        headers: { 'Authorization': `Bearer ${tkn}` },
      });
      const data = await parseJsonResponse(res, 'Failed to fetch audit logs');
      setAuditLogs(data.auditLogs || []);
    } catch (err) {
      console.error('[Fetch Audit Logs Error]:', err.message);
    }
  };

  const verifyAuditChain = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${API_BASE}/audit/verify`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await parseJsonResponse(res, 'Audit verification failed');
      setAuditVerification(data);
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  // User Authentication Handlers
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });
      const contentType = res.headers.get('content-type');
      const data = contentType && contentType.includes('application/json') ? await res.json() : {};

      if (!res.ok) {
        if (data.setupRequired) {
          if (data.setupToken) {
            setActiveSetupToken(data.setupToken);
          } else {
            setError('Account setup is required before you can continue. Please use your account activation setup link.');
          }
          return;
        }
        throw new Error(data.message || 'Invalid email or password.');
      }

      setToken(data.token);
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);
      setUserPermissions(data.user.permissions || []);
      if (window.electronAPI) {
        await window.electronAPI.saveSession(data.token);
      }
      setupCryptoIdentity(data.token);
      fetchAllData(data.token);
      setSuccessMsg('Successfully logged in.');
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(null);

    const hasMinLen = regPassword.length >= 8;
    const hasUpper = /[A-Z]/.test(regPassword);
    const hasLower = /[a-z]/.test(regPassword);
    const hasNumber = /[0-9]/.test(regPassword);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(regPassword);

    if (!hasMinLen || !hasUpper || !hasLower || !hasNumber || !hasSpecial) {
      setError('Password must be at least 8 characters long and contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.');
      return;
    }

    if (regPassword !== regConfirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgName: regOrgName, name: regName, email: regEmail, password: regPassword }),
      });
      const data = await parseJsonResponse(res, 'Registration failed');
      setToken(data.token);
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);
      setUserPermissions(data.user.permissions || []);
      if (window.electronAPI) {
        await window.electronAPI.saveSession(data.token);
      }
      setupCryptoIdentity(data.token, data.user);
      fetchAllData(data.token);
      setSuccessMsg('Organization & Owner account created successfully.');
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    if (token) {
      try {
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
        });
      } catch (e) {
        console.error('[Logout API Error]:', e.message);
      }
    }

    if (window.electronAPI) {
      await window.electronAPI.clearSession();
    }
    setToken(null);
    setCurrentUser(null);
    setCurrentOrg(null);
    setUserPermissions([]);
    setCryptoIdentity({ protected: false, registered: false, publicKey: null });
    setFileList([]);
    setSharedFileList([]);
    setOrgMembers([]);
    setOwnerInfo(null);
    setSuccessMsg('Logged out successfully.');
  };

  // Local Encryption & Upload Flow
  const handleSelectFile = async () => {
    if (!window.electronAPI) return { canceled: true };
    const res = await window.electronAPI.selectFile();
    if (!res.canceled) {
      setSelectedFile(res);
      setEncryptResult(null);
    }
    return res;
  };

  const handleEncryptFile = async (filePath) => {
    if (!window.electronAPI) return;
    const res = await window.electronAPI.encryptFile(filePath);
    if (res.success) {
      setEncryptResult(res);
      setSuccessMsg('File encrypted locally via AES-256-GCM.');
    } else {
      setError(getFriendlyErrorMessage(res.error || 'Local encryption failed'));
    }
  };

  const handleUploadCiphertext = async (fileId, classification = 'INTERNAL') => {
    if (!token) return;
    setError(null);
    try {
      let res;
      if (window.electronAPI && typeof window.electronAPI.uploadCiphertext === 'function') {
        res = await window.electronAPI.uploadCiphertext({
          fileId,
          token,
          dataClassification: classification,
        });
      } else {
        setError('Ciphertext upload requires Electron IPC integration.');
        return;
      }

      if (res.success) {
        setSuccessMsg('Ciphertext uploaded to Backblaze B2 and stored in Vault.');
        setSelectedFile(null);
        setEncryptResult(null);
        fetchUserFiles();
      } else {
        setError(getFriendlyErrorMessage(res.error || 'Upload failed'));
      }
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  const handleDownloadFile = async (fileId, reauthPassword = null) => {
    if (!token) return;
    setError(null);
    setDownloadStatus((prev) => ({ ...prev, [fileId]: true }));

    const res = await window.electronAPI.downloadDecryptFile({ fileId, token, reauthPassword });
    setDownloadStatus((prev) => ({ ...prev, [fileId]: false }));

    if (res.success) {
      setSuccessMsg(`File decrypted & saved to ${res.savedPath}`);
    } else if (res.stepUpRequired) {
      promptStepUp(res.error, (pwd) => handleDownloadFile(fileId, pwd));
    } else {
      setError(getFriendlyErrorMessage(res.error || 'File decryption failed'));
    }
  };

  const handleDownloadSharedFile = async (fileId, reauthPassword = null) => {
    if (!token || !currentUser) return;
    setError(null);
    setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: true }));

    const res = await window.electronAPI.downloadDecryptSharedFile({
      fileId,
      token,
      recipientUserId: currentUser.id,
      reauthPassword,
    });

    setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: false }));

    if (res.success) {
      setSuccessMsg(`Shared file decrypted & saved to ${res.savedPath}`);
    } else if (res.stepUpRequired) {
      promptStepUp(res.error, (pwd) => handleDownloadSharedFile(fileId, pwd));
    } else {
      setError(getFriendlyErrorMessage(res.error || 'Shared file decryption failed'));
    }
  };

  const handleDeleteFile = async (fileId, reauthPassword = null) => {
    if (!token) return;
    setError(null);
    try {
      let res;
      if (window.electronAPI && typeof window.electronAPI.deleteFile === 'function') {
        res = await window.electronAPI.deleteFile({ fileId, token, reauthPassword });
      } else {
        const headers = { 'Authorization': `Bearer ${token}` };
        if (reauthPassword) headers['X-Reauth-Password'] = reauthPassword;
        const response = await fetch(`${API_BASE}/files/${fileId}`, {
          method: 'DELETE',
          headers,
        });
        const data = await response.json();
        if (!response.ok) {
          res = { success: false, error: data.message || 'Failed to delete file', stepUpRequired: Boolean(data.stepUpRequired) };
        } else {
          res = { success: true, message: data.message };
        }
      }

      if (res.success) {
        setSuccessMsg('File deleted successfully from vault.');
        setFileList((prev) => prev.filter((f) => f.id !== fileId));
        setSharedFileList((prev) => prev.filter((f) => f.id !== fileId));
        fetchUserFiles();
      } else if (res.stepUpRequired) {
        promptStepUp(res.error, (pwd) => handleDeleteFile(fileId, pwd));
      } else {
        setError(getFriendlyErrorMessage(res.error || 'Failed to delete file'));
      }
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  const handleShareFile = async (payload) => {
    if (!token) return { success: false, error: 'Authentication required' };
    try {
      let res;
      if (window.electronAPI && typeof window.electronAPI.shareFile === 'function') {
        res = await window.electronAPI.shareFile({ ...payload, token });
      } else {
        const response = await fetch(`${API_BASE}/files/${payload.fileId}/share`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify(payload),
        });
        const data = await parseJsonResponse(response, 'Share failed');
        res = { success: true, message: data.message };
      }

      if (res.success) {
        fetchFileShares(payload.fileId);
      }
      return res;
    } catch (err) {
      return { success: false, error: getFriendlyErrorMessage(err) };
    }
  };

  const handleRevokeShare = async (fileId, recipientUserId) => {
    if (!token) return { success: false, error: 'Authentication required' };
    try {
      let res;
      if (window.electronAPI && typeof window.electronAPI.revokeFileShare === 'function') {
        res = await window.electronAPI.revokeFileShare({ fileId, recipientUserId, token });
      } else {
        const response = await fetch(`${API_BASE}/files/${fileId}/share/${recipientUserId}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await parseJsonResponse(response, 'Revoke failed');
        res = { success: true, message: data.message };
      }

      if (res.success) {
        fetchFileShares(fileId);
      }
      return res;
    } catch (err) {
      return { success: false, error: getFriendlyErrorMessage(err) };
    }
  };

  const handleCreateUser = async (payload) => {
    try {
      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const data = await parseJsonResponse(res, 'Failed to create user');
      setSuccessMsg(data.message || 'User account created.');
      fetchOrgMembers();
      return { success: true, user: data.user };
    } catch (err) {
      return { success: false, error: getFriendlyErrorMessage(err) };
    }
  };

  const handleUpdateUserRoles = async (userId, roleIds) => {
    try {
      const res = await fetch(`${API_BASE}/users/${userId}/roles`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ roleIds }),
      });
      await parseJsonResponse(res, 'Failed to update user roles');
      setSuccessMsg('User roles updated successfully.');
      fetchOrgMembers();
      fetchPermissionAuditView();
      return { success: true };
    } catch (err) {
      return { success: false, error: getFriendlyErrorMessage(err) };
    }
  };

  const handleDeleteUser = async (userId) => {
    try {
      const res = await fetch(`${API_BASE}/users/${userId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      await parseJsonResponse(res, 'Failed to delete member');
      setSuccessMsg('Member deleted successfully.');
      fetchOrgMembers();
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  const handleCreateRole = async (payload) => {
    try {
      const res = await fetch(`${API_BASE}/roles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      await parseJsonResponse(res, 'Failed to create role');
      setSuccessMsg('Custom role created successfully.');
      fetchOrgRoles();
      fetchPermissionAuditView();
      return { success: true };
    } catch (err) {
      return { success: false, error: getFriendlyErrorMessage(err) };
    }
  };

  const handleDeleteRole = async (roleId) => {
    try {
      const res = await fetch(`${API_BASE}/roles/${roleId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      await parseJsonResponse(res, 'Failed to delete role');
      setSuccessMsg('Role deleted successfully.');
      fetchOrgRoles();
      fetchPermissionAuditView();
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  const handleUpdatePolicy = async (payload) => {
    try {
      const res = await fetch(`${API_BASE}/policies`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const data = await parseJsonResponse(res, 'Failed to update policies');
      setOrgPolicy(data.policy);
      setSuccessMsg('Security policy updated successfully.');
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  const handleAddGeoLocation = async (payload) => {
    try {
      const res = await fetch(`${API_BASE}/policies/locations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const data = await parseJsonResponse(res, 'Failed to add location');
      setOrgPolicy(data.policy);
      setSuccessMsg('Allowed geographic location added.');
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  const handleRemoveGeoLocation = async (geoPolicyId) => {
    try {
      const res = await fetch(`${API_BASE}/policies/locations/${geoPolicyId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await parseJsonResponse(res, 'Failed to remove location');
      setOrgPolicy(data.policy);
      setSuccessMsg('Allowed location removed.');
    } catch (err) {
      setError(getFriendlyErrorMessage(err));
    }
  };

  if (activeSetupToken) {
    return (
      <AccountSetupPage
        setupToken={activeSetupToken}
        onSetupComplete={() => setActiveSetupToken(null)}
        onBackToLogin={() => setActiveSetupToken(null)}
      />
    );
  }

  if (initializing) {
    return <LoadingSpinner text="Initializing SecureVault Security Context..." />;
  }

  // Auth Screen (Unauthenticated)
  if (!token) {
    return (
      <div style={styles.authWrapper}>
        <div className="card" style={{ maxWidth: '440px', width: '100%' }}>
          <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'linear-gradient(135deg, #2563eb, #0284c7)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.5rem', fontWeight: 'bold', color: 'white', marginBottom: '0.75rem' }}>
              SV
            </div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: '700' }}>SecureVault</h2>
            <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              Enterprise E2EE Zero-Trust Vault Platform
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '1.25rem', backgroundColor: 'var(--bg-dark-root)', padding: '0.25rem', borderRadius: '8px' }}>
            <button
              onClick={() => setAuthTab('login')}
              style={{
                flex: 1,
                padding: '0.45rem 0.2rem',
                border: 'none',
                borderRadius: '6px',
                backgroundColor: authTab === 'login' ? 'var(--bg-dark-card-hover)' : 'transparent',
                color: authTab === 'login' ? 'var(--text-primary)' : 'var(--text-muted)',
                fontWeight: '600',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => setAuthTab('setup')}
              style={{
                flex: 1,
                padding: '0.45rem 0.2rem',
                border: 'none',
                borderRadius: '6px',
                backgroundColor: authTab === 'setup' ? 'var(--bg-dark-card-hover)' : 'transparent',
                color: authTab === 'setup' ? 'var(--text-primary)' : 'var(--text-muted)',
                fontWeight: '600',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              Account Setup
            </button>
            <button
              onClick={() => setAuthTab('register')}
              style={{
                flex: 1,
                padding: '0.45rem 0.2rem',
                border: 'none',
                borderRadius: '6px',
                backgroundColor: authTab === 'register' ? 'var(--bg-dark-card-hover)' : 'transparent',
                color: authTab === 'register' ? 'var(--text-primary)' : 'var(--text-muted)',
                fontWeight: '600',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              Register Org
            </button>
          </div>

          <Alert message={error} onClose={() => setError(null)} />
          <Alert type="success" message={successMsg} onClose={() => setSuccessMsg(null)} />

          {authTab === 'login' ? (
            <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input
                  type="email"
                  className="form-input"
                  placeholder="user@org.com"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Password</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  required
                />
              </div>

              <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }}>
                {loading ? 'Authenticating...' : 'Sign In to SecureVault'}
              </button>

              <div style={{ textAlign: 'center', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => {
                    setAuthTab('setup');
                    setShowSetupTokenModal(true);
                  }}
                  style={{ background: 'none', border: 'none', color: 'var(--accent-blue)', fontSize: '0.8rem', cursor: 'pointer', textDecoration: 'underline' }}
                >
                  Have an Account Setup Token? Complete Setup Here
                </button>
              </div>
            </form>
          ) : authTab === 'setup' ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (setupTokenInput && setupTokenInput.trim()) {
                  setActiveSetupToken(setupTokenInput.trim());
                  setSetupTokenInput('');
                }
              }}
              style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
            >
              <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                Enter your <strong>Account Setup Token</strong> provided by your organization administrator to set your password and activate your vault account.
              </div>

              <div className="form-group">
                <label className="form-label">Account Setup Token *</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Paste setup token here..."
                  value={setupTokenInput}
                  onChange={(e) => setSetupTokenInput(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                disabled={!setupTokenInput.trim()}
                style={{ width: '100%', marginTop: '0.5rem', justifyContent: 'center' }}
              >
                Continue Account Setup
              </button>
            </form>
          ) : (
            (() => {
              const regStrength = {
                hasMinLen: (regPassword || '').length >= 8,
                hasUpper: /[A-Z]/.test(regPassword || ''),
                hasLower: /[a-z]/.test(regPassword || ''),
                hasNumber: /[0-9]/.test(regPassword || ''),
                hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(regPassword || ''),
              };
              const isRegValid = Object.values(regStrength).every(Boolean);

              return (
                <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Organization Name *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="Acme Security Corp"
                      value={regOrgName}
                      onChange={(e) => setRegOrgName(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Owner Full Name *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="Jane Doe"
                      value={regOwnerName}
                      onChange={(e) => setRegOwnerName(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Owner Email Address *</label>
                    <input
                      type="email"
                      className="form-input"
                      placeholder="owner@acme.com"
                      value={regEmail}
                      onChange={(e) => setRegEmail(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Owner Master Password *</label>
                    <input
                      type="password"
                      className="form-input"
                      placeholder="••••••••"
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      required
                    />
                  </div>

                  {/* Password Requirements Checklist */}
                  <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '0.65rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.725rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.35rem' }}>
                    <span style={{ color: regStrength.hasMinLen ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      {regStrength.hasMinLen ? '✓' : '•'} 8+ Characters
                    </span>
                    <span style={{ color: regStrength.hasUpper ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      {regStrength.hasUpper ? '✓' : '•'} 1 Uppercase Letter
                    </span>
                    <span style={{ color: regStrength.hasLower ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      {regStrength.hasLower ? '✓' : '•'} 1 Lowercase Letter
                    </span>
                    <span style={{ color: regStrength.hasNumber ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      {regStrength.hasNumber ? '✓' : '•'} 1 Number
                    </span>
                    <span style={{ color: regStrength.hasSpecial ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem', gridColumn: 'span 2' }}>
                      {regStrength.hasSpecial ? '✓' : '•'} 1 Special Character (!@#$%^&*)
                    </span>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Confirm Password *</label>
                    <input
                      type="password"
                      className="form-input"
                      placeholder="Re-enter password"
                      value={regConfirmPassword}
                      onChange={(e) => setRegConfirmPassword(e.target.value)}
                      required
                    />
                    {regConfirmPassword && regPassword !== regConfirmPassword && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--accent-rose)', marginTop: '0.25rem' }}>
                        Passwords do not match.
                      </div>
                    )}
                  </div>

                  <button type="submit" disabled={loading || !isRegValid || regPassword !== regConfirmPassword} className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }}>
                    {loading ? 'Registering...' : 'Register & Create Vault'}
                  </button>
                </form>
              );
            })()
          )}
        </div>

        {/* Account Setup Token Modal for Auth Screen */}
        <Modal
          isOpen={showSetupTokenModal}
          title="Enter Account Setup Token"
          onClose={() => {
            setShowSetupTokenModal(false);
            setSetupTokenInput('');
          }}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (setupTokenInput && setupTokenInput.trim()) {
                setActiveSetupToken(setupTokenInput.trim());
                setShowSetupTokenModal(false);
                setSetupTokenInput('');
              }
            }}
            style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
          >
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', margin: 0 }}>
              Please enter your Account Setup Token provided by your organization administrator.
            </p>
            <div className="form-group">
              <label className="form-label">Setup Token *</label>
              <input
                type="text"
                className="form-input"
                placeholder="Paste your setup token here..."
                value={setupTokenInput}
                onChange={(e) => setSetupTokenInput(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setShowSetupTokenModal(false);
                  setSetupTokenInput('');
                }}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={!setupTokenInput.trim()}>
                Continue Setup
              </button>
            </div>
          </form>
        </Modal>
      </div>
    );
  }

  // Authenticated Main Workspace Layout
  const activeTabLabels = {
    dashboard: 'Security Overview & Metrics',
    files: 'Encrypted Vault & Sharing Management',
    members: 'Organization Member & User Control',
    roles: 'RBAC Roles & System Permissions Catalog',
    policies: 'Contextual Zero-Trust Security Policies',
    audit: 'Tamper-Evident Immutable Audit Log Trail',
  };

  return (
    <div style={styles.appContainer}>
      <Sidebar
        activeTab={navTab}
        setActiveTab={setNavTab}
        orgName={currentOrg?.name}
        currentUser={currentUser}
        userPermissions={userPermissions}
      />

      <div style={styles.mainContent}>
        <Header
          currentUser={currentUser}
          cryptoIdentity={cryptoIdentity}
          onLogout={handleLogout}
          activeTabLabel={activeTabLabels[navTab]}
        />

        <main style={styles.viewBody}>
          <Alert message={error} onClose={() => setError(null)} />
          <Alert type="success" message={successMsg} onClose={() => setSuccessMsg(null)} />

          {navTab === 'dashboard' && (
            <DashboardPage
              currentUser={currentUser}
              currentOrg={currentOrg}
              fileList={fileList}
              sharedFileList={sharedFileList}
              orgMembers={orgMembers}
              orgPolicy={orgPolicy}
              auditVerification={auditVerification}
              onVerifyAuditChain={() => verifyAuditChain()}
              setActiveTab={setNavTab}
            />
          )}

          {navTab === 'files' && (
            <FilesPage
              fileList={fileList}
              sharedFileList={sharedFileList}
              selectedFile={selectedFile}
              encryptResult={encryptResult}
              uploadClassification={uploadClassification}
              setUploadClassification={setUploadClassification}
              onSelectFile={handleSelectFile}
              onEncryptFile={handleEncryptFile}
              onUploadCiphertext={handleUploadCiphertext}
              onDownloadFile={handleDownloadFile}
              onDownloadSharedFile={handleDownloadSharedFile}
              onDeleteFile={handleDeleteFile}
              onOpenShareModal={(file) => {
                setActiveShareModalFile(file);
                fetchFileShares(file.id);
              }}
              downloadStatus={downloadStatus}
              sharedDownloadStatus={sharedDownloadStatus}
              userPermissions={userPermissions}
              currentUser={currentUser}
            />
          )}

          {navTab === 'members' && (
            <MembersPage
              orgMembers={orgMembers}
              ownerInfo={ownerInfo}
              orgRoles={orgRoles}
              onCreateUser={handleCreateUser}
              onEditRoles={(member) => setEditingUserModalTarget(member)}
              onDeleteUser={handleDeleteUser}
              userPermissions={userPermissions}
              currentUser={currentUser}
            />
          )}

          {navTab === 'roles' && (
            <RolesPage
              orgRoles={orgRoles}
              allPermissions={allPermissions}
              permissionAuditRecords={permissionAuditRecords}
              onCreateRole={() => setShowCreateRoleModal(true)}
              onDeleteRole={handleDeleteRole}
              userPermissions={userPermissions}
              currentUser={currentUser}
            />
          )}

          {navTab === 'policies' && (
            <PoliciesPage
              orgPolicy={orgPolicy}
              onUpdatePolicy={handleUpdatePolicy}
              onAddGeoLocation={handleAddGeoLocation}
              onRemoveGeoLocation={handleRemoveGeoLocation}
              userPermissions={userPermissions}
              currentUser={currentUser}
            />
          )}

          {navTab === 'audit' && (
            <AuditPage
              auditLogs={auditLogs}
              auditVerification={auditVerification}
              onVerifyChain={verifyAuditChain}
            />
          )}
        </main>
      </div>

      {/* Step-Up Re-Authentication Modal */}
      <StepUpModal
        isOpen={stepUpModal.show}
        reason={stepUpModal.reason}
        onConfirm={handleStepUpSubmit}
        onCancel={() => setStepUpModal({ show: false, reason: '', pendingAction: null })}
      />

      {/* File Sharing Modal */}
      {activeShareModalFile && (
        <FileShareModal
          isOpen={Boolean(activeShareModalFile)}
          file={activeShareModalFile}
          fileShares={fileShares[activeShareModalFile.id] || []}
          onShare={handleShareFile}
          onRevoke={handleRevokeShare}
          onClose={() => setActiveShareModalFile(null)}
          token={token}
          userPermissionsCache={userPermissionsCache}
          onFetchPermissions={fetchUserPermissionsCache}
        />
      )}

      {/* Edit User Roles Modal */}
      {editingUserModalTarget && (
        <EditUserRolesModal
          isOpen={Boolean(editingUserModalTarget)}
          targetUser={editingUserModalTarget}
          orgRoles={orgRoles}
          onSave={handleUpdateUserRoles}
          onClose={() => setEditingUserModalTarget(null)}
        />
      )}

      {/* Create Role Modal */}
      <CreateRoleModal
        isOpen={showCreateRoleModal}
        allPermissions={allPermissions}
        onCreateRole={handleCreateRole}
        onClose={() => setShowCreateRoleModal(false)}
      />

      {/* Account Setup Token Modal */}
      <Modal
        isOpen={showSetupTokenModal}
        title="Enter Account Setup Token"
        onClose={() => {
          setShowSetupTokenModal(false);
          setSetupTokenInput('');
        }}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (setupTokenInput && setupTokenInput.trim()) {
              setActiveSetupToken(setupTokenInput.trim());
              setShowSetupTokenModal(false);
              setSetupTokenInput('');
            }
          }}
          style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
        >
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', margin: 0 }}>
            Please enter your Account Setup Token provided by your organization administrator.
          </p>
          <div className="form-group">
            <label className="form-label">Setup Token *</label>
            <input
              type="text"
              className="form-input"
              placeholder="Paste your setup token here..."
              value={setupTokenInput}
              onChange={(e) => setSetupTokenInput(e.target.value)}
              required
              autoFocus
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setShowSetupTokenModal(false);
                setSetupTokenInput('');
              }}
            >
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={!setupTokenInput.trim()}>
              Continue Setup
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

const styles = {
  appContainer: {
    display: 'flex',
    height: '100vh',
    width: '100vw',
    backgroundColor: 'var(--bg-dark-root)',
    overflow: 'hidden',
  },
  mainContent: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  viewBody: {
    flex: 1,
    overflowY: 'auto',
    padding: '2rem',
  },
  authWrapper: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'var(--bg-dark-root)',
    padding: '2rem 1rem',
  },
};
