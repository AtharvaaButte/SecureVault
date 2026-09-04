import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  // Session & User Context
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  const [userPermissions, setUserPermissions] = useState([]);
  const [userAssignedRoles, setUserAssignedRoles] = useState([]);

  // Navigation Tab State: 'files' | 'users' | 'roles' | 'policies' | 'audit'
  const [navTab, setNavTab] = useState('files');

  // Crypto Identity state
  const [cryptoIdentity, setCryptoIdentity] = useState({
    protected: false,
    registered: false,
    publicKey: null,
  });

  // Local File Encryption & Upload state
  const [selectedFile, setSelectedFile] = useState(null);
  const [encryptResult, setEncryptResult] = useState(null);
  const [uploadClassification, setUploadClassification] = useState('INTERNAL');
  const [fileList, setFileList] = useState([]);
  const [downloadStatus, setDownloadStatus] = useState({});

  // Shared Files & Sharing Controls state
  const [sharedFileList, setSharedFileList] = useState([]);
  const [orgMembers, setOrgMembers] = useState([]);
  const [shareRecipients, setShareRecipients] = useState({});
  const [shareAccessLevels, setShareAccessLevels] = useState({});
  const [shareStatus, setShareStatus] = useState({});
  const [sharedDownloadStatus, setSharedDownloadStatus] = useState({});
  const [fileShares, setFileShares] = useState({});
  const [userPermissionsCache, setUserPermissionsCache] = useState({}); // userId -> { roles, permissions }

  // User Management state
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRoleIds, setNewUserRoleIds] = useState([]);
  const [editingUser, setEditingUser] = useState(null); // { id, email, roles }
  const [editUserRoleIds, setEditUserRoleIds] = useState([]);

  // Role Management state
  const [orgRoles, setOrgRoles] = useState([]);
  const [allPermissions, setAllPermissions] = useState([]);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [newRolePerms, setNewRolePerms] = useState([]);
  const [editingRole, setEditingRole] = useState(null); // { id, name, description, permissions }
  const [editRolePerms, setEditRolePerms] = useState([]);
  const [permissionAuditRecords, setPermissionAuditRecords] = useState([]);

  // Security Policies & Multi-Geo Locations state
  const [orgPolicy, setOrgPolicy] = useState(null);
  const [newGeoCountry, setNewGeoCountry] = useState('IN');
  const [newGeoState, setNewGeoState] = useState('ALL');
  const [newGeoCity, setNewGeoCity] = useState('ALL');

  // Security Event Audit Logs & Hash Chain state
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditVerification, setAuditVerification] = useState(null);

  // Security Context & Step-Up Modal state
  const [showSecurityPanel, setShowSecurityPanel] = useState(false);
  const [stepUpModal, setStepUpModal] = useState({ show: false, reason: '', pendingAction: null });
  const [stepUpPassword, setStepUpPassword] = useState('');

  // UI Flow & Notification states
  const [authTab, setAuthTab] = useState('login'); // 'login' | 'register'
  const [loading, setLoading] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Auth Form states
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [regOrgName, setRegOrgName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');

  // Helper for JSON API calls & status checks
  const parseJsonResponse = async (res, fallbackMessage = 'Request failed') => {
    const contentType = res.headers.get('content-type');
    const isJson = contentType && contentType.includes('application/json');
    const data = isJson ? await res.json() : {};
    if (!res.ok) {
      const errObj = new Error(data.message || `${fallbackMessage} (${res.status} ${res.statusText})`);
      errObj.status = res.status;
      errObj.stepUpRequired = Boolean(data.stepUpRequired);
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

  const handleStepUpSubmit = async (e) => {
    e.preventDefault();
    if (!stepUpPassword) return;
    const action = stepUpModal.pendingAction;
    const pwd = stepUpPassword;
    setStepUpPassword('');
    setStepUpModal({ show: false, reason: '', pendingAction: null });
    if (action) {
      await action(pwd);
    }
  };

  // Data Fetchers
  const fetchUserFiles = async (authToken = token) => {
    let files = [];
    if (window.electronAPI && typeof window.electronAPI.getUserFiles === 'function') {
      try {
        const res = await window.electronAPI.getUserFiles(authToken);
        if (res.success) {
          files = res.files || [];
        } else if (res.error) {
          setError(`[Files Error]: ${res.error}`);
        }
      } catch (err) {
        console.error('[Fetch User Files IPC Error]:', err.message);
      }
    } else {
      try {
        const res = await fetch(`${API_BASE}/files`, {
          headers: { 'Authorization': `Bearer ${authToken}` },
        });
        const data = await parseJsonResponse(res, 'Failed to fetch user files');
        files = data.files || [];
      } catch (err) {
        console.error('[Fetch Files Error]:', err.message);
      }
    }

    setFileList(files);
    if (files.length > 0) {
      for (const f of files) {
        fetchFileShares(f.id, authToken);
      }
    }
  };

  const fetchFileShares = async (fileId, authToken = token) => {
    if (!window.electronAPI || typeof window.electronAPI.getFileShares !== 'function' || !authToken) return;
    try {
      const res = await window.electronAPI.getFileShares(fileId, authToken);
      if (res.success) {
        setFileShares((prev) => ({ ...prev, [fileId]: res.shares || [] }));
      }
    } catch (err) {
      console.error('[Fetch File Shares Error]:', err.message);
    }
  };

  const fetchOrgMembers = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/users/members`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrgMembers(data.users || []);
        const me = data.users.find((u) => u.id === currentUser?.id);
        if (me) {
          setUserPermissions(me.permissions || []);
          setUserAssignedRoles(me.roles || []);
        }
      }
    } catch (err) {
      console.error('[Fetch Org Members Error]:', err.message);
    }
  };

  const fetchUserPermissions = async (userId, authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/users/${userId}/permissions`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setUserPermissionsCache((prev) => ({
          ...prev,
          [userId]: { roles: data.roles || [], permissions: data.permissions || [] },
        }));
        return data;
      }
    } catch (err) {
      console.error('[Fetch User Permissions Error]:', err.message);
    }
    return null;
  };

  const fetchOrgRoles = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/roles`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrgRoles(data.roles || []);
      }
    } catch (err) {
      console.error('[Fetch Org Roles Error]:', err.message);
    }
  };

  const fetchAllPermissions = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/roles/permissions`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAllPermissions(data.permissions || []);
      }
    } catch (err) {
      console.error('[Fetch All Permissions Error]:', err.message);
    }
  };

  const fetchPermissionAuditView = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/roles/audit`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setPermissionAuditRecords(data.auditRecords || []);
      }
    } catch (err) {
      console.error('[Fetch Permission Audit Error]:', err.message);
    }
  };

  const fetchOrgPolicy = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/policies`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrgPolicy(data.policy);
      }
    } catch (err) {
      console.error('[Fetch Org Policy Error]:', err.message);
    }
  };

  const fetchAuditLogs = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/audit`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.logs || []);
      }
    } catch (err) {
      console.error('[Fetch Audit Logs Error]:', err.message);
    }
  };

  const fetchSharedFiles = async (authToken = token) => {
    if (!window.electronAPI || typeof window.electronAPI.getSharedFiles !== 'function') return;
    try {
      const res = await window.electronAPI.getSharedFiles(authToken);
      if (res.success) {
        setSharedFileList(res.sharedFiles || []);
      }
    } catch (err) {
      console.error('[Fetch Shared Files Error]:', err.message);
    }
  };

  const syncCryptographicIdentity = async (authToken) => {
    if (!window.electronAPI || typeof window.electronAPI.ensureIdentity !== 'function') return;
    try {
      const localId = await window.electronAPI.ensureIdentity();
      if (localId && localId.hasIdentity) {
        const res = await fetch(`${API_BASE}/crypto/public-key`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`,
          },
          body: JSON.stringify({ publicKey: localId.publicKey }),
        });

        if (res.ok) {
          setCryptoIdentity({
            protected: true,
            registered: true,
            publicKey: localId.publicKey,
          });
        }
      }
    } catch (err) {
      console.error('[Crypto Identity Sync Error]:', err.message);
    }
  };

  // Restore Session on Mount
  useEffect(() => {
    async function restoreSession() {
      setInitializing(true);
      try {
        if (window.electronAPI && typeof window.electronAPI.getSession === 'function') {
          const storedToken = await window.electronAPI.getSession();
          if (storedToken) {
            const res = await fetch(`${API_BASE}/auth/me`, {
              headers: { 'Authorization': `Bearer ${storedToken}` },
            });
            if (res.ok) {
              const data = await res.json();
              setToken(storedToken);
              setCurrentUser(data.user);
              setCurrentOrg(data.organization);
              setUserPermissions(data.user.permissions || []);
              setUserAssignedRoles(data.user.roles || []);

              await syncCryptographicIdentity(storedToken);
              await fetchUserFiles(storedToken);
              await fetchOrgMembers(storedToken);
              await fetchSharedFiles(storedToken);
              await fetchOrgRoles(storedToken);
              await fetchAllPermissions(storedToken);
              await fetchOrgPolicy(storedToken);
              await fetchAuditLogs(storedToken);
            } else {
              await window.electronAPI.clearSession();
            }
          }
        }
      } catch (err) {
        console.error('[Session Restore Error]:', err.message);
      } finally {
        setInitializing(false);
      }
    }
    restoreSession();
  }, []);

  // Handlers for Auth
  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orgName: regOrgName, email: regEmail, password: regPassword }),
      });

      const data = await parseJsonResponse(res, 'Registration failed');

      setToken(data.token);
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);
      setUserPermissions(data.user.permissions || []);
      setUserAssignedRoles(data.user.roles || []);

      if (window.electronAPI && typeof window.electronAPI.saveSession === 'function') {
        await window.electronAPI.saveSession(data.token);
      }

      await syncCryptographicIdentity(data.token);
      await fetchUserFiles(data.token);
      await fetchOrgMembers(data.token);
      await fetchSharedFiles(data.token);
      await fetchOrgRoles(data.token);
      await fetchAllPermissions(data.token);
      await fetchOrgPolicy(data.token);
      await fetchAuditLogs(data.token);
      setSuccessMsg('Account registered and cryptographic identity set up successfully!');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });

      const data = await parseJsonResponse(res, 'Login failed');

      setToken(data.token);
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);
      setUserPermissions(data.user.permissions || []);
      setUserAssignedRoles(data.user.roles || []);

      if (window.electronAPI && typeof window.electronAPI.saveSession === 'function') {
        await window.electronAPI.saveSession(data.token);
      }

      await syncCryptographicIdentity(data.token);
      await fetchUserFiles(data.token);
      await fetchOrgMembers(data.token);
      await fetchSharedFiles(data.token);
      await fetchOrgRoles(data.token);
      await fetchAllPermissions(data.token);
      await fetchOrgPolicy(data.token);
      await fetchAuditLogs(data.token);
      setSuccessMsg('Logged in successfully!');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    if (window.electronAPI && typeof window.electronAPI.clearSession === 'function') {
      await window.electronAPI.clearSession();
    }
    setToken(null);
    setCurrentUser(null);
    setCurrentOrg(null);
    setFileList([]);
    setSharedFileList([]);
    setOrgPolicy(null);
    setAuditLogs([]);
    setSuccessMsg('Logged out successfully.');
  };

  // User Management Actions (Requirement 1 & 2)
  const handleCreateUser = async (e, reauthPwd = null) => {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      };
      if (reauthPwd) headers['X-Reauth-Password'] = reauthPwd;

      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          email: newUserEmail,
          password: newUserPassword,
          roleIds: newUserRoleIds,
        }),
      });

      const data = await parseJsonResponse(res, 'Failed to create user account');

      setNewUserEmail('');
      setNewUserPassword('');
      setNewUserRoleIds([]);
      setSuccessMsg(`User account ${data.user.email} created with ${data.user.roles.length} assigned role(s).`);
      await fetchOrgMembers(token);
      await fetchAuditLogs(token);
    } catch (err) {
      if (err.stepUpRequired) {
        promptStepUp(err.message, (pwd) => handleCreateUser(null, pwd));
      } else {
        setError(`[User Creation Error]: ${err.message}`);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateUserRoles = async (userId, targetRoleIds) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/users/${userId}/roles`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ roleIds: targetRoleIds }),
      });

      const data = await parseJsonResponse(res, 'Failed to update user roles');
      setSuccessMsg('User roles updated successfully.');
      setEditingUser(null);
      await fetchOrgMembers(token);
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Update User Roles Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Role Management Actions (Requirement 3)
  const handleCreateCustomRole = async (e) => {
    e.preventDefault();
    if (!newRoleName) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/roles`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: newRoleName,
          description: newRoleDesc,
          permissions: newRolePerms,
        }),
      });

      const data = await parseJsonResponse(res, 'Failed to create custom role');
      setNewRoleName('');
      setNewRoleDesc('');
      setNewRolePerms([]);
      setSuccessMsg(`Custom role "${data.role.name}" created successfully.`);
      await fetchOrgRoles(token);
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Create Role Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateRolePermissions = async (roleId, permissions) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/roles/${roleId}/permissions`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ permissions }),
      });

      const data = await parseJsonResponse(res, 'Failed to update role permissions');
      setSuccessMsg('Role permissions updated successfully.');
      setEditingRole(null);
      await fetchOrgRoles(token);
      await fetchOrgMembers(token);
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Update Role Permissions Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCustomRole = async (roleId, roleName) => {
    if (!window.confirm(`Are you sure you want to delete role "${roleName}"?`)) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/roles/${roleId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      const data = await parseJsonResponse(res, 'Failed to delete role');
      setSuccessMsg(`Role "${roleName}" deleted.`);
      await fetchOrgRoles(token);
      await fetchOrgMembers(token);
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Delete Role Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Policy Management Actions (Requirements 4 & 5)
  const handleUpdatePolicySettings = async (newPolicyFields) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/policies`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newPolicyFields),
      });

      const data = await parseJsonResponse(res, 'Failed to update organization security policy');
      setOrgPolicy(data.policy);
      setSuccessMsg('Organization security policy updated successfully.');
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Policy Update Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAddGeoLocation = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/policies/locations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          allowedCountry: newGeoCountry,
          allowedState: newGeoState,
          allowedCity: newGeoCity,
        }),
      });

      const data = await parseJsonResponse(res, 'Failed to add geographic location policy');
      setOrgPolicy(data.policy);
      setSuccessMsg('Allowed geographic location policy added.');
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Geo Policy Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveGeoLocation = async (locId) => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/policies/locations/${locId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      const data = await parseJsonResponse(res, 'Failed to remove geographic location policy');
      setOrgPolicy(data.policy);
      setSuccessMsg('Geographic location policy removed.');
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Geo Policy Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Local Encryption & Cloud Upload (Requirement 9)
  const handleSelectFile = async () => {
    if (!window.electronAPI || typeof window.electronAPI.selectFile !== 'function') return;
    setError(null);
    try {
      const res = await window.electronAPI.selectFile();
      if (!res.canceled) {
        setSelectedFile(res);
        setEncryptResult(null);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEncryptFile = async () => {
    if (!selectedFile) return;
    setLoading(true);
    setError(null);

    try {
      const res = await window.electronAPI.encryptFile(selectedFile.filePath);
      if (res.success) {
        setEncryptResult(res);
        setSuccessMsg('File encrypted locally with AES-256-GCM.');
      } else {
        setError(res.error);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCloudUpload = async (reauthPwd = null) => {
    if (!selectedFile || !encryptResult) return;
    setLoading(true);
    setError(null);

    try {
      const res = await window.electronAPI.uploadCiphertext({
        fileId: encryptResult.fileId,
        dataClassification: uploadClassification,
        sensitivityLevel: uploadClassification,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setSuccessMsg(`File uploaded successfully! Classification: ${uploadClassification}`);
        setSelectedFile(null);
        setEncryptResult(null);
        await fetchUserFiles(token);
        await fetchAuditLogs(token);
      } else {
        if (res.stepUpRequired) {
          promptStepUp(res.error, (pwd) => handleCloudUpload(pwd));
        } else {
          setError(`[Upload Error]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Downloading Files & Handling Step-Up (Requirement 10 & 11)
  const handleDownloadFile = async (fileId, dataClassification, reauthPwd = null) => {
    setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null } }));
    setError(null);

    try {
      const res = await window.electronAPI.downloadDecryptFile({
        fileId,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setDownloadStatus((prev) => ({
          ...prev,
          [fileId]: { loading: false, success: true, savedPath: res.savedPath },
        }));
        setSuccessMsg(`Downloaded and decrypted file to: ${res.savedPath}`);
        await fetchAuditLogs(token);
      } else {
        setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: res.error } }));
        if (res.stepUpRequired) {
          promptStepUp(res.error, (pwd) => handleDownloadFile(fileId, dataClassification, pwd));
        } else {
          setError(`[Access Denied]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
      setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: err.message } }));
    }
  };

  // File Sharing Flow (Requirements 6, 7 & 8)
  const handleRecipientSelected = async (fileId, recipientUserId) => {
    if (!recipientUserId) {
      setShareRecipients((prev) => ({ ...prev, [fileId]: null }));
      return;
    }
    const targetUser = orgMembers.find((u) => u.id === recipientUserId);
    if (targetUser) {
      setShareRecipients((prev) => ({ ...prev, [fileId]: targetUser }));
      await fetchUserPermissions(recipientUserId);
    }
  };

  const handleShareFile = async (fileId, reauthPwd = null) => {
    const recipient = shareRecipients[fileId];
    if (!recipient || !recipient.id || !recipient.publicKeyRegistered) {
      setError('Please select a valid recipient from your organization with a registered public key.');
      return;
    }

    const accessLevel = shareAccessLevels[fileId] || 'READ';

    setShareStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null } }));
    setError(null);

    try {
      const res = await window.electronAPI.shareFile({
        fileId,
        recipientUserId: recipient.id,
        recipientPublicKey: recipient.publicKeyRegistered ? recipient.publicKey : null,
        accessLevel,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setShareStatus((prev) => ({
          ...prev,
          [fileId]: { loading: false, success: true, message: res.message },
        }));
        setSuccessMsg(`File shared successfully with ${recipient.email} (${accessLevel} access level)!`);
        await fetchFileShares(fileId, token);
        await fetchAuditLogs(token);
      } else {
        setShareStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: res.error } }));
        if (res.stepUpRequired) {
          promptStepUp(res.error, (pwd) => handleShareFile(fileId, pwd));
        } else {
          setError(`[Share Error]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
      setShareStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: err.message } }));
    }
  };

  const handleRevokeShare = async (fileId, recipientUserId, reauthPwd = null) => {
    setError(null);
    try {
      const res = await window.electronAPI.revokeFileShare({
        fileId,
        recipientUserId,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setSuccessMsg('Share permission revoked successfully.');
        await fetchFileShares(fileId, token);
        await fetchAuditLogs(token);
      } else {
        if (res.stepUpRequired) {
          promptStepUp(res.error, (pwd) => handleRevokeShare(fileId, recipientUserId, pwd));
        } else {
          setError(`[Revoke Error]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDownloadSharedFile = async (fileId, dataClassification, reauthPwd = null) => {
    setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null } }));
    setError(null);

    try {
      const res = await window.electronAPI.downloadDecryptSharedFile({
        fileId,
        currentUserId: currentUser.id,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setSharedDownloadStatus((prev) => ({
          ...prev,
          [fileId]: { loading: false, success: true, savedPath: res.savedPath },
        }));
        setSuccessMsg(`Downloaded and decrypted shared file to: ${res.savedPath}`);
        await fetchAuditLogs(token);
      } else {
        setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: res.error } }));
        if (res.stepUpRequired) {
          promptStepUp(res.error, (pwd) => handleDownloadSharedFile(fileId, dataClassification, pwd));
        } else {
          setError(`[Shared Download Access Denied]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
      setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: err.message } }));
    }
  };

  // Audit Verification (Requirement 12)
  const handleVerifyAuditChain = async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/audit/verify`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await parseJsonResponse(res, 'Audit chain verification failed');
      setAuditVerification(data);
      if (data.valid) {
        setSuccessMsg(`Audit Chain Verified! All ${data.totalLogs} SHA-256 log hashes intact.`);
      } else {
        setError(`[TAMPER DETECTED]: ${data.error}`);
      }
    } catch (err) {
      setError(`[Verification Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Initial Loading Screen
  if (initializing) {
    return (
      <div style={{ display: 'flex', height: '100vh', justifyContent: 'center', alignItems: 'center', backgroundColor: '#0f172a', color: '#f8fafc', fontFamily: 'sans-serif' }}>
        <div>Initializing SecureVault session & identity...</div>
      </div>
    );
  }

  // Unauthenticated Login / Register Screen
  if (!token) {
    return (
      <div style={{ maxWidth: '420px', margin: '60px auto', padding: '30px', backgroundColor: '#1e293b', borderRadius: '12px', color: '#f8fafc', fontFamily: 'sans-serif', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}>
        <h2 style={{ textAlign: 'center', marginTop: 0, color: '#38bdf8' }}>🔒 SecureVault</h2>
        <p style={{ textAlign: 'center', fontSize: '13px', color: '#94a3b8', marginBottom: '24px' }}>Zero Trust E2EE Cloud Storage Solution</p>

        <div style={{ display: 'flex', borderBottom: '1px solid #334155', marginBottom: '20px' }}>
          <button onClick={() => { setAuthTab('login'); setError(null); }} style={{ flex: 1, padding: '10px', background: 'none', border: 'none', borderBottom: authTab === 'login' ? '2px solid #38bdf8' : 'none', color: authTab === 'login' ? '#38bdf8' : '#94a3b8', fontWeight: 'bold', cursor: 'pointer' }}>Login</button>
          <button onClick={() => { setAuthTab('register'); setError(null); }} style={{ flex: 1, padding: '10px', background: 'none', border: 'none', borderBottom: authTab === 'register' ? '2px solid #38bdf8' : 'none', color: authTab === 'register' ? '#38bdf8' : '#94a3b8', fontWeight: 'bold', cursor: 'pointer' }}>Register Organization</button>
        </div>

        {error && <div style={{ padding: '10px', backgroundColor: '#7f1d1d', color: '#fca5a5', borderRadius: '6px', fontSize: '13px', marginBottom: '16px' }}>{error}</div>}

        {authTab === 'login' ? (
          <form onSubmit={handleLogin}>
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Email Address</label>
              <input type="email" value={loginEmail} onChange={(e) => setLoginEmail(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Password</label>
              <input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <button type="submit" disabled={loading} style={{ width: '100%', padding: '12px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>{loading ? 'Authenticating...' : 'Sign In'}</button>
          </form>
        ) : (
          <form onSubmit={handleRegister}>
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Organization Name</label>
              <input type="text" value={regOrgName} onChange={(e) => setRegOrgName(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Owner Email Address</label>
              <input type="email" value={regEmail} onChange={(e) => setRegEmail(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Owner Password</label>
              <input type="password" value={regPassword} onChange={(e) => setRegPassword(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <button type="submit" disabled={loading} style={{ width: '100%', padding: '12px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>{loading ? 'Creating Organization...' : 'Register & Setup Identity'}</button>
          </form>
        )}
      </div>
    );
  }

  // Main Authenticated Dashboard
  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#f8fafc', fontFamily: 'sans-serif', padding: '24px' }}>

      {/* STEP-UP RE-AUTHENTICATION MODAL */}
      {stepUpModal.show && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9999 }}>
          <div style={{ backgroundColor: '#1e293b', border: '2px solid #eab308', borderRadius: '12px', padding: '28px', maxWidth: '440px', width: '100%', color: '#fff', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)' }}>
            <h3 style={{ marginTop: 0, color: '#eab308', display: 'flex', alignItems: 'center', gap: '8px' }}>
              ⚠️ Additional Authentication Required
            </h3>
            <p style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: '1.5', marginBottom: '18px' }}>
              {stepUpModal.reason}
            </p>
            <form onSubmit={handleStepUpSubmit}>
              <div style={{ marginBottom: '18px' }}>
                <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#94a3b8' }}>Confirm Account Password</label>
                <input
                  type="password"
                  value={stepUpPassword}
                  onChange={(e) => setStepUpPassword(e.target.value)}
                  placeholder="Enter your account password..."
                  required
                  autoFocus
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #475569', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }}
                />
              </div>
              <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => setStepUpModal({ show: false, reason: '', pendingAction: null })}
                  style={{ padding: '8px 16px', backgroundColor: '#334155', color: '#cbd5e1', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ padding: '8px 18px', backgroundColor: '#eab308', color: '#0f172a', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
                >
                  Verify & Proceed
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* EDIT USER ROLES MODAL */}
      {editingUser && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9991 }}>
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #38bdf8', borderRadius: '12px', padding: '24px', maxWidth: '480px', width: '100%', color: '#fff' }}>
            <h3 style={{ marginTop: 0, color: '#38bdf8' }}>Manage Roles for {editingUser.email}</h3>
            <p style={{ fontSize: '12px', color: '#94a3b8' }}>Select organization roles to assign to this user:</p>
            <div style={{ maxHeight: '200px', overflowY: 'auto', marginBottom: '16px', backgroundColor: '#0f172a', padding: '10px', borderRadius: '6px' }}>
              {orgRoles.map((r) => (
                <label key={r.id} style={{ display: 'block', padding: '6px 0', fontSize: '13px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={editUserRoleIds.includes(r.id)}
                    onChange={(e) => {
                      if (e.target.checked) setEditUserRoleIds((prev) => [...prev, r.id]);
                      else setEditUserRoleIds((prev) => prev.filter((id) => id !== r.id));
                    }}
                    style={{ marginRight: '8px' }}
                  />
                  <strong>{r.name}</strong> ({r.description || 'Custom role'})
                </label>
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button onClick={() => setEditingUser(null)} style={{ padding: '8px 14px', backgroundColor: '#334155', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Cancel</button>
              <button onClick={() => handleUpdateUserRoles(editingUser.id, editUserRoleIds)} style={{ padding: '8px 16px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>Save Roles</button>
            </div>
          </div>
        </div>
      )}

      {/* EDIT ROLE PERMISSIONS MODAL */}
      {editingRole && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9991 }}>
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #38bdf8', borderRadius: '12px', padding: '24px', maxWidth: '520px', width: '100%', color: '#fff' }}>
            <h3 style={{ marginTop: 0, color: '#38bdf8' }}>Edit Role Permissions: {editingRole.name}</h3>
            <div style={{ maxHeight: '260px', overflowY: 'auto', marginBottom: '16px', backgroundColor: '#0f172a', padding: '10px', borderRadius: '6px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              {allPermissions.map((p) => {
                const permName = typeof p === 'string' ? p : p.name;
                const permId = typeof p === 'string' ? p : (p.id || p.name);
                return (
                  <label key={permId} style={{ fontSize: '12px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={editRolePerms.includes(permName)}
                      onChange={(e) => {
                        if (e.target.checked) setEditRolePerms((prev) => [...prev, permName]);
                        else setEditRolePerms((prev) => prev.filter((item) => item !== permName));
                      }}
                      style={{ marginRight: '6px' }}
                    />
                    {permName}
                  </label>
                );
              })}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button onClick={() => setEditingRole(null)} style={{ padding: '8px 14px', backgroundColor: '#334155', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Cancel</button>
              <button onClick={() => handleUpdateRolePermissions(editingRole.id, editRolePerms)} style={{ padding: '8px 16px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>Save Permissions</button>
            </div>
          </div>
        </div>
      )}

      {/* ZERO TRUST SECURITY CONTEXT MODAL */}
      {showSecurityPanel && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9990 }}>
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #38bdf8', borderRadius: '12px', padding: '28px', maxWidth: '640px', width: '100%', color: '#fff', maxHeight: '85vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #334155', paddingBottom: '12px', marginBottom: '18px' }}>
              <h3 style={{ margin: 0, color: '#38bdf8' }}>🛡️ Zero Trust Security Context</h3>
              <button onClick={() => setShowSecurityPanel(false)} style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '18px', cursor: 'pointer' }}>✕</button>
            </div>
            
            <div style={{ fontSize: '13px', lineHeight: '1.6' }}>
              <div style={{ marginBottom: '10px' }}><strong>Authenticated Identity:</strong> {currentUser?.email} ({currentUser?.id})</div>
              <div style={{ marginBottom: '10px' }}><strong>Organization:</strong> {currentOrg?.name} ({currentOrg?.id})</div>
              
              <div style={{ marginBottom: '10px' }}>
                <strong>Assigned Roles:</strong>{' '}
                {userAssignedRoles.map((r) => {
                  const roleId = typeof r === 'string' ? r : r.id;
                  const roleName = typeof r === 'string' ? r : r.name;
                  return (
                    <span key={roleId || roleName} style={{ padding: '2px 8px', borderRadius: '4px', backgroundColor: '#0369a1', color: '#fff', fontWeight: 'bold', marginRight: '4px', fontSize: '11px' }}>
                      {roleName}
                    </span>
                  );
                })}
              </div>
              
              <div style={{ marginBottom: '14px' }}>
                <strong>Effective Dynamic RBAC Permissions:</strong>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                  {userPermissions.map((p) => {
                    const permName = typeof p === 'string' ? p : p.name;
                    const permId = typeof p === 'string' ? p : (p.id || p.name);
                    return (
                      <span key={permId} style={{ padding: '3px 8px', borderRadius: '4px', backgroundColor: String(permName).startsWith('FILE_') ? '#0284c7' : '#7c3aed', color: '#fff', fontSize: '11px' }}>{permName}</span>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TOP HEADER & SYSTEM STATUS */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#1e293b', padding: '16px 24px', borderRadius: '10px', marginBottom: '20px', border: '1px solid #334155' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#38bdf8' }}>🔒 SecureVault</h2>
          <div style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '4px' }}>
            Org: <strong>{currentOrg?.name}</strong> | User: <strong>{currentUser?.email}</strong> | Roles: {userAssignedRoles.map((r) => typeof r === 'string' ? r : r.name).join(', ') || 'No Role Assigned'}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <button
            onClick={() => setShowSecurityPanel(true)}
            style={{ padding: '8px 14px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
          >
            🛡️ Zero Trust Security Context
          </button>
          <button
            onClick={handleLogout}
            style={{ padding: '8px 14px', backgroundColor: '#475569', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', cursor: 'pointer' }}
          >
            Logout
          </button>
        </div>
      </header>

      {/* NAVIGATION TABS BAR */}
      <nav style={{ display: 'flex', gap: '8px', borderBottom: '1px solid #334155', paddingBottom: '12px', marginBottom: '20px' }}>
        <button
          onClick={() => { setNavTab('files'); setError(null); setSuccessMsg(null); }}
          style={{ padding: '10px 18px', borderRadius: '6px', border: 'none', backgroundColor: navTab === 'files' ? '#0284c7' : '#1e293b', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px' }}
        >
          📂 Files & Encryption
        </button>

        {(userPermissions.includes('USER_CREATE') || userPermissions.includes('USER_MANAGE')) && (
          <button
            onClick={() => { setNavTab('users'); setError(null); setSuccessMsg(null); fetchOrgMembers(token); }}
            style={{ padding: '10px 18px', borderRadius: '6px', border: 'none', backgroundColor: navTab === 'users' ? '#0284c7' : '#1e293b', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px' }}
          >
            👥 User Management
          </button>
        )}

        {userPermissions.includes('ROLE_MANAGE') && (
          <button
            onClick={() => { setNavTab('roles'); setError(null); setSuccessMsg(null); fetchOrgRoles(token); fetchAllPermissions(token); fetchPermissionAuditView(token); }}
            style={{ padding: '10px 18px', borderRadius: '6px', border: 'none', backgroundColor: navTab === 'roles' ? '#0284c7' : '#1e293b', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px' }}
          >
            ⚙️ Custom Role Management
          </button>
        )}

        {userPermissions.includes('ORG_MANAGE') && (
          <button
            onClick={() => { setNavTab('policies'); setError(null); setSuccessMsg(null); fetchOrgPolicy(token); }}
            style={{ padding: '10px 18px', borderRadius: '6px', border: 'none', backgroundColor: navTab === 'policies' ? '#0284c7' : '#1e293b', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px' }}
          >
            🛡️ Security Policies
          </button>
        )}

        {(userPermissions.includes('ORG_MANAGE') || userPermissions.includes('USER_MANAGE')) && (
          <button
            onClick={() => { setNavTab('audit'); setError(null); setSuccessMsg(null); fetchAuditLogs(token); }}
            style={{ padding: '10px 18px', borderRadius: '6px', border: 'none', backgroundColor: navTab === 'audit' ? '#0284c7' : '#1e293b', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px' }}
          >
            📜 Security Audit Logs
          </button>
        )}
      </nav>

      {/* NOTIFICATION BANNERS */}
      {error && <div style={{ padding: '12px 16px', backgroundColor: '#7f1d1d', color: '#fca5a5', borderRadius: '8px', fontSize: '13px', marginBottom: '20px', border: '1px solid #991b1b' }}>{error}</div>}
      {successMsg && <div style={{ padding: '12px 16px', backgroundColor: '#064e3b', color: '#6ee7b7', borderRadius: '8px', fontSize: '13px', marginBottom: '20px', border: '1px solid #047857' }}>{successMsg}</div>}

      {/* TAB 1: FILES & ENCRYPTION */}
      {navTab === 'files' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
          
          {/* LEFT COLUMN: Local Encryption & Upload */}
          <div>
            {userPermissions.includes('FILE_UPLOAD') ? (
              <>
                <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
                  <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>1. Local File Encryption (AES-256-GCM)</h3>
                  <button onClick={handleSelectFile} style={{ padding: '10px 16px', backgroundColor: '#334155', color: '#fff', border: '1px solid #475569', borderRadius: '6px', fontSize: '13px', cursor: 'pointer', marginBottom: '12px' }}>
                    📁 Select Local File
                  </button>

                  {selectedFile && (
                    <div style={{ fontSize: '12px', backgroundColor: '#0f172a', padding: '10px', borderRadius: '6px', marginBottom: '12px' }}>
                      <div>Selected: <strong>{selectedFile.fileName}</strong> ({selectedFile.fileSize} bytes)</div>
                    </div>
                  )}

                  {selectedFile && !encryptResult && (
                    <button onClick={handleEncryptFile} disabled={loading} style={{ padding: '10px 16px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 'bold', cursor: 'pointer' }}>
                      {loading ? 'Encrypting...' : '🔒 Encrypt File Locally'}
                    </button>
                  )}

                  {encryptResult && (
                    <div style={{ marginTop: '12px', fontSize: '12px', backgroundColor: '#0f172a', padding: '12px', borderRadius: '6px', border: '1px solid #0284c7' }}>
                      <div style={{ color: '#38bdf8', fontWeight: 'bold', marginBottom: '4px' }}>✓ File Encrypted Locally!</div>
                      <div>ID: {encryptResult.fileId}</div>
                    </div>
                  )}
                </div>

                {encryptResult && (
                  <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
                    <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>2. Cloud Upload & Data Classification</h3>
                    <div style={{ marginBottom: '16px' }}>
                      <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Data Classification</label>
                      <select value={uploadClassification} onChange={(e) => setUploadClassification(e.target.value)} style={{ width: '100%', padding: '10px', borderRadius: '6px', backgroundColor: '#0f172a', color: '#fff', border: '1px solid #475569' }}>
                        <option value="PUBLIC">⚪ PUBLIC (Unclassified)</option>
                        <option value="INTERNAL">🟢 INTERNAL (Standard Security)</option>
                        <option value="CONFIDENTIAL">🟡 CONFIDENTIAL (Step-Up on Share/Revoke)</option>
                        <option value="HIGHLY_CONFIDENTIAL">🔴 HIGHLY_CONFIDENTIAL (Step-Up on Download & Share)</option>
                      </select>
                    </div>
                    <button onClick={() => handleCloudUpload()} disabled={loading} style={{ padding: '10px 18px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 'bold', cursor: 'pointer' }}>
                      {loading ? 'Uploading...' : '☁️ Upload Ciphertext to B2'}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div style={{ padding: '20px', backgroundColor: '#1e293b', borderRadius: '10px', border: '1px solid #334155', fontSize: '13px', color: '#94a3b8' }}>
                ℹ️ Your role does not have <code>FILE_UPLOAD</code> permission. Contact your organization administrator to upload files.
              </div>
            )}
          </div>

          {/* RIGHT COLUMN: My Files & Shared Files */}
          <div>
            {/* My Files Listing & Sharing Flow */}
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
              <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>📂 My Uploaded Files</h3>

              {fileList.length === 0 ? (
                <p style={{ fontSize: '12px', color: '#94a3b8' }}>No uploaded files found.</p>
              ) : (
                fileList.map((f) => {
                  const recipient = shareRecipients[f.id];
                  const recipientInfo = recipient ? userPermissionsCache[recipient.id] : null;

                  return (
                    <div key={f.id} style={{ backgroundColor: '#0f172a', padding: '14px', borderRadius: '8px', marginBottom: '14px', border: '1px solid #334155' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                        <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{f.originalName}</strong>
                        <span style={{ fontSize: '10px', padding: '3px 8px', borderRadius: '4px', backgroundColor: f.dataClassification === 'HIGHLY_CONFIDENTIAL' ? '#ef4444' : f.dataClassification === 'CONFIDENTIAL' ? '#eab308' : '#22c55e', color: '#0f172a', fontWeight: 'bold' }}>
                          {f.dataClassification || f.sensitivityLevel}
                        </span>
                      </div>

                      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
                        <button onClick={() => handleDownloadFile(f.id, f.dataClassification)} style={{ padding: '6px 12px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}>⬇️ Download & Decrypt</button>
                      </div>

                      {/* FILE SHARING CONTROL */}
                      {userPermissions.includes('FILE_SHARE') && (
                        <div style={{ padding: '12px', backgroundColor: '#1e293b', borderRadius: '6px', border: '1px solid #334155' }}>
                          <div style={{ fontSize: '12px', fontWeight: 'bold', color: '#38bdf8', marginBottom: '8px' }}>🤝 Share File with Organization User</div>
                          
                          {/* Step 1: Select Organization User */}
                          <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                            <select
                              onChange={(e) => handleRecipientSelected(f.id, e.target.value)}
                              style={{ flex: 1, padding: '6px', borderRadius: '4px', backgroundColor: '#0f172a', color: '#fff', border: '1px solid #475569', fontSize: '12px' }}
                            >
                              <option value="">Select Recipient User...</option>
                              {orgMembers.filter((u) => u.id !== currentUser.id).map((u) => (
                                <option key={u.id} value={u.id}>{u.email} {u.publicKeyRegistered ? '(Crypto Identity Ready)' : '(No Crypto Key)'}</option>
                              ))}
                            </select>

                            <select
                              value={shareAccessLevels[f.id] || 'READ'}
                              onChange={(e) => setShareAccessLevels((prev) => ({ ...prev, [f.id]: e.target.value }))}
                              style={{ width: '130px', padding: '6px', borderRadius: '4px', backgroundColor: '#0f172a', color: '#fff', border: '1px solid #475569', fontSize: '12px' }}
                            >
                              <option value="READ">READ ONLY</option>
                              <option value="FULL">FULL ACCESS</option>
                            </select>
                          </div>

                          {/* Step 2: Display Selected User's Organization Permissions */}
                          {recipient && (
                            <div style={{ backgroundColor: '#0f172a', padding: '10px', borderRadius: '6px', fontSize: '11px', marginBottom: '10px', border: '1px solid #334155' }}>
                              <div style={{ color: '#cbd5e1', fontWeight: 'bold', marginBottom: '4px' }}>
                                Selected User: <span>{recipient.email}</span>
                              </div>
                              <div style={{ marginBottom: '4px' }}>
                                <strong>Assigned Roles:</strong> {recipient.roles && recipient.roles.length > 0 ? recipient.roles.map((r) => typeof r === 'string' ? r : (r.name || r.id)).join(', ') : 'None'}
                              </div>
                              <div style={{ color: '#cbd5e1' }}>
                                <strong>Effective Organization Permissions:</strong>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px', marginTop: '4px' }}>
                                  <div>{(recipientInfo?.permissions || recipient.permissions || []).includes('FILE_READ') ? '✓ FILE_READ' : '✗ FILE_READ'}</div>
                                  <div>{(recipientInfo?.permissions || recipient.permissions || []).includes('FILE_SHARE') ? '✓ FILE_SHARE' : '✗ FILE_SHARE'}</div>
                                  <div>{(recipientInfo?.permissions || recipient.permissions || []).includes('FILE_REVOKE') ? '✓ FILE_REVOKE' : '✗ FILE_REVOKE'}</div>
                                  <div>{(recipientInfo?.permissions || recipient.permissions || []).includes('FILE_DELETE') ? '✓ FILE_DELETE' : '✗ FILE_DELETE'}</div>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Step 3: Explanation of File-Specific Restrictions */}
                          <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>
                            {shareAccessLevels[f.id] === 'READ' ? (
                              <span>🔒 <strong>File Restriction Applied:</strong> Recipient can read/download, but will be explicitly restricted from re-sharing, revoking, or deleting this specific file (even if their role has those general permissions).</span>
                            ) : (
                              <span>⚡ <strong>Full Control Access:</strong> Recipient can re-share or manage this file if permitted by their role permissions.</span>
                            )}
                          </div>

                          <button onClick={() => handleShareFile(f.id)} style={{ width: '100%', padding: '8px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}>
                            Share File with {recipient ? recipient.email : 'Selected User'}
                          </button>
                        </div>
                      )}

                      {/* ACTIVE SHARES FOR THIS FILE */}
                      {fileShares[f.id] && fileShares[f.id].length > 0 && (
                        <div style={{ marginTop: '10px', fontSize: '11px', backgroundColor: '#1e293b', padding: '8px', borderRadius: '4px' }}>
                          <strong style={{ color: '#94a3b8' }}>Currently Shared With:</strong>
                          {fileShares[f.id].map((s) => (
                            <div key={s.userId} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                              <span>{s.email} ({s.accessLevel || 'READ'} access)</span>
                              {userPermissions.includes('FILE_REVOKE') && (
                                <button onClick={() => handleRevokeShare(f.id, s.userId)} style={{ color: '#ef4444', background: 'none', border: 'none', cursor: 'pointer', fontSize: '11px' }}>Revoke</button>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>

            {/* Shared Files Listing */}
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', border: '1px solid #334155' }}>
              <h3 style={{ marginTop: 0, fontSize: '16px', color: '#38bdf8' }}>📥 Files Shared With Me</h3>
              {sharedFileList.length === 0 ? (
                <p style={{ fontSize: '12px', color: '#94a3b8' }}>No shared files received.</p>
              ) : (
                sharedFileList.map((sf) => (
                  <div key={sf.id} style={{ backgroundColor: '#0f172a', padding: '14px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #334155' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{sf.originalName}</strong>
                      <span style={{ fontSize: '10px', padding: '2px 6px', backgroundColor: sf.accessLevel === 'FULL' ? '#16a34a' : '#0284c7', borderRadius: '4px' }}>{sf.accessLevel} Access</span>
                    </div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>Owner: {sf.ownerEmail} | Classification: {sf.dataClassification}</div>
                    <button onClick={() => handleDownloadSharedFile(sf.id, sf.dataClassification)} style={{ padding: '6px 14px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}>🔓 Download & Decrypt Shared File</button>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      )}

      {/* TAB 2: USER MANAGEMENT */}
      {navTab === 'users' && (
        <div style={{ backgroundColor: '#1e293b', padding: '24px', borderRadius: '10px', border: '1px solid #334155' }}>
          <h3 style={{ marginTop: 0, fontSize: '18px', color: '#38bdf8' }}>👥 Organization User Management</h3>
          <p style={{ fontSize: '13px', color: '#cbd5e1', marginBottom: '20px' }}>
            Authorized users with <code>USER_CREATE</code> or <code>USER_MANAGE</code> permission can create user accounts and assign organization-specific roles.
          </p>

          {/* User Creation Form */}
          {userPermissions.includes('USER_CREATE') && (
            <div style={{ backgroundColor: '#0f172a', padding: '18px', borderRadius: '8px', marginBottom: '24px', border: '1px solid #334155' }}>
              <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', color: '#f8fafc' }}>Create New User Account</h4>
              <form onSubmit={handleCreateUser}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', marginBottom: '4px', color: '#cbd5e1' }}>User Email</label>
                    <input type="email" value={newUserEmail} onChange={(e) => setNewUserEmail(e.target.value)} required style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#1e293b', color: '#fff', fontSize: '12px', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', marginBottom: '4px', color: '#cbd5e1' }}>Initial Password</label>
                    <input type="password" value={newUserPassword} onChange={(e) => setNewUserPassword(e.target.value)} required style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#1e293b', color: '#fff', fontSize: '12px', boxSizing: 'border-box' }} />
                  </div>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Assign Organization Roles (Multi-Select):</label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', backgroundColor: '#1e293b', padding: '10px', borderRadius: '6px', border: '1px solid #334155' }}>
                    {orgRoles.map((r) => (
                      <label key={r.id} style={{ fontSize: '12px', cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={newUserRoleIds.includes(r.id)}
                          onChange={(e) => {
                            if (e.target.checked) setNewUserRoleIds((prev) => [...prev, r.id]);
                            else setNewUserRoleIds((prev) => prev.filter((id) => id !== r.id));
                          }}
                          style={{ marginRight: '6px' }}
                        />
                        <strong>{r.name}</strong>
                      </label>
                    ))}
                  </div>
                </div>

                <button type="submit" disabled={loading} style={{ padding: '10px 20px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 'bold', cursor: 'pointer' }}>
                  {loading ? 'Creating Account...' : 'Create User Account'}
                </button>
              </form>
            </div>
          )}

          {/* Members Table */}
          <h4 style={{ fontSize: '14px', color: '#f8fafc', marginBottom: '12px' }}>Organization Members List</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: '#0f172a', textAlign: 'left', color: '#94a3b8', borderBottom: '1px solid #334155' }}>
                <th style={{ padding: '10px' }}>User Email</th>
                <th style={{ padding: '10px' }}>Assigned Roles</th>
                <th style={{ padding: '10px' }}>Effective Permissions</th>
                <th style={{ padding: '10px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {orgMembers.map((u) => (
                <tr key={u.id} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '10px' }}>
                    <strong>{u.email}</strong>
                    {u.id === currentUser?.id && <span style={{ marginLeft: '6px', fontSize: '10px', color: '#38bdf8' }}>(You)</span>}
                  </td>
                  <td style={{ padding: '10px' }}>
                    {(u.roles || []).map((r) => {
                      const roleId = typeof r === 'string' ? r : r.id;
                      const roleName = typeof r === 'string' ? r : r.name;
                      return (
                        <span key={roleId || roleName} style={{ display: 'inline-block', padding: '2px 8px', borderRadius: '4px', backgroundColor: '#0369a1', color: '#fff', fontSize: '11px', marginRight: '4px' }}>
                          {roleName}
                        </span>
                      );
                    })}
                  </td>
                  <td style={{ padding: '10px', fontSize: '11px', color: '#94a3b8' }}>
                    {(u.permissions || []).join(', ')}
                  </td>
                  <td style={{ padding: '10px' }}>
                    {userPermissions.includes('USER_MANAGE') && (
                      <button
                        onClick={() => {
                          setEditingUser(u);
                          setEditUserRoleIds((u.roles || []).map((r) => typeof r === 'string' ? r : r.id));
                        }}
                        style={{ padding: '4px 10px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', cursor: 'pointer' }}
                      >
                        Edit Roles
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 3: CUSTOM ROLE MANAGEMENT */}
      {navTab === 'roles' && (
        <div style={{ backgroundColor: '#1e293b', padding: '24px', borderRadius: '10px', border: '1px solid #334155' }}>
          <h3 style={{ marginTop: 0, fontSize: '18px', color: '#38bdf8' }}>⚙️ Custom Role Management</h3>
          <p style={{ fontSize: '13px', color: '#cbd5e1', marginBottom: '20px' }}>
            Define custom organization-scoped roles by picking permissions from the system catalog.
          </p>

          {/* Create Custom Role Form */}
          <div style={{ backgroundColor: '#0f172a', padding: '18px', borderRadius: '8px', marginBottom: '24px', border: '1px solid #334155' }}>
            <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', color: '#f8fafc' }}>Create New Custom Role</h4>
            <form onSubmit={handleCreateCustomRole}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px', marginBottom: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', marginBottom: '4px', color: '#cbd5e1' }}>Role Name</label>
                  <input type="text" value={newRoleName} onChange={(e) => setNewRoleName(e.target.value)} required placeholder="e.g. Audit Manager" style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#1e293b', color: '#fff', fontSize: '12px', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', marginBottom: '4px', color: '#cbd5e1' }}>Description</label>
                  <input type="text" value={newRoleDesc} onChange={(e) => setNewRoleDesc(e.target.value)} placeholder="Role description..." style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#1e293b', color: '#fff', fontSize: '12px', boxSizing: 'border-box' }} />
                </div>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Select System Permissions Catalog:</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', backgroundColor: '#1e293b', padding: '12px', borderRadius: '6px', border: '1px solid #334155' }}>
                  {allPermissions.map((p) => {
                    const permName = typeof p === 'string' ? p : p.name;
                    const permId = typeof p === 'string' ? p : (p.id || p.name);
                    return (
                      <label key={permId} style={{ fontSize: '12px', cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={newRolePerms.includes(permName)}
                          onChange={(e) => {
                            if (e.target.checked) setNewRolePerms((prev) => [...prev, permName]);
                            else setNewRolePerms((prev) => prev.filter((item) => item !== permName));
                          }}
                          style={{ marginRight: '6px' }}
                        />
                        {permName}
                      </label>
                    );
                  })}
                </div>
              </div>

              <button type="submit" disabled={loading} style={{ padding: '10px 20px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 'bold', cursor: 'pointer' }}>
                {loading ? 'Creating Role...' : 'Create Role'}
              </button>
            </form>
          </div>

          {/* Organization Roles List */}
          <h4 style={{ fontSize: '14px', color: '#f8fafc', marginBottom: '12px' }}>Organization Custom Roles Catalog</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', marginBottom: '24px' }}>
            <thead>
              <tr style={{ backgroundColor: '#0f172a', textAlign: 'left', color: '#94a3b8', borderBottom: '1px solid #334155' }}>
                <th style={{ padding: '10px' }}>Role Name</th>
                <th style={{ padding: '10px' }}>Description</th>
                <th style={{ padding: '10px' }}>Included Permissions</th>
                <th style={{ padding: '10px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {orgRoles.map((r) => (
                <tr key={r.id} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '10px' }}><strong>{r.name}</strong></td>
                  <td style={{ padding: '10px', color: '#cbd5e1' }}>{r.description || '-'}</td>
                  <td style={{ padding: '10px' }}>
                    {(r.permissions || []).map((p) => {
                      const permName = typeof p === 'string' ? p : p.name;
                      const permId = typeof p === 'string' ? p : (p.id || p.name);
                      return (
                        <span key={permId} style={{ display: 'inline-block', padding: '2px 6px', borderRadius: '4px', backgroundColor: '#334155', color: '#38bdf8', fontSize: '11px', marginRight: '4px', marginBottom: '2px' }}>
                          {permName}
                        </span>
                      );
                    })}
                  </td>
                  <td style={{ padding: '10px' }}>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        onClick={() => {
                          setEditingRole(r);
                          setEditRolePerms((r.permissions || []).map((p) => typeof p === 'string' ? p : p.name));
                        }}
                        style={{ padding: '4px 10px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', cursor: 'pointer' }}
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDeleteCustomRole(r.id, r.name)}
                        style={{ padding: '4px 10px', backgroundColor: '#ef4444', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', cursor: 'pointer' }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* PERMISSION AUDIT MATRIX VIEW */}
          <h4 style={{ fontSize: '14px', color: '#f8fafc', marginBottom: '12px' }}>Permission Audit View (User-Role-Permission Mapping)</h4>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ backgroundColor: '#0f172a', textAlign: 'left', color: '#94a3b8', borderBottom: '1px solid #334155' }}>
                <th style={{ padding: '8px' }}>User Email</th>
                <th style={{ padding: '8px' }}>Role</th>
                <th style={{ padding: '8px' }}>Granted Permission</th>
              </tr>
            </thead>
            <tbody>
              {permissionAuditRecords.map((rec, idx) => (
                <tr key={rec.id || `${rec.email}_${rec.role_name}_${rec.permission_name}_${idx}`} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '8px' }}>{rec.email}</td>
                  <td style={{ padding: '8px', color: '#38bdf8' }}>{rec.role_name}</td>
                  <td style={{ padding: '8px' }}><code>{rec.permission_name}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 4: SECURITY POLICIES & GEO LOCATIONS */}
      {navTab === 'policies' && (
        <div style={{ backgroundColor: '#1e293b', padding: '24px', borderRadius: '10px', border: '1px solid #334155' }}>
          <h3 style={{ marginTop: 0, fontSize: '18px', color: '#38bdf8' }}>🛡️ Organization Security Policies & Geo-Fencing</h3>
          <p style={{ fontSize: '13px', color: '#cbd5e1', marginBottom: '20px' }}>
            Configure organization-level security controls and zero trust geographic location rules.
          </p>

          {orgPolicy ? (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
              
              {/* Policy Toggles Form */}
              <div style={{ backgroundColor: '#0f172a', padding: '18px', borderRadius: '8px', border: '1px solid #334155' }}>
                <h4 style={{ margin: '0 0 14px 0', fontSize: '14px', color: '#f8fafc' }}>Core Security Controls</h4>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', fontSize: '13px' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(orgPolicy.enforce_geo_fencing)}
                      onChange={(e) => handleUpdatePolicySettings({ enforceGeoFencing: e.target.checked })}
                      style={{ marginRight: '10px', width: '16px', height: '16px' }}
                    />
                    <div>
                      <strong>Enable Strict Geo-Fencing</strong>
                      <div style={{ fontSize: '11px', color: '#94a3b8' }}>When enabled, requests outside allowed geographic locations are strictly blocked with HTTP 403. Default: Disabled.</div>
                    </div>
                  </label>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', fontSize: '13px' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(orgPolicy.require_stepup_new_location)}
                      onChange={(e) => handleUpdatePolicySettings({ requireStepupNewLocation: e.target.checked })}
                      style={{ marginRight: '10px', width: '16px', height: '16px' }}
                    />
                    <div>
                      <strong>Require Step-Up Auth on New Location</strong>
                      <div style={{ fontSize: '11px', color: '#94a3b8' }}>Triggers password re-authentication when accessing from an unrecognized IP location.</div>
                    </div>
                  </label>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', fontSize: '13px' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(orgPolicy.require_stepup_sensitive_file)}
                      onChange={(e) => handleUpdatePolicySettings({ requireStepupSensitiveFile: e.target.checked })}
                      style={{ marginRight: '10px', width: '16px', height: '16px' }}
                    />
                    <div>
                      <strong>Require Step-Up Auth on Sensitive/Confidential Resources</strong>
                      <div style={{ fontSize: '11px', color: '#94a3b8' }}>Requires re-authenticating for actions on CONFIDENTIAL and HIGHLY_CONFIDENTIAL files.</div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Multi-Location Geo Policies */}
              <div style={{ backgroundColor: '#0f172a', padding: '18px', borderRadius: '8px', border: '1px solid #334155' }}>
                <h4 style={{ margin: '0 0 10px 0', fontSize: '14px', color: '#f8fafc' }}>Allowed Geographic Locations (Multiple Supported)</h4>
                
                {/* Form to Add Location */}
                <form onSubmit={handleAddGeoLocation} style={{ marginBottom: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 70px', gap: '6px' }}>
                  <input type="text" placeholder="Country (IN)" value={newGeoCountry} onChange={(e) => setNewGeoCountry(e.target.value)} required style={{ padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '12px' }} />
                  <input type="text" placeholder="State (ALL)" value={newGeoState} onChange={(e) => setNewGeoState(e.target.value)} required style={{ padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '12px' }} />
                  <input type="text" placeholder="City (ALL)" value={newGeoCity} onChange={(e) => setNewGeoCity(e.target.value)} required style={{ padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '12px' }} />
                  <button type="submit" style={{ padding: '6px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}>Add</button>
                </form>

                {/* List Locations */}
                <div style={{ backgroundColor: '#1e293b', borderRadius: '6px', padding: '10px' }}>
                  {(orgPolicy.allowedLocations || []).length === 0 ? (
                    <div style={{ fontSize: '12px', color: '#94a3b8' }}>No location rules configured.</div>
                  ) : (
                    (orgPolicy.allowedLocations || []).map((loc) => (
                      <div key={loc.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #334155', fontSize: '12px' }}>
                        <div>
                          Country: <strong>{loc.allowed_country}</strong> | State: <strong>{loc.allowed_state}</strong> | City: <strong>{loc.allowed_city}</strong>
                        </div>
                        <button onClick={() => handleRemoveGeoLocation(loc.id)} style={{ color: '#ef4444', background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px' }}>Delete</button>
                      </div>
                    ))
                  )}
                </div>
              </div>

            </div>
          ) : <div>Loading policies...</div>}
        </div>
      )}

      {/* TAB 5: SECURITY AUDIT LOGS & INTEGRITY */}
      {navTab === 'audit' && (
        <div style={{ backgroundColor: '#1e293b', padding: '24px', borderRadius: '10px', border: '1px solid #334155' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '18px', color: '#38bdf8' }}>📜 Security Audit Logs & Hash Chain Integrity</h3>
              <p style={{ fontSize: '12px', color: '#cbd5e1', margin: '4px 0 0 0' }}>Tamper-evident security audit events linked via SHA-256 cryptographic hashes.</p>
            </div>
            <button onClick={handleVerifyAuditChain} style={{ padding: '8px 16px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}>
              ✓ Verify Hash Chain Integrity
            </button>
          </div>

          {auditVerification && (
            <div style={{ padding: '12px 16px', backgroundColor: auditVerification.valid ? '#064e3b' : '#7f1d1d', color: auditVerification.valid ? '#6ee7b7' : '#fca5a5', borderRadius: '8px', fontSize: '13px', marginBottom: '16px', border: '1px solid #334155' }}>
              {auditVerification.valid ? (
                <div>✓ <strong>Chain Intact:</strong> All {auditVerification.totalLogs} audit records successfully re-computed and verified against SHA-256 parent hashes.</div>
              ) : (
                <div>⚠️ <strong>SECURITY ALERT:</strong> {auditVerification.error}</div>
              )}
            </div>
          )}

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ backgroundColor: '#0f172a', textAlign: 'left', color: '#94a3b8', borderBottom: '1px solid #334155' }}>
                <th style={{ padding: '10px' }}>Timestamp</th>
                <th style={{ padding: '10px' }}>Event</th>
                <th style={{ padding: '10px' }}>Result</th>
                <th style={{ padding: '10px' }}>User ID</th>
                <th style={{ padding: '10px' }}>Resource</th>
                <th style={{ padding: '10px' }}>Location</th>
                <th style={{ padding: '10px' }}>IP Address</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log) => (
                <tr key={log.id} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '10px', color: '#94a3b8' }}>{new Date(log.created_at).toLocaleString()}</td>
                  <td style={{ padding: '10px' }}><strong>{log.event_type}</strong></td>
                  <td style={{ padding: '10px' }}>
                    <span style={{ padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 'bold', backgroundColor: log.action === 'ALLOW' ? '#16a34a' : log.action === 'STEP_UP_REQUIRED' ? '#eab308' : '#ef4444', color: '#0f172a' }}>
                      {log.action}
                    </span>
                  </td>
                  <td style={{ padding: '10px' }}><code>{log.user_id ? log.user_id.substring(0, 8) + '...' : '-'}</code></td>
                  <td style={{ padding: '10px' }}><code>{log.resource_id ? log.resource_id.substring(0, 8) + '...' : '-'}</code></td>
                  <td style={{ padding: '10px' }}>{log.location_label || 'Localhost'}</td>
                  <td style={{ padding: '10px' }}><code>{log.ip_address || '127.0.0.1'}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

    </div>
  );
}
