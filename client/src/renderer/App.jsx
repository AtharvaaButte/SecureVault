import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  const [userPermissions, setUserPermissions] = useState([]);
  const [userAssignedRoles, setUserAssignedRoles] = useState([]);

  // Crypto Identity state
  const [cryptoIdentity, setCryptoIdentity] = useState({
    protected: false,
    registered: false,
    publicKey: null,
  });

  // Local File Encryption state
  const [selectedFile, setSelectedFile] = useState(null);
  const [encryptResult, setEncryptResult] = useState(null);

  // Upload & File Listing state
  const [uploadSensitivity, setUploadSensitivity] = useState('INTERNAL');
  const [fileList, setFileList] = useState([]);
  const [downloadStatus, setDownloadStatus] = useState({});

  // E2EE File Sharing state
  const [sharedFileList, setSharedFileList] = useState([]);
  const [orgUsers, setOrgUsers] = useState([]);
  const [shareRecipients, setShareRecipients] = useState({});
  const [shareAccessLevels, setShareAccessLevels] = useState({});
  const [shareStatus, setShareStatus] = useState({});
  const [sharedDownloadStatus, setSharedDownloadStatus] = useState({});
  const [fileShares, setFileShares] = useState({});

  // RBAC & Roles state
  const [orgRoles, setOrgRoles] = useState([]);
  const [allPermissions, setAllPermissions] = useState([]);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [newRolePerms, setNewRolePerms] = useState([]);

  // Organization Security Policies & Multi-Geo Locations state
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

  const [activeTab, setActiveTab] = useState('login'); // 'login' | 'register'
  const [loading, setLoading] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Form states
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  const [regOrgName, setRegOrgName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');

  const [orgMembers, setOrgMembers] = useState([]);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');

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

  const fetchOrgMembers = async (authToken = token) => {
    try {
      const res = await fetch(`${API_BASE}/users/members`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrgMembers(data.users || []);
        const me = data.users.find(u => u.id === currentUser?.id);
        if (me) {
          setUserPermissions(me.permissions || []);
          setUserAssignedRoles(me.roles || []);
        }
      }
    } catch (err) {
      console.error('[Fetch Org Members Error]:', err.message);
    }
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

  const handleVerifyAuditChain = async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`${API_BASE}/audit/verify`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await parseJsonResponse(res, 'Audit verification failed');
      setAuditVerification(data);
      if (data.valid) {
        setSuccessMsg(`Audit Chain Verified! All ${data.totalLogs} SHA-256 event hashes intact.`);
      } else {
        setError(`[TAMPER DETECTED]: ${data.error}`);
      }
    } catch (err) {
      setError(`[Verification Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePolicy = async (newPolicyFields) => {
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
    } catch (err) {
      setError(`[Geo Policy Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchOrgUsers = async (authToken = token) => {
    if (!window.electronAPI || typeof window.electronAPI.getOrganizationUsers !== 'function' || !authToken) return;
    try {
      const res = await window.electronAPI.getOrganizationUsers(authToken);
      if (res.success) {
        setOrgUsers(res.users || []);
      }
    } catch (err) {
      console.error('[Fetch Org Users Error]:', err.message);
    }
  };

  const fetchSharedFiles = async (authToken = token) => {
    if (!window.electronAPI || typeof window.electronAPI.getSharedFiles !== 'function') return;
    try {
      const res = await window.electronAPI.getSharedFiles(authToken);
      if (res.success) {
        setSharedFileList(res.sharedFiles || []);
      } else if (res.error) {
        console.error('[Shared Files Error]:', res.error);
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
              await fetchOrgUsers(storedToken);
              await fetchSharedFiles(storedToken);
              await fetchOrgMembers(storedToken);
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

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          orgName: regOrgName,
          email: regEmail,
          password: regPassword,
        }),
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
      await fetchOrgUsers(data.token);
      await fetchSharedFiles(data.token);
      await fetchOrgMembers(data.token);
      await fetchOrgRoles(data.token);
      await fetchAllPermissions(data.token);
      await fetchOrgPolicy(data.token);
      await fetchAuditLogs(data.token);
      setSuccessMsg('Account registered and cryptographic identity setup successfully!');
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
        body: JSON.stringify({
          email: loginEmail,
          password: loginPassword,
        }),
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
      await fetchOrgUsers(data.token);
      await fetchSharedFiles(data.token);
      await fetchOrgMembers(data.token);
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
        }),
      });

      const data = await parseJsonResponse(res, 'Failed to create user');

      setNewUserEmail('');
      setNewUserPassword('');
      setSuccessMsg(`User ${data.user.email} created successfully.`);
      await fetchOrgMembers(token);
      await fetchOrgUsers(token);
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
      setSuccessMsg(`Role "${data.role.name}" created successfully.`);
      await fetchOrgRoles(token);
      await fetchAuditLogs(token);
    } catch (err) {
      setError(`[Create Custom Role Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

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
        dataClassification: uploadSensitivity,
        sensitivityLevel: uploadSensitivity,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setSuccessMsg(`File uploaded successfully! Sensitivity Level: ${uploadSensitivity}`);
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

  const handleDownloadFile = async (fileId, sensitivityLevel, reauthPwd = null) => {
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
          promptStepUp(res.error, (pwd) => handleDownloadFile(fileId, sensitivityLevel, pwd));
        } else {
          setError(`[Download Error]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
      setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: err.message } }));
    }
  };

  const handleShareFile = async (fileId, reauthPwd = null) => {
    const recipient = shareRecipients[fileId];
    if (!recipient || !recipient.id || !recipient.publicKey) {
      setError('Please select a recipient with a registered public key from the dropdown.');
      return;
    }

    const accessLevel = shareAccessLevels[fileId] || 'READ';

    setShareStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null } }));
    setError(null);

    try {
      const res = await window.electronAPI.shareFile({
        fileId,
        recipientUserId: recipient.id,
        recipientPublicKey: recipient.publicKey,
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

  const handleDownloadSharedFile = async (fileId, sensitivityLevel, reauthPwd = null) => {
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
          promptStepUp(res.error, (pwd) => handleDownloadSharedFile(fileId, sensitivityLevel, pwd));
        } else {
          setError(`[Shared Download Access Denied]: ${res.error}`);
        }
      }
    } catch (err) {
      setError(err.message);
      setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: err.message } }));
    }
  };

  if (initializing) {
    return (
      <div style={{ display: 'flex', height: '100vh', justifyContent: 'center', alignItems: 'center', backgroundColor: '#0f172a', color: '#f8fafc', fontFamily: 'sans-serif' }}>
        <div>Initializing SecureVault session & identity...</div>
      </div>
    );
  }

  if (!token) {
    return (
      <div style={{ maxWidth: '420px', margin: '60px auto', padding: '30px', backgroundColor: '#1e293b', borderRadius: '12px', color: '#f8fafc', fontFamily: 'sans-serif', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}>
        <h2 style={{ textAlign: 'center', marginTop: 0, color: '#38bdf8' }}>🔒 SecureVault</h2>
        <p style={{ textAlign: 'center', fontSize: '13px', color: '#94a3b8', marginBottom: '24px' }}>Zero Trust E2EE Cloud Storage Solution</p>

        <div style={{ display: 'flex', borderBottom: '1px solid #334155', marginBottom: '20px' }}>
          <button onClick={() => { setActiveTab('login'); setError(null); }} style={{ flex: 1, padding: '10px', background: 'none', border: 'none', borderBottom: activeTab === 'login' ? '2px solid #38bdf8' : 'none', color: activeTab === 'login' ? '#38bdf8' : '#94a3b8', fontWeight: 'bold', cursor: 'pointer' }}>Login</button>
          <button onClick={() => { setActiveTab('register'); setError(null); }} style={{ flex: 1, padding: '10px', background: 'none', border: 'none', borderBottom: activeTab === 'register' ? '2px solid #38bdf8' : 'none', color: activeTab === 'register' ? '#38bdf8' : '#94a3b8', fontWeight: 'bold', cursor: 'pointer' }}>Register Organization</button>
        </div>

        {error && <div style={{ padding: '10px', backgroundColor: '#7f1d1d', color: '#fca5a5', borderRadius: '6px', fontSize: '13px', marginBottom: '16px' }}>{error}</div>}

        {activeTab === 'login' ? (
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

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#f8fafc', fontFamily: 'sans-serif', padding: '24px' }}>
      
      {/* STEP-UP RE-AUTHENTICATION MODAL */}
      {stepUpModal.show && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 9999 }}>
          <div style={{ backgroundColor: '#1e293b', border: '2px solid #eab308', borderRadius: '12px', padding: '28px', maxWidth: '440px', width: '100%', color: '#fff', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)' }}>
            <h3 style={{ marginTop: 0, color: '#eab308', display: 'flex', alignItems: 'center', gap: '8px' }}>
              ⚠️ Step-Up Re-Authentication Required
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

      {/* ZERO TRUST & SECURITY CONTEXT MODAL */}
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
                {userAssignedRoles.map(r => (
                  <span key={r.id} style={{ padding: '2px 8px', borderRadius: '4px', backgroundColor: '#0369a1', color: '#fff', fontWeight: 'bold', marginRight: '4px', fontSize: '11px' }}>
                    {r.name}
                  </span>
                ))}
              </div>
              
              <div style={{ marginBottom: '14px' }}>
                <strong>Effective Dynamic RBAC Permissions:</strong>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                  {userPermissions.map(p => (
                    <span key={p} style={{ padding: '3px 8px', borderRadius: '4px', backgroundColor: p.startsWith('FILE_') ? '#0284c7' : '#7c3aed', color: '#fff', fontSize: '11px' }}>{p}</span>
                  ))}
                </div>
              </div>

              {/* AUDIT CHAIN STATUS */}
              <div style={{ padding: '12px', backgroundColor: '#0f172a', borderRadius: '8px', marginBottom: '14px', border: '1px solid #334155' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <h4 style={{ margin: 0, color: '#38bdf8', fontSize: '13px' }}>📜 SHA-256 Audit Chain Verification</h4>
                  <button onClick={handleVerifyAuditChain} style={{ padding: '4px 10px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', cursor: 'pointer' }}>Verify Chain Integrity</button>
                </div>
                {auditVerification && (
                  <div style={{ fontSize: '11px', color: auditVerification.valid ? '#4ade80' : '#fca5a5', fontWeight: 'bold' }}>
                    {auditVerification.valid ? `✓ Chain Intact (${auditVerification.totalLogs} logs verified)` : `⚠️ ${auditVerification.error}`}
                  </div>
                )}
              </div>

              {/* MULTI-GEO POLICIES */}
              <div style={{ padding: '12px', backgroundColor: '#0f172a', borderRadius: '8px', marginBottom: '14px', border: '1px solid #334155' }}>
                <h4 style={{ margin: '0 0 8px 0', color: '#38bdf8', fontSize: '13px' }}>🌍 Multi-Location Geo Policies</h4>
                {orgPolicy ? (
                  <div>
                    <div>Geo-Fencing Mode: <strong>{orgPolicy.enforce_geo_fencing ? '🔴 Strict Enforce / Block' : '🟡 Flexible / Step-Up Re-Auth'}</strong></div>
                    <div style={{ marginTop: '6px', fontSize: '11px' }}>Allowed Locations:</div>
                    {(orgPolicy.allowedLocations || []).map(loc => (
                      <div key={loc.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', padding: '2px 0' }}>
                        <code>{loc.allowed_city}, {loc.allowed_state}, {loc.allowed_country}</code>
                        {userPermissions.includes('ORG_MANAGE') && (
                          <button onClick={() => handleRemoveGeoLocation(loc.id)} style={{ color: '#ef4444', background: 'none', border: 'none', cursor: 'pointer' }}>Remove</button>
                        )}
                      </div>
                    ))}
                  </div>
                ) : <div>Loading policies...</div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TOP HEADER */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#1e293b', padding: '16px 24px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#38bdf8' }}>🔒 SecureVault</h2>
          <div style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '4px' }}>
            Org: <strong>{currentOrg?.name}</strong> | User: <strong>{currentUser?.email}</strong> | Roles: {userAssignedRoles.map(r => r.name).join(', ') || 'No Assigned Role'}
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

      {/* NOTIFICATION BANNERS */}
      {error && <div style={{ padding: '12px 16px', backgroundColor: '#7f1d1d', color: '#fca5a5', borderRadius: '8px', fontSize: '13px', marginBottom: '20px', border: '1px solid #991b1b' }}>{error}</div>}
      {successMsg && <div style={{ padding: '12px 16px', backgroundColor: '#064e3b', color: '#6ee7b7', borderRadius: '8px', fontSize: '13px', marginBottom: '20px', border: '1px solid #047857' }}>{successMsg}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        
        {/* LEFT COLUMN */}
        <div>
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
              </div>
            )}
          </div>

          {encryptResult && (
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
              <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>2. Cloud Upload & Data Classification</h3>
              <div style={{ marginBottom: '16px' }}>
                <select value={uploadSensitivity} onChange={(e) => setUploadSensitivity(e.target.value)} style={{ width: '100%', padding: '10px', borderRadius: '6px', backgroundColor: '#0f172a', color: '#fff', border: '1px solid #475569' }}>
                  <option value="INTERNAL">🟢 INTERNAL (Standard Security)</option>
                  <option value="CONFIDENTIAL">🟡 CONFIDENTIAL (Step-Up on Share/Revoke)</option>
                  <option value="HIGHLY_CONFIDENTIAL">🔴 HIGHLY_CONFIDENTIAL (Step-Up on Download & Share)</option>
                  <option value="PUBLIC">⚪ PUBLIC (Unclassified)</option>
                </select>
              </div>
              <button onClick={() => handleCloudUpload()} disabled={loading} style={{ padding: '10px 18px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 'bold', cursor: 'pointer' }}>
                {loading ? 'Uploading...' : '☁️ Upload Ciphertext'}
              </button>
            </div>
          )}

          {/* ADMIN MANAGEMENT */}
          {(userPermissions.includes('USER_MANAGE') || userPermissions.includes('ROLE_MANAGE') || userPermissions.includes('ORG_MANAGE')) && (
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', border: '1px solid #334155' }}>
              <h3 style={{ marginTop: 0, fontSize: '16px', color: '#38bdf8' }}>⚙️ Security Policy & User Management</h3>

              {/* Add Geo Location Policy */}
              {userPermissions.includes('ORG_MANAGE') && (
                <form onSubmit={handleAddGeoLocation} style={{ backgroundColor: '#0f172a', padding: '12px', borderRadius: '8px', marginBottom: '16px', border: '1px solid #334155' }}>
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: '#38bdf8' }}>Add Allowed Geographic Scope</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 80px', gap: '6px' }}>
                    <input type="text" placeholder="Country (IN)" value={newGeoCountry} onChange={(e) => setNewGeoCountry(e.target.value)} required style={{ padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '11px' }} />
                    <input type="text" placeholder="State (ALL)" value={newGeoState} onChange={(e) => setNewGeoState(e.target.value)} required style={{ padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '11px' }} />
                    <input type="text" placeholder="City (ALL)" value={newGeoCity} onChange={(e) => setNewGeoCity(e.target.value)} required style={{ padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '11px' }} />
                    <button type="submit" style={{ padding: '6px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', cursor: 'pointer' }}>Add</button>
                  </div>
                </form>
              )}

              {/* Add User Form */}
              <form onSubmit={handleCreateUser} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 100px', gap: '8px', marginBottom: '16px' }}>
                <input type="email" placeholder="User Email" value={newUserEmail} onChange={(e) => setNewUserEmail(e.target.value)} required style={{ padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', fontSize: '12px' }} />
                <input type="password" placeholder="Password" value={newUserPassword} onChange={(e) => setNewUserPassword(e.target.value)} required style={{ padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', fontSize: '12px' }} />
                <button type="submit" disabled={loading} style={{ padding: '8px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}>Add User</button>
              </form>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN */}
        <div>
          <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
            <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>📂 My Uploaded Files</h3>

            {fileList.length === 0 ? (
              <p style={{ fontSize: '12px', color: '#94a3b8' }}>No uploaded files found.</p>
            ) : (
              fileList.map((f) => (
                <div key={f.id} style={{ backgroundColor: '#0f172a', padding: '14px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #334155' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{f.originalName}</strong>
                    <span style={{ fontSize: '10px', padding: '3px 8px', borderRadius: '4px', backgroundColor: '#22c55e', color: '#0f172a', fontWeight: 'bold' }}>{f.sensitivityLevel}</span>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
                    <button onClick={() => handleDownloadFile(f.id, f.sensitivityLevel)} style={{ padding: '6px 12px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}>⬇️ Download</button>
                  </div>

                  {/* RECIPIENT SHARING CONTROL WITH RESOURCE-LEVEL ACCESS RESTRICTION */}
                  <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
                    <select
                      onChange={(e) => {
                        const targetUser = orgUsers.find(u => u.id === e.target.value);
                        if (targetUser) setShareRecipients(prev => ({ ...prev, [f.id]: targetUser }));
                      }}
                      style={{ flex: 1, padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '11px' }}
                    >
                      <option value="">Select Recipient...</option>
                      {orgUsers.filter(u => u.id !== currentUser.id).map(u => (
                        <option key={u.id} value={u.id}>{u.email}</option>
                      ))}
                    </select>

                    <select
                      value={shareAccessLevels[f.id] || 'READ'}
                      onChange={(e) => setShareAccessLevels(prev => ({ ...prev, [f.id]: e.target.value }))}
                      style={{ width: '100px', padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '11px' }}
                    >
                      <option value="READ">READ ONLY</option>
                      <option value="FULL">FULL ACCESS</option>
                    </select>

                    <button onClick={() => handleShareFile(f.id)} style={{ padding: '6px 12px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', cursor: 'pointer' }}>🤝 Share</button>
                  </div>
                </div>
              ))
            )}
          </div>

          <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', border: '1px solid #334155' }}>
            <h3 style={{ marginTop: 0, fontSize: '16px', color: '#38bdf8' }}>📥 Files Shared With Me</h3>
            {sharedFileList.map((sf) => (
              <div key={sf.id} style={{ backgroundColor: '#0f172a', padding: '14px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #334155' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{sf.originalName}</strong>
                  <span style={{ fontSize: '10px', padding: '2px 6px', backgroundColor: sf.accessLevel === 'FULL' ? '#16a34a' : '#0284c7', borderRadius: '4px' }}>{sf.accessLevel}</span>
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>Owner: {sf.ownerEmail}</div>
                <button onClick={() => handleDownloadSharedFile(sf.id, sf.sensitivityLevel)} style={{ padding: '6px 14px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}>🔓 Download & Decrypt</button>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
