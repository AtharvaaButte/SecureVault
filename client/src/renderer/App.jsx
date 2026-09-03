import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  const [userPermissions, setUserPermissions] = useState([]);
  const [userAssignedRoles, setUserAssignedRoles] = useState([]);

  // Cycle 2 Crypto Identity state
  const [cryptoIdentity, setCryptoIdentity] = useState({
    protected: false,
    registered: false,
    publicKey: null,
  });

  // Cycle 3 File Encryption state
  const [selectedFile, setSelectedFile] = useState(null);
  const [encryptResult, setEncryptResult] = useState(null);
  const [decryptResult, setDecryptResult] = useState(null);
  const [integrityResult, setIntegrityResult] = useState(null);

  // Cycle 4 + Phase 9D Upload & File Listing state
  const [uploadSensitivity, setUploadSensitivity] = useState('NORMAL');
  const [uploadResult, setUploadResult] = useState(null);
  const [fileList, setFileList] = useState([]);
  const [downloadStatus, setDownloadStatus] = useState({});

  // Cycle 6 & 7 E2EE File Sharing & Access Control state
  const [sharedFileList, setSharedFileList] = useState([]);
  const [orgUsers, setOrgUsers] = useState([]);
  const [shareRecipients, setShareRecipients] = useState({});
  const [shareStatus, setShareStatus] = useState({});
  const [sharedDownloadStatus, setSharedDownloadStatus] = useState({});
  const [fileShares, setFileShares] = useState({});

  // Cycle 10.1 RBAC & Roles state
  const [orgRoles, setOrgRoles] = useState([]);
  const [allPermissions, setAllPermissions] = useState([]);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [newRolePerms, setNewRolePerms] = useState([]);

  // Phase 9C/9D Risk & Security Panel state
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
  const [newUserRole, setNewUserRole] = useState('USER');

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

  // Fetch active recipient shares for a given owned file (Cycle 7)
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

  // Fetch current user's file listing (Cycle 4 + 7 + 9D)
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

  // Fetch Admin Organization Members List with Roles & Permissions
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

  // Fetch Organization Custom Roles (Cycle 10.1)
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

  // Fetch System Available Permissions (Cycle 10.1)
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

  // Fetch directory of other users in organization for sharing (Cycle 6)
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

  // Fetch files shared with current user (Cycle 6)
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

  // Helper to sync local identity with backend (Cycle 2)
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

  // Auto restore session and identity on launch
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
              await syncCryptographicIdentity(storedToken);
              await fetchUserFiles(storedToken);
              await fetchOrgUsers(storedToken);
              await fetchSharedFiles(storedToken);
              await fetchOrgMembers(storedToken);
              await fetchOrgRoles(storedToken);
              await fetchAllPermissions(storedToken);
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
      setSuccessMsg('Account registered and cryptographic identity keys generated!');
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
          role: newUserRole,
        }),
      });

      const data = await parseJsonResponse(res, 'Failed to create user');

      setNewUserEmail('');
      setNewUserPassword('');
      setSuccessMsg(`User ${data.user.email} created successfully.`);
      await fetchOrgMembers(token);
      await fetchOrgUsers(token);
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

  // Cycle 10.1 Create Custom Organization Role
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
      setSuccessMsg(`Custom Role "${data.role.name}" created successfully.`);
      await fetchOrgRoles(token);
    } catch (err) {
      setError(`[Create Custom Role Error]: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Cycle 3 Local File Selection & Local AES-256-GCM Encryption
  const handleSelectFile = async () => {
    if (!window.electronAPI || typeof window.electronAPI.selectFile !== 'function') return;
    setError(null);
    try {
      const res = await window.electronAPI.selectFile();
      if (!res.canceled) {
        setSelectedFile(res);
        setEncryptResult(null);
        setDecryptResult(null);
        setIntegrityResult(null);
        setUploadResult(null);
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
        setSuccessMsg('File encrypted locally with AES-256-GCM and stored in memory.');
      } else {
        setError(res.error);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Phase 9D Cloud Ciphertext Upload with Sensitivity Level
  const handleCloudUpload = async (reauthPwd = null) => {
    if (!selectedFile || !encryptResult) return;
    setLoading(true);
    setError(null);
    setUploadResult(null);

    try {
      const res = await window.electronAPI.uploadCiphertext({
        fileId: encryptResult.fileId,
        sensitivityLevel: uploadSensitivity,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setUploadResult({
          message: 'File ciphertext uploaded to cloud storage.',
          file: res.file,
        });
        setSuccessMsg(`File uploaded successfully! Sensitivity Level: ${uploadSensitivity}`);
        await fetchUserFiles(token);
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

  // Download & Decrypt Owned File
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

  // Share File with Recipient (Cycle 6 + 7 + 9D)
  const handleShareFile = async (fileId, reauthPwd = null) => {
    const recipient = shareRecipients[fileId];
    if (!recipient || !recipient.id || !recipient.publicKey) {
      setError('Please select a recipient with a registered public key from the dropdown.');
      return;
    }

    setShareStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null } }));
    setError(null);

    try {
      const res = await window.electronAPI.shareFile({
        fileId,
        recipientUserId: recipient.id,
        recipientPublicKey: recipient.publicKey,
        token,
        reauthPassword: reauthPwd,
      });

      if (res.success) {
        setShareStatus((prev) => ({
          ...prev,
          [fileId]: { loading: false, success: true, message: res.message },
        }));
        setSuccessMsg(`File shared successfully with ${recipient.email}!`);
        await fetchFileShares(fileId, token);
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

  // Revoke Share (Cycle 7 + 9D)
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

  // Download & Decrypt Shared File (Bob)
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

  // --- UNAUTHENTICATED LOGIN / REGISTER VIEW ---
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
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Admin Email Address</label>
              <input type="email" value={regEmail} onChange={(e) => setRegEmail(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '12px', marginBottom: '6px', color: '#cbd5e1' }}>Admin Password</label>
              <input type="password" value={regPassword} onChange={(e) => setRegPassword(e.target.value)} required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', boxSizing: 'border-box' }} />
            </div>
            <button type="submit" disabled={loading} style={{ width: '100%', padding: '12px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>{loading ? 'Creating Organization...' : 'Register & Setup Identity'}</button>
          </form>
        )}
      </div>
    );
  }

  // --- AUTHENTICATED DASHBOARD VIEW ---
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
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #38bdf8', borderRadius: '12px', padding: '28px', maxWidth: '560px', width: '100%', color: '#fff', maxHeight: '85vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #334155', paddingBottom: '12px', marginBottom: '18px' }}>
              <h3 style={{ margin: 0, color: '#38bdf8' }}>🛡️ Zero Trust Security Context (Phase 9A–9D & Cycle 10.1)</h3>
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

              <div style={{ marginBottom: '10px' }}><strong>Device Context (Safe ID):</strong> <code>{window.electronAPI?.platform ? `electron-profile-${currentUser?.email.split('@')[0]}` : 'electron-default-device'}</code></div>
              <div style={{ marginBottom: '10px' }}><strong>OS / Platform:</strong> <code>{window.electronAPI?.platform || 'windows-x64'}</code></div>
              <div style={{ marginBottom: '10px' }}><strong>Network & Region Context:</strong> <code>127.0.0.1 (LOCAL/DEV)</code></div>
              <div style={{ marginBottom: '14px' }}><strong>Device Trust State:</strong> <span style={{ color: '#4ade80', fontWeight: 'bold' }}>✓ Trusted Device Context</span></div>
              
              <div style={{ padding: '10px', backgroundColor: '#0f172a', borderRadius: '6px', fontSize: '11px', color: '#94a3b8', border: '1px dashed #334155' }}>
                🔒 <strong>Zero Trust Invariant Verified:</strong> Admin & Role privileges NEVER grant plaintext access to encrypted files. File decryption requires explicit file ownership or a valid DEK share.
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
            Org: <strong>{currentOrg?.name}</strong> | User: <strong>{currentUser?.email}</strong> | Roles: {userAssignedRoles.map(r => r.name).join(', ') || currentUser?.role}
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
        
        {/* LEFT COLUMN: FILE ENCRYPTION & CLOUD UPLOAD */}
        <div>
          {/* LOCAL ENCRYPTION CARD */}
          <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
            <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>1. Local File Encryption (AES-256-GCM)</h3>
            <p style={{ fontSize: '12px', color: '#94a3b8' }}>Select a local file to generate a 32-byte DEK and encrypt buffer locally.</p>

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
                <div>Algorithm: <code>{encryptResult.algorithm}</code></div>
                <div>Encrypted Size: {encryptResult.encryptedSize} bytes</div>
              </div>
            )}
          </div>

          {/* CLOUD UPLOAD & CLASSIFICATION CARD */}
          {encryptResult && (
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
              <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>2. Cloud Ciphertext Upload & Sensitivity Classification</h3>
              
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#cbd5e1', marginBottom: '6px' }}>Select File Sensitivity Level (Phase 9D):</label>
                <select
                  value={uploadSensitivity}
                  onChange={(e) => setUploadSensitivity(e.target.value)}
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', backgroundColor: '#0f172a', color: '#fff', border: '1px solid #475569' }}
                >
                  <option value="NORMAL">🟢 NORMAL (Standard E2EE Security)</option>
                  <option value="SENSITIVE">🟡 SENSITIVE (Step-Up Re-auth on Share/Revoke)</option>
                  <option value="HIGHLY_SENSITIVE">🔴 HIGHLY_SENSITIVE (Step-Up Re-auth on Download & Share)</option>
                </select>
              </div>

              <button onClick={() => handleCloudUpload()} disabled={loading} style={{ padding: '10px 18px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 'bold', cursor: 'pointer' }}>
                {loading ? 'Uploading to B2...' : '☁️ Upload Ciphertext & Self-Wrap DEK'}
              </button>
            </div>
          )}

          {/* ADMIN & ROLE MANAGEMENT PANEL (Cycle 10.1) */}
          {(userPermissions.includes('USER_MANAGE') || userPermissions.includes('ROLE_MANAGE')) && (
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', border: '1px solid #334155' }}>
              <h3 style={{ marginTop: 0, fontSize: '16px', color: '#38bdf8' }}>👥 User & Role Management (Cycle 10.1 RBAC)</h3>

              {/* Add User Form */}
              <form onSubmit={handleCreateUser} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 100px 100px', gap: '8px', marginBottom: '16px' }}>
                <input type="email" placeholder="New User Email" value={newUserEmail} onChange={(e) => setNewUserEmail(e.target.value)} required style={{ padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', fontSize: '12px' }} />
                <input type="password" placeholder="Password" value={newUserPassword} onChange={(e) => setNewUserPassword(e.target.value)} required style={{ padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', fontSize: '12px' }} />
                <select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value)} style={{ padding: '8px', borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a', color: '#fff', fontSize: '12px' }}>
                  <option value="USER">USER</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
                <button type="submit" disabled={loading} style={{ padding: '8px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}>Add User</button>
              </form>

              {/* Custom Role Creation Form */}
              {userPermissions.includes('ROLE_MANAGE') && (
                <form onSubmit={handleCreateCustomRole} style={{ backgroundColor: '#0f172a', padding: '12px', borderRadius: '8px', marginBottom: '16px', border: '1px solid #334155' }}>
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: '#a78bfa' }}>Create Custom Organization Role</h4>
                  <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                    <input type="text" placeholder="Role Name (e.g. Auditor)" value={newRoleName} onChange={(e) => setNewRoleName(e.target.value)} required style={{ flex: 1, padding: '6px 8px', borderRadius: '4px', border: '1px solid #334155', backgroundColor: '#1e293b', color: '#fff', fontSize: '12px' }} />
                    <input type="text" placeholder="Description" value={newRoleDesc} onChange={(e) => setNewRoleDesc(e.target.value)} style={{ flex: 1, padding: '6px 8px', borderRadius: '4px', border: '1px solid #334155', backgroundColor: '#1e293b', color: '#fff', fontSize: '12px' }} />
                  </div>
                  <div style={{ fontSize: '11px', color: '#cbd5e1', marginBottom: '8px' }}>Select Permissions:</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '10px' }}>
                    {allPermissions.map(p => (
                      <label key={p.id} style={{ fontSize: '11px', padding: '2px 6px', backgroundColor: '#1e293b', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <input
                          type="checkbox"
                          checked={newRolePerms.includes(p.name)}
                          onChange={(e) => {
                            if (e.target.checked) setNewRolePerms([...newRolePerms, p.name]);
                            else setNewRolePerms(newRolePerms.filter(x => x !== p.name));
                          }}
                        />
                        {p.name}
                      </label>
                    ))}
                  </div>
                  <button type="submit" disabled={loading} style={{ padding: '6px 14px', backgroundColor: '#7c3aed', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}>Create Custom Role</button>
                </form>
              )}

              <div style={{ fontSize: '12px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                      <th style={{ padding: '6px' }}>Email</th>
                      <th style={{ padding: '6px' }}>Assigned Roles</th>
                      <th style={{ padding: '6px' }}>Effective Permissions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {orgMembers.map(m => (
                      <tr key={m.id} style={{ borderBottom: '1px solid #1e293b' }}>
                        <td style={{ padding: '6px' }}>{m.email}</td>
                        <td style={{ padding: '6px' }}>
                          {(m.roles || []).map(r => (
                            <span key={r.id} style={{ padding: '2px 6px', borderRadius: '4px', backgroundColor: r.name === 'Admin' ? '#0369a1' : '#334155', fontSize: '10px', marginRight: '4px' }}>{r.name}</span>
                          ))}
                        </td>
                        <td style={{ padding: '6px' }}>
                          <span style={{ fontSize: '10px', color: '#94a3b8' }}>{(m.permissions || []).length} perms</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: OWNED FILES & SHARED FILES */}
        <div>
          {/* OWNED FILES & E2EE SHARING */}
          <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #334155' }}>
            <h3 style={{ marginTop: 0, fontSize: '16px', color: '#f8fafc' }}>📂 My Uploaded Files</h3>

            {fileList.length === 0 ? (
              <p style={{ fontSize: '12px', color: '#94a3b8' }}>No uploaded files found.</p>
            ) : (
              fileList.map((f) => {
                const sensitivity = f.sensitivityLevel || 'NORMAL';
                const badgeColor = sensitivity === 'HIGHLY_SENSITIVE' ? '#ef4444' : (sensitivity === 'SENSITIVE' ? '#eab308' : '#22c55e');

                return (
                  <div key={f.id} style={{ backgroundColor: '#0f172a', padding: '14px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #334155' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{f.originalName}</strong>
                      <span style={{ fontSize: '10px', padding: '3px 8px', borderRadius: '4px', backgroundColor: badgeColor, color: '#0f172a', fontWeight: 'bold' }}>
                        {sensitivity}
                      </span>
                    </div>

                    <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>
                      Size: {f.originalSize} bytes | ID: {f.id.substring(0, 8)}...
                    </div>

                    <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
                      <button
                        onClick={() => handleDownloadFile(f.id, sensitivity)}
                        style={{ padding: '6px 12px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}
                      >
                        ⬇️ Download & Decrypt
                      </button>
                    </div>

                    {/* RECIPIENT SHARING CONTROL */}
                    <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
                      <select
                        onChange={(e) => {
                          const targetUser = orgUsers.find(u => u.id === e.target.value);
                          if (targetUser) setShareRecipients(prev => ({ ...prev, [f.id]: targetUser }));
                        }}
                        style={{ flex: 1, padding: '6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#fff', border: '1px solid #334155', fontSize: '11px' }}
                      >
                        <option value="">Select Org Recipient...</option>
                        {orgUsers.filter(u => u.id !== currentUser.id).map(u => (
                          <option key={u.id} value={u.id}>{u.email}</option>
                        ))}
                      </select>
                      <button
                        onClick={() => handleShareFile(f.id)}
                        style={{ padding: '6px 12px', backgroundColor: '#16a34a', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', cursor: 'pointer' }}
                      >
                        🤝 Share DEK
                      </button>
                    </div>

                    {/* ACTIVE SHARES LIST */}
                    {fileShares[f.id] && fileShares[f.id].length > 0 && (
                      <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px dashed #334155', fontSize: '11px' }}>
                        <span style={{ color: '#cbd5e1' }}>Currently Shared With:</span>
                        {fileShares[f.id].map(share => (
                          <div key={share.userId} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                            <span>• {share.email}</span>
                            <button
                              onClick={() => handleRevokeShare(f.id, share.userId)}
                              style={{ padding: '2px 8px', backgroundColor: '#991b1b', color: '#fff', border: 'none', borderRadius: '3px', fontSize: '10px', cursor: 'pointer' }}
                            >
                              Revoke
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* FILES SHARED WITH ME */}
          <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '10px', border: '1px solid #334155' }}>
            <h3 style={{ marginTop: 0, fontSize: '16px', color: '#38bdf8' }}>📥 Files Shared With Me</h3>

            {sharedFileList.length === 0 ? (
              <p style={{ fontSize: '12px', color: '#94a3b8' }}>No shared files available.</p>
            ) : (
              sharedFileList.map((sf) => {
                const sensitivity = sf.sensitivityLevel || 'NORMAL';
                const badgeColor = sensitivity === 'HIGHLY_SENSITIVE' ? '#ef4444' : (sensitivity === 'SENSITIVE' ? '#eab308' : '#22c55e');

                return (
                  <div key={sf.id} style={{ backgroundColor: '#0f172a', padding: '14px', borderRadius: '8px', marginBottom: '12px', border: '1px solid #334155' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <strong style={{ fontSize: '14px', color: '#f8fafc' }}>{sf.originalName}</strong>
                      <span style={{ fontSize: '10px', padding: '3px 8px', borderRadius: '4px', backgroundColor: badgeColor, color: '#0f172a', fontWeight: 'bold' }}>
                        {sensitivity}
                      </span>
                    </div>

                    <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>
                      Owner: <strong>{sf.ownerEmail}</strong> | Size: {sf.originalSize} bytes
                    </div>

                    <button
                      onClick={() => handleDownloadSharedFile(sf.id, sensitivity)}
                      style={{ padding: '6px 14px', backgroundColor: '#0284c7', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                    >
                      🔓 Download & Decrypt Shared File
                    </button>
                  </div>
                );
              })
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
