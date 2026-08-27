import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);

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

  // Cycle 4 Cloud Upload & File Listing state
  const [uploadResult, setUploadResult] = useState(null);
  const [fileList, setFileList] = useState([]);
  const [downloadStatus, setDownloadStatus] = useState({});

  // Cycle 6 E2EE File Sharing state
  const [sharedFileList, setSharedFileList] = useState([]);
  const [orgUsers, setOrgUsers] = useState([]);
  const [shareRecipients, setShareRecipients] = useState({});
  const [shareStatus, setShareStatus] = useState({});
  const [sharedDownloadStatus, setSharedDownloadStatus] = useState({});

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

  // Fetch current user's file listing (Cycle 4)
  const fetchUserFiles = async (authToken) => {
    try {
      const res = await fetch(`${API_BASE}/files`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setFileList(data.files || []);
      }
    } catch (err) {
      console.error('[Fetch Files Error]:', err.message);
    }
  };

  const fetchOrgMembers = async (authToken) => {
    try {
      const res = await fetch(`${API_BASE}/users/members`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setOrgMembers(data.users || []);
      }
    } catch (err) {
      console.error('[Fetch Org Members Error]:', err.message);
    }
  };

  // Fetch directory of other users in organization for sharing (Cycle 6)
  const fetchOrgUsers = async (authToken) => {
    if (!window.electronAPI || typeof window.electronAPI.getOrganizationUsers !== 'function') return;
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
  const fetchSharedFiles = async (authToken) => {
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

  // Helper to sync local identity with backend (Cycle 2)
  const syncCryptographicIdentity = async (authToken) => {
    if (!window.electronAPI || typeof window.electronAPI.ensureIdentity !== 'function') {
      return;
    }

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
        } else {
          setCryptoIdentity({
            protected: true,
            registered: false,
            publicKey: localId.publicKey,
          });
        }
      }
    } catch (err) {
      console.error('[Crypto Identity Sync Error]:', err.message);
    }
  };

  // Auto restore session and identity on app launch
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
              if (data.user?.role === 'ADMIN') {
                await fetchOrgMembers(storedToken);
              }
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

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Registration failed.');

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
      if (data.user?.role === 'ADMIN') {
        await fetchOrgMembers(data.token);
      }
      setSuccessMsg('Account registered and identity keys generated!');
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

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Login failed.');

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
      if (data.user?.role === 'ADMIN') {
        await fetchOrgMembers(data.token);
      }
      setSuccessMsg('Logged in successfully!');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!token) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          email: newUserEmail,
          password: newUserPassword,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to create user.');

      setNewUserEmail('');
      setNewUserPassword('');
      await fetchOrgMembers(token);
      setSuccessMsg(`User created: ${data.user.email}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      if (window.electronAPI && typeof window.electronAPI.clearSession === 'function') {
        await window.electronAPI.clearSession();
      }
      setToken(null);
      setCurrentUser(null);
      setCurrentOrg(null);
      setCryptoIdentity({ protected: false, registered: false, publicKey: null });
      setSelectedFile(null);
      setEncryptResult(null);
      setDecryptResult(null);
      setIntegrityResult(null);
      setUploadResult(null);
      setFileList([]);
      setSharedFileList([]);
      setOrgUsers([]);
      setOrgMembers([]);
      setNewUserEmail('');
      setNewUserPassword('');
      setSuccessMsg('Logged out successfully.');
    } catch (err) {
      console.error('[Logout Error]:', err.message);
    } finally {
      setLoading(false);
    }
  };

  // Cycle 3 Local File Operations
  const handleSelectFile = async () => {
    if (!window.electronAPI || typeof window.electronAPI.selectFile !== 'function') return;
    setError(null);
    setEncryptResult(null);
    setDecryptResult(null);
    setIntegrityResult(null);
    setUploadResult(null);

    const res = await window.electronAPI.selectFile();
    if (res.canceled) return;
    if (res.error) {
      setError(res.error);
    } else {
      setSelectedFile(res);
    }
  };

  const handleEncryptFile = async () => {
    if (!selectedFile || !window.electronAPI) return;
    setLoading(true);
    setError(null);

    const res = await window.electronAPI.encryptFile(selectedFile.filePath);
    setLoading(false);

    if (res.error) {
      setError(res.error);
    } else {
      setEncryptResult(res);
      setSuccessMsg('File encrypted locally using AES-256-GCM. DEK held in memory.');
    }
  };

  const handleDecryptFile = async () => {
    if (!encryptResult || !window.electronAPI) return;
    setLoading(true);
    setError(null);

    const res = await window.electronAPI.decryptFile(encryptResult.fileId);
    setLoading(false);

    if (res.error) {
      setError(res.error);
    } else {
      setDecryptResult(res);
      const integrity = await window.electronAPI.verifyIntegrity(selectedFile.filePath, res.decryptedPath);
      setIntegrityResult(integrity);
    }
  };

  // Cycle 4 Upload Handler
  const handleUploadCiphertext = async () => {
    if (!encryptResult || !token || !window.electronAPI) return;
    setLoading(true);
    setError(null);

    const res = await window.electronAPI.uploadCiphertext(encryptResult.fileId, token);
    setLoading(false);

    if (!res.success) {
      setError(res.error || 'Cloud upload failed');
    } else {
      setUploadResult(res.file);
      setSuccessMsg('Ciphertext uploaded to Backblaze B2 & metadata saved to PostgreSQL!');
      await fetchUserFiles(token);
    }
  };

  // Cycle 5 Download Handler (Owned File)
  const handleDownloadDecrypt = async (fileId) => {
    if (!token || !window.electronAPI) return;
    setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null, success: false } }));

    const res = await window.electronAPI.downloadDecryptFile(fileId, token);

    if (!res.success) {
      setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: res.error, success: false } }));
    } else {
      setDownloadStatus((prev) => ({
        ...prev,
        [fileId]: {
          loading: false,
          success: true,
          savedPath: res.savedPath,
          decryptedSize: res.decryptedSize,
        },
      }));
    }
  };

  // Cycle 6 Share File Handler
  const handleShareFile = async (fileId) => {
    const recipientUserId = shareRecipients[fileId];
    if (!recipientUserId || !token || !window.electronAPI) {
      setShareStatus((prev) => ({ ...prev, [fileId]: { error: 'Please select a recipient user.' } }));
      return;
    }

    const recipient = orgUsers.find((u) => u.id === recipientUserId);
    if (!recipient || !recipient.publicKey) {
      setShareStatus((prev) => ({ ...prev, [fileId]: { error: 'Selected recipient does not have a public key.' } }));
      return;
    }

    setShareStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null, success: null } }));

    const res = await window.electronAPI.shareFile(fileId, recipient.id, recipient.publicKey, token);

    if (!res.success) {
      setShareStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: res.error } }));
    } else {
      setShareStatus((prev) => ({ ...prev, [fileId]: { loading: false, success: `✓ File shared with ${recipient.email}!` } }));
    }
  };

  // Cycle 6 Download Shared File Handler
  const handleDownloadDecryptShared = async (fileId) => {
    if (!token || !currentUser || !window.electronAPI) return;
    setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: true, error: null, success: false } }));

    const res = await window.electronAPI.downloadDecryptSharedFile(fileId, currentUser.id, token);

    if (!res.success) {
      setSharedDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: false, error: res.error, success: false } }));
    } else {
      setSharedDownloadStatus((prev) => ({
        ...prev,
        [fileId]: {
          loading: false,
          success: true,
          savedPath: res.savedPath,
          decryptedSize: res.decryptedSize,
        },
      }));
    }
  };

  if (initializing) {
    return (
      <div className="container" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <p className="subtitle">Initializing SecureVault Security Subsystem...</p>
      </div>
    );
  }

  return (
    <div className="container">
      {/* Top Navbar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.8rem', color: '#f8fafc' }}>SecureVault</h1>
          <span className="subtitle">Zero-Trust E2EE Cloud Storage Client</span>
        </div>
        {token && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
              Identity: <strong style={{ color: cryptoIdentity.protected ? '#10b981' : '#f59e0b' }}>
                {cryptoIdentity.protected ? 'Protected (X25519 SafeStorage)' : 'Unregistered'}
              </strong>
            </span>
            <button className="btn-secondary" onClick={handleLogout} disabled={loading}>
              Sign Out
            </button>
          </div>
        )}
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {successMsg && <div className="alert alert-success">{successMsg}</div>}

      {!token ? (
        <div className="auth-card">
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', borderBottom: '1px solid #334155' }}>
            <button
              className={`tab-btn ${activeTab === 'login' ? 'active' : ''}`}
              onClick={() => { setActiveTab('login'); setError(null); setSuccessMsg(null); }}
            >
              Sign In
            </button>
            <button
              className={`tab-btn ${activeTab === 'register' ? 'active' : ''}`}
              onClick={() => { setActiveTab('register'); setError(null); setSuccessMsg(null); }}
            >
              Create Account
            </button>
          </div>

          {activeTab === 'login' ? (
            <form onSubmit={handleLogin}>
              <div className="form-group">
                <label>Email Address</label>
                <input
                  type="email"
                  className="form-input"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="user@organization.org"
                  required
                />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  className="form-input"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                />
              </div>
              <button type="submit" className="btn-primary" disabled={loading} style={{ width: '100%', marginTop: '1rem' }}>
                {loading ? 'Authenticating...' : 'Sign In'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister}>
              <div className="form-group">
                <label>Organization Name</label>
                <input
                  type="text"
                  className="form-input"
                  value={regOrgName}
                  onChange={(e) => setRegOrgName(e.target.value)}
                  placeholder="Acme Security Corp"
                  required
                />
              </div>
              <div className="form-group">
                <label>Work Email Address</label>
                <input
                  type="email"
                  className="form-input"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="admin@acme.org"
                  required
                />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  className="form-input"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                />
              </div>
              <button type="submit" className="btn-primary" disabled={loading} style={{ width: '100%', marginTop: '1rem' }}>
                {loading ? 'Registering...' : 'Register Account'}
              </button>
            </form>
          )}
        </div>
      ) : (
        <div className="dashboard-grid">
          {/* User & Organization Details */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>Authenticated Account</h2>
                <p className="subtitle">Persistent Session Restored (OS SafeStorage)</p>
              </div>
              <span className={`badge ${currentUser.role === 'ADMIN' ? 'admin' : 'user'}`}>
                {currentUser.role}
              </span>
            </div>

            <div className="detail-row">
              <span className="detail-label">User Email</span>
              <span className="detail-value">{currentUser.email}</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">Organization Name</span>
              <span className="detail-value">{currentOrg?.name}</span>
            </div>
          </div>

          {currentUser.role === 'ADMIN' && (
            <div className="user-card">
              <div className="user-card-header">
                <div>
                  <h2>Organization Users</h2>
                  <p className="subtitle">Admin: create additional users in this organization</p>
                </div>
                <button className="tab-btn" onClick={() => fetchOrgMembers(token)} style={{ border: '1px solid #334155' }}>
                  Refresh List
                </button>
              </div>

              <form onSubmit={handleCreateUser}>
                <div className="form-group">
                  <label>New User Email</label>
                  <input
                    type="email"
                    className="form-input"
                    value={newUserEmail}
                    onChange={(e) => setNewUserEmail(e.target.value)}
                    placeholder="alice@organization.org"
                    required
                  />
                </div>
                <div className="form-group" style={{ marginTop: '0.75rem' }}>
                  <label>Temporary Password</label>
                  <input
                    type="password"
                    className="form-input"
                    value={newUserPassword}
                    onChange={(e) => setNewUserPassword(e.target.value)}
                    placeholder="••••••••"
                    required
                  />
                </div>
                <button type="submit" className="btn-primary" disabled={loading} style={{ marginTop: '1rem' }}>
                  {loading ? 'Creating...' : 'Create User'}
                </button>
              </form>

              {orgMembers.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {orgMembers.map((member) => (
                    <div key={member.id} className="detail-row">
                      <span className="detail-label">{member.email}</span>
                      <span className="detail-value">
                        {member.role}{member.hasPublicKey ? '' : ' · no identity yet'}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                  No organization users loaded.
                </p>
              )}
            </div>
          )}

          {/* Local File Encryption & Cloud Upload Card (Cycle 3 + 4) */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>Local Encryption & Cloud Upload</h2>
                <p className="subtitle">Local AES-256-GCM → Express → Backblaze B2</p>
              </div>
              <button className="btn-primary" onClick={handleSelectFile} disabled={loading}>
                Select File
              </button>
            </div>

            {selectedFile ? (
              <>
                <div className="detail-row">
                  <span className="detail-label">Selected File</span>
                  <span className="detail-value">{selectedFile.fileName} ({selectedFile.fileSize} bytes)</span>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem', flexWrap: 'wrap' }}>
                  <button className="btn-primary" onClick={handleEncryptFile} disabled={loading}>
                    1. Encrypt File Locally
                  </button>

                  {encryptResult && (
                    <button className="btn-primary" onClick={handleDecryptFile} disabled={loading}>
                      2. Test Local Decryption
                    </button>
                  )}

                  {encryptResult && (
                    <button className="btn-primary" onClick={handleUploadCiphertext} disabled={loading} style={{ backgroundColor: '#0284c7' }}>
                      3. Upload Ciphertext to B2
                    </button>
                  )}
                </div>

                {encryptResult && (
                  <div className="detail-row" style={{ marginTop: '0.75rem' }}>
                    <span className="detail-label">Local Encryption</span>
                    <span className="detail-value" style={{ color: '#10b981' }}>✓ Ciphertext generated (AES-256-GCM)</span>
                  </div>
                )}

                {decryptResult && (
                  <div className="detail-row">
                    <span className="detail-label">Local Decryption</span>
                    <span className="detail-value" style={{ color: '#10b981' }}>✓ Decrypted cleanly</span>
                  </div>
                )}

                {integrityResult && (
                  <div className="detail-row">
                    <span className="detail-label">Byte Integrity</span>
                    <span className="detail-value" style={{ color: integrityResult.identical ? '#10b981' : '#ef4444' }}>
                      {integrityResult.identical ? '✓ Original and decrypted files are 100% IDENTICAL' : '❌ Byte mismatch'}
                    </span>
                  </div>
                )}

                {uploadResult && (
                  <div className="detail-row">
                    <span className="detail-label">Cloud B2 Upload</span>
                    <span className="detail-value" style={{ color: '#10b981' }}>
                      ✓ Ciphertext uploaded! Storage Key: {uploadResult.storageKey}
                    </span>
                  </div>
                )}
              </>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                No file selected. Click "Select File" to encrypt locally and upload ciphertext to Backblaze B2.
              </p>
            )}
          </div>

          {/* Persistent Cloud File Listing Card (Cycle 4 + 5 + 6 Sharing) */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>Your Uploaded Encrypted Files</h2>
                <p className="subtitle">Backblaze B2 Storage & E2EE Sharing</p>
              </div>
              <button className="tab-btn" onClick={() => fetchUserFiles(token)} style={{ border: '1px solid #334155' }}>
                Refresh List
              </button>
            </div>

            {fileList.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {fileList.map((file) => {
                  const status = downloadStatus[file.id] || {};
                  const sStatus = shareStatus[file.id] || {};
                  return (
                    <div key={file.id} style={{ padding: '0.75rem', borderRadius: '8px', backgroundColor: '#0f172a', border: '1px solid #334155' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <div>
                          <div style={{ fontWeight: 'bold', fontSize: '0.95rem' }}>{file.originalName}</div>
                          <div className="subtitle">{file.originalSize} bytes</div>
                        </div>
                        <button
                          className="btn-primary"
                          style={{ backgroundColor: '#10b981', padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}
                          disabled={status.loading}
                          onClick={() => handleDownloadDecrypt(file.id)}
                        >
                          {status.loading ? 'Downloading...' : 'Download & Decrypt'}
                        </button>
                      </div>

                      {/* E2EE Sharing Section */}
                      <div style={{ marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px dashed #334155', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <select
                          style={{ flex: 1, padding: '0.35rem', borderRadius: '4px', backgroundColor: '#1e293b', color: '#f8fafc', border: '1px solid #475569', fontSize: '0.85rem' }}
                          value={shareRecipients[file.id] || ''}
                          onChange={(e) => setShareRecipients({ ...shareRecipients, [file.id]: e.target.value })}
                        >
                          <option value="">Select user to share with...</option>
                          {orgUsers.map((user) => (
                            <option key={user.id} value={user.id}>{user.email}</option>
                          ))}
                        </select>
                        <button
                          className="btn-primary"
                          style={{ backgroundColor: '#8b5cf6', padding: '0.35rem 0.75rem', fontSize: '0.85rem' }}
                          disabled={sStatus.loading}
                          onClick={() => handleShareFile(file.id)}
                        >
                          {sStatus.loading ? 'Wrapping...' : 'Share File'}
                        </button>
                      </div>

                      {sStatus.success && (
                        <div style={{ fontSize: '0.8rem', color: '#10b981', marginTop: '0.4rem', backgroundColor: '#064e3b', padding: '0.3rem 0.5rem', borderRadius: '4px' }}>
                          {sStatus.success}
                        </div>
                      )}
                      {sStatus.error && (
                        <div style={{ fontSize: '0.8rem', color: '#f87171', marginTop: '0.4rem', backgroundColor: '#7f1d1d', padding: '0.3rem 0.5rem', borderRadius: '4px' }}>
                          ❌ {sStatus.error}
                        </div>
                      )}

                      {status.success && (
                        <div style={{ fontSize: '0.8rem', color: '#10b981', marginTop: '0.4rem', backgroundColor: '#064e3b', padding: '0.4rem', borderRadius: '4px' }}>
                          ✓ Downloaded from B2 & Decrypted to: <strong>{status.savedPath}</strong> ({status.decryptedSize} bytes)
                        </div>
                      )}
                      {status.error && (
                        <div style={{ fontSize: '0.8rem', color: '#f87171', marginTop: '0.4rem', backgroundColor: '#7f1d1d', padding: '0.4rem', borderRadius: '4px' }}>
                          ❌ {status.error}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                No files uploaded yet.
              </p>
            )}
          </div>

          {/* Files Shared With Me Card (Cycle 6) */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>Files Shared With Me</h2>
                <p className="subtitle">E2EE Shared Files (Per-User DEK Unwrapping)</p>
              </div>
              <button className="tab-btn" onClick={() => fetchSharedFiles(token)} style={{ border: '1px solid #334155' }}>
                Refresh List
              </button>
            </div>

            {sharedFileList.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {sharedFileList.map((file) => {
                  const status = sharedDownloadStatus[file.id] || {};
                  return (
                    <div key={file.id} style={{ padding: '0.75rem', borderRadius: '8px', backgroundColor: '#0f172a', border: '1px solid #334155' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <div>
                          <div style={{ fontWeight: 'bold', fontSize: '0.95rem' }}>{file.originalName}</div>
                          <div className="subtitle">Shared by: {file.ownerEmail} | {file.originalSize} bytes</div>
                        </div>
                        <button
                          className="btn-primary"
                          style={{ backgroundColor: '#8b5cf6', padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}
                          disabled={status.loading}
                          onClick={() => handleDownloadDecryptShared(file.id)}
                        >
                          {status.loading ? 'Unwrapping...' : 'Download & Decrypt'}
                        </button>
                      </div>

                      {status.success && (
                        <div style={{ fontSize: '0.8rem', color: '#10b981', marginTop: '0.4rem', backgroundColor: '#064e3b', padding: '0.4rem', borderRadius: '4px' }}>
                          ✓ Unwrapped DEK & Decrypted to: <strong>{status.savedPath}</strong> ({status.decryptedSize} bytes)
                        </div>
                      )}
                      {status.error && (
                        <div style={{ fontSize: '0.8rem', color: '#f87171', marginTop: '0.4rem', backgroundColor: '#7f1d1d', padding: '0.4rem', borderRadius: '4px' }}>
                          ❌ {status.error}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                No files shared with you yet.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
