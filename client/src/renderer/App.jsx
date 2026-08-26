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
  const [tamperTestResult, setTamperTestResult] = useState(null);
  const [doubleEncResult, setDoubleEncResult] = useState(null);

  // Cycle 4 Cloud Upload & File Listing state
  const [uploadResult, setUploadResult] = useState(null);
  const [fileList, setFileList] = useState([]);

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
        let savedToken = null;
        if (window.electronAPI && typeof window.electronAPI.getSession === 'function') {
          savedToken = await window.electronAPI.getSession();
        }

        if (savedToken) {
          const res = await fetch(`${API_BASE}/auth/me`, {
            headers: {
              'Authorization': `Bearer ${savedToken}`,
            },
          });

          if (res.ok) {
            const data = await res.json();
            setToken(savedToken);
            setCurrentUser(data.user);
            setCurrentOrg(data.organization);

            await syncCryptographicIdentity(savedToken);
            await fetchUserFiles(savedToken);
          } else {
            if (window.electronAPI && typeof window.electronAPI.clearSession === 'function') {
              await window.electronAPI.clearSession();
            }
          }
        }
      } catch (err) {
        console.error('[Session Restore Failed]:', err.message);
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

      if (!res.ok) {
        throw new Error(data.message || 'Registration failed.');
      }

      setToken(data.token);
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);

      if (window.electronAPI && typeof window.electronAPI.saveSession === 'function') {
        await window.electronAPI.saveSession(data.token);
      }

      await syncCryptographicIdentity(data.token);
      await fetchUserFiles(data.token);
      setSuccessMsg('Organization and Admin account registered successfully!');
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

      if (!res.ok) {
        throw new Error(data.message || 'Authentication failed.');
      }

      setToken(data.token);
      setCurrentUser(data.user);
      setCurrentOrg(data.organization);

      if (window.electronAPI && typeof window.electronAPI.saveSession === 'function') {
        await window.electronAPI.saveSession(data.token);
      }

      await syncCryptographicIdentity(data.token);
      await fetchUserFiles(data.token);
      setSuccessMsg('Logged in successfully!');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE}/auth/logout`, { method: 'POST' });
      if (window.electronAPI && typeof window.electronAPI.clearSession === 'function') {
        await window.electronAPI.clearSession();
      }
    } catch (err) {
      console.error('[Logout Error]:', err.message);
    } finally {
      setToken(null);
      setCurrentUser(null);
      setCurrentOrg(null);
      setCryptoIdentity({ protected: false, registered: false, publicKey: null });
      setSelectedFile(null);
      setEncryptResult(null);
      setDecryptResult(null);
      setIntegrityResult(null);
      setTamperTestResult(null);
      setDoubleEncResult(null);
      setUploadResult(null);
      setFileList([]);
      setLoading(false);
      setSuccessMsg(null);
      setError(null);
    }
  };

  // --- Cycle 3 & 4 Handlers ---
  const handleSelectFile = async () => {
    if (!window.electronAPI || typeof window.electronAPI.selectFile !== 'function') return;
    const file = await window.electronAPI.selectFile();
    if (file) {
      setSelectedFile(file);
      setEncryptResult(null);
      setDecryptResult(null);
      setIntegrityResult(null);
      setTamperTestResult(null);
      setDoubleEncResult(null);
      setUploadResult(null);
    }
  };

  const handleEncryptFile = async () => {
    if (!selectedFile) return;
    setLoading(true);
    const res = await window.electronAPI.encryptFile(selectedFile.filePath);
    if (res.success) {
      setEncryptResult(res);
    } else {
      setError(res.error || 'Encryption failed.');
    }
    setLoading(false);
  };

  const handleDecryptFile = async () => {
    if (!encryptResult) return;
    setLoading(true);
    const decRes = await window.electronAPI.decryptFile(encryptResult.fileId);
    if (decRes.success) {
      setDecryptResult(decRes);
      const verifyRes = await window.electronAPI.verifyIntegrity(
        encryptResult.originalPath,
        decRes.decryptedPath
      );
      setIntegrityResult(verifyRes);
    } else {
      setError(decRes.error || 'Decryption failed.');
    }
    setLoading(false);
  };

  const handleUploadCiphertext = async () => {
    if (!encryptResult || !token) return;
    setLoading(true);
    setError(null);

    const upRes = await window.electronAPI.uploadCiphertext(encryptResult.fileId, token);
    if (upRes.success) {
      setUploadResult(upRes.file);
      await fetchUserFiles(token);
    } else {
      setError(upRes.error || 'Cloud upload failed.');
    }
    setLoading(false);
  };

  const [downloadStatus, setDownloadStatus] = useState({});

  const handleDownloadDecrypt = async (fileId) => {
    if (!token) return;
    setDownloadStatus((prev) => ({ ...prev, [fileId]: { loading: true } }));
    setError(null);
    setSuccessMsg(null);

    const res = await window.electronAPI.downloadDecryptFile(fileId, token);
    if (res.success) {
      setDownloadStatus((prev) => ({
        ...prev,
        [fileId]: {
          loading: false,
          success: true,
          savedPath: res.savedPath,
          originalName: res.originalName,
          decryptedSize: res.decryptedSize,
        },
      }));
      setSuccessMsg(`✓ File "${res.originalName}" downloaded from B2, decrypted locally, and saved to: ${res.savedPath}`);
    } else {
      setDownloadStatus((prev) => ({
        ...prev,
        [fileId]: { loading: false, success: false, error: res.error },
      }));
      setError(res.error || 'Download/decryption failed.');
    }
  };

  if (initializing) {
    return (
      <div className="container" style={{ textAlign: 'center', paddingTop: '4rem' }}>
        <h2 style={{ color: '#94a3b8' }}>Restoring SecureVault session...</h2>
      </div>
    );
  }

  return (
    <div className="container">
      <header className="header">
        <div className="title-group">
          <div className="logo-badge">SV</div>
          <div>
            <h1>SecureVault</h1>
            <p className="subtitle">Cycle 5 — E2EE Cloud Storage: Download & Local Decryption</p>
          </div>
        </div>

        {currentUser && (
          <button className="btn-danger" onClick={handleLogout} disabled={loading}>
            Logout
          </button>
        )}
      </header>

      {error && <div className="alert-error" style={{ marginBottom: '1rem' }}>{error}</div>}
      {successMsg && <div className="alert-success" style={{ marginBottom: '1rem' }}>{successMsg}</div>}

      {!currentUser ? (
        <div className="auth-card">
          <div className="tabs">
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
              Register Organization
            </button>
          </div>

          {activeTab === 'login' ? (
            <form className="auth-form" onSubmit={handleLogin}>
              <div className="form-group">
                <label>Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="admin@organization.com"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                />
              </div>

              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Authenticating...' : 'Sign In'}
              </button>
            </form>
          ) : (
            <form className="auth-form" onSubmit={handleRegister}>
              <div className="form-group">
                <label>Organization Name</label>
                <input
                  type="text"
                  required
                  placeholder="Acme Corporation"
                  value={regOrgName}
                  onChange={(e) => setRegOrgName(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Admin Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="admin@acme.com"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Master Account Password</label>
                <input
                  type="password"
                  required
                  minLength={6}
                  placeholder="••••••••••••"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                />
              </div>

              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Creating Account...' : 'Register & Create Organization'}
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

          {/* Persistent Cloud File Listing Card (Cycle 4 + 5) */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>Your Uploaded Encrypted Files</h2>
                <p className="subtitle">Backblaze B2 Storage & Local Decryption</p>
              </div>
              <button className="tab-btn" onClick={() => fetchUserFiles(token)} style={{ border: '1px solid #334155' }}>
                Refresh List
              </button>
            </div>

            {fileList.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {fileList.map((file) => {
                  const status = downloadStatus[file.id] || {};
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
                      <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                        Key: {file.storageKey} | Algo: {file.algorithm}
                      </div>
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
        </div>
      )}
    </div>
  );
}
