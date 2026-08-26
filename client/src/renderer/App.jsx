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
      setLoading(false);
      setSuccessMsg(null);
      setError(null);
    }
  };

  // --- Cycle 3 File Encryption Handlers ---
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
      // Automatically verify byte-for-byte integrity
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

  const handleRunTamperTest = async () => {
    if (!encryptResult) return;
    setLoading(true);
    const tamperRes = await window.electronAPI.testTamper(encryptResult.fileId);
    setTamperTestResult(tamperRes);
    setLoading(false);
  };

  const handleRunDoubleEncryptTest = async () => {
    if (!selectedFile) return;
    setLoading(true);
    const doubleRes = await window.electronAPI.testDoubleEncrypt(selectedFile.filePath);
    setDoubleEncResult(doubleRes);
    setLoading(false);
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
            <p className="subtitle">Cycle 3 — Basic Local File Encryption (AES-256-GCM)</p>
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

          {/* Cryptographic Identity Card (Cycle 2) */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>Cryptographic Identity</h2>
                <p className="subtitle">Local X25519 Key Pair & OS Protection</p>
              </div>
            </div>

            <div className="detail-row">
              <span className="detail-label">Private Key Protection</span>
              <span className="detail-value" style={{ color: '#10b981' }}>
                {cryptoIdentity.protected ? '✓ Protected (OS SafeStorage)' : '❌ Not Protected'}
              </span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Public Identity</span>
              <span className="detail-value" style={{ color: '#10b981' }}>
                {cryptoIdentity.registered ? '✓ Registered (PostgreSQL)' : '❌ Not Registered'}
              </span>
            </div>
          </div>

          {/* Local File Encryption Card (Cycle 3) */}
          <div className="user-card">
            <div className="user-card-header">
              <div>
                <h2>SecureVault — File Encryption</h2>
                <p className="subtitle">Local AES-256-GCM Encryption with Fresh Memory DEK</p>
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
                    1. Encrypt File
                  </button>

                  {encryptResult && (
                    <button className="btn-primary" onClick={handleDecryptFile} disabled={loading}>
                      2. Decrypt & Verify Byte Integrity
                    </button>
                  )}

                  {encryptResult && (
                    <button className="btn-danger" onClick={handleRunTamperTest} disabled={loading}>
                      3. Test Tamper Failure
                    </button>
                  )}

                  <button className="tab-btn" onClick={handleRunDoubleEncryptTest} disabled={loading} style={{ border: '1px solid #334155' }}>
                    4. Test Randomness (Double Encrypt)
                  </button>
                </div>

                {encryptResult && (
                  <div className="detail-row" style={{ marginTop: '0.75rem' }}>
                    <span className="detail-label">Encryption</span>
                    <span className="detail-value" style={{ color: '#10b981' }}>✓ Complete (AES-256-GCM)</span>
                  </div>
                )}

                {decryptResult && (
                  <div className="detail-row">
                    <span className="detail-label">Decryption</span>
                    <span className="detail-value" style={{ color: '#10b981' }}>✓ Complete</span>
                  </div>
                )}

                {integrityResult && (
                  <div className="detail-row">
                    <span className="detail-label">Byte-for-Byte Integrity</span>
                    <span className="detail-value" style={{ color: integrityResult.identical ? '#10b981' : '#ef4444' }}>
                      {integrityResult.identical ? '✓ Original and decrypted files are IDENTICAL (SHA-256 match)' : '❌ Mismatched bytes!'}
                    </span>
                  </div>
                )}

                {tamperTestResult && (
                  <div className="detail-row">
                    <span className="detail-label">Tamper Auth Check</span>
                    <span className="detail-value" style={{ color: tamperTestResult.caughtTampering ? '#10b981' : '#ef4444' }}>
                      {tamperTestResult.caughtTampering ? `✓ Caught Tampering! Exception: "${tamperTestResult.errorMessage}"` : '❌ Failed to detect tampering!'}
                    </span>
                  </div>
                )}

                {doubleEncResult && (
                  <div className="detail-row">
                    <span className="detail-label">CSPRNG Nonce Randomness</span>
                    <span className="detail-value" style={{ color: doubleEncResult.uniqueCiphertexts ? '#10b981' : '#ef4444' }}>
                      {doubleEncResult.uniqueCiphertexts ? '✓ Double Encryption produced 2 unique IVs & distinct ciphertexts' : '❌ Reused IV/Ciphertext!'}
                    </span>
                  </div>
                )}
              </>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                No file selected. Click "Select File" to test local AES-256-GCM encryption.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
