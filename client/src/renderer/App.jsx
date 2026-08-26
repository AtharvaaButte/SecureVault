import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  
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

  // Auto restore session on app launch
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
          } else {
            // Token expired or invalid
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

      // Persist session securely in OS storage
      if (window.electronAPI && typeof window.electronAPI.saveSession === 'function') {
        await window.electronAPI.saveSession(data.token);
      }

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

      // Persist session securely in OS storage
      if (window.electronAPI && typeof window.electronAPI.saveSession === 'function') {
        await window.electronAPI.saveSession(data.token);
      }

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
      setLoading(false);
      setSuccessMsg(null);
      setError(null);
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
            <p className="subtitle">Cycle 1 — Account & Organization Management</p>
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
              <span className="detail-label">User ID</span>
              <span className="detail-value">{currentUser.id}</span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Organization Name</span>
              <span className="detail-value">{currentOrg?.name}</span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Organization ID</span>
              <span className="detail-value">{currentOrg?.id}</span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Assigned Role</span>
              <span className="detail-value">{currentUser.role}</span>
            </div>

            <div className="detail-row">
              <span className="detail-label">Account Created</span>
              <span className="detail-value">{new Date(currentUser.createdAt).toLocaleString()}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
