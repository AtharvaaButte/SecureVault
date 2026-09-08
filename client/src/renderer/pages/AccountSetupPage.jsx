import React, { useState, useEffect } from 'react';
import { ShieldCheck, Lock, KeyRound, CheckCircle2, AlertCircle, ArrowRight } from 'lucide-react';
import Card from '../components/Common/Card';
import Alert from '../components/Common/Alert';

export default function AccountSetupPage({ setupToken, onSetupComplete, onBackToLogin }) {
  const [tokenInfo, setTokenInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [securityHint, setSecurityHint] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (!setupToken) {
      setError('Account setup token is missing.');
      setLoading(false);
      return;
    }

    const checkToken = async () => {
      try {
        const response = await fetch(`http://localhost:5000/api/auth/setup/${setupToken}`);
        const data = await response.json();

        if (!response.ok) {
          setError(data.message || 'Invalid or expired account setup link.');
        } else {
          setTokenInfo(data.user);
        }
      } catch (err) {
        setError('Unable to connect to authentication server. Please check your network connection.');
      } finally {
        setLoading(false);
      }
    };

    checkToken();
  }, [setupToken]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      let pubKey = null;
      if (window.electronAPI && typeof window.electronAPI.ensureIdentity === 'function') {
        const ensured = await window.electronAPI.ensureIdentity();
        if (ensured && ensured.publicKey) {
          pubKey = ensured.publicKey;
        }
      }

      if (!pubKey) {
        pubKey = `-----BEGIN PUBLIC KEY-----\nMCowKOYDK2VuA3IBAE${Buffer.from(String(Date.now())).toString('base64')}\n-----END PUBLIC KEY-----`;
      }

      const response = await fetch(`http://localhost:5000/api/auth/setup/${setupToken}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, publicKey: pubKey, securityHint }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.message || 'Failed to activate account.');
      } else {
        setSuccess(true);
        if (onSetupComplete) onSetupComplete();
      }
    } catch (err) {
      setError('Network error while completing setup. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div style={styles.container}>
        <Card style={styles.card}>
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <div className="spinner" style={{ margin: '0 auto 1rem' }}></div>
            <p style={{ color: 'var(--text-secondary)' }}>Validating account setup link...</p>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <Card style={styles.card}>
        <div style={styles.header}>
          <div style={styles.logoBadge}>
            <ShieldCheck size={28} color="#ffffff" />
          </div>
          <h2 style={styles.title}>Activate Account</h2>
          <p style={styles.subtitle}>
            Welcome to <strong>{tokenInfo?.organizationName || 'SecureVault'}</strong>. Set up your password to activate your account.
          </p>
        </div>

        {error && <Alert type="danger" message={error} style={{ marginBottom: '1.25rem' }} />}

        {success ? (
          <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
            <CheckCircle2 size={48} color="var(--accent-emerald)" style={{ margin: '0 auto 1rem' }} />
            <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              Account Activated Successfully!
            </h3>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
              Your password has been configured. You can now log in to your vault workspace.
            </p>
            <button onClick={onBackToLogin} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
              <span>Proceed to Login</span>
              <ArrowRight size={16} />
            </button>
          </div>
        ) : tokenInfo ? (
          <form onSubmit={handleSubmit} style={styles.form}>
            {/* User Metadata Overview */}
            <div style={styles.userBox}>
              <div>
                <div style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-primary)' }}>{tokenInfo.name}</div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{tokenInfo.email}</div>
              </div>
              <span className="badge badge-owner" style={{ backgroundColor: 'rgba(37, 99, 235, 0.15)', color: '#60a5fa' }}>
                Pending Activation
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">New Password</label>
              <div style={styles.inputWrapper}>
                <Lock size={16} style={styles.inputIcon} />
                <input
                  type="password"
                  required
                  className="form-control"
                  placeholder="Enter secure password (min 6 chars)"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Confirm Password</label>
              <div style={styles.inputWrapper}>
                <Lock size={16} style={styles.inputIcon} />
                <input
                  type="password"
                  required
                  className="form-control"
                  placeholder="Re-enter password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">
                Security / Memory Hint <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>(Optional)</span>
              </label>
              <div style={styles.inputWrapper}>
                <KeyRound size={16} style={styles.inputIcon} />
                <input
                  type="text"
                  className="form-control"
                  placeholder="Optional hint (e.g. Favorite book title)"
                  value={securityHint}
                  onChange={(e) => setSecurityHint(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            <button type="submit" disabled={submitting} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}>
              {submitting ? 'Activating Account...' : 'Complete Account Setup'}
            </button>

            <button type="button" onClick={onBackToLogin} className="btn btn-secondary" style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}>
              Back to Login
            </button>
          </form>
        ) : (
          <div style={{ textAlign: 'center', marginTop: '1rem' }}>
            <button onClick={onBackToLogin} className="btn btn-secondary" style={{ width: '100%', justifyContent: 'center' }}>
              Back to Login
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}

const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'var(--bg-dark-root)',
    padding: '2rem 1rem',
  },
  card: {
    width: '100%',
    maxWidth: '460px',
    padding: '2rem',
  },
  header: {
    textAlign: 'center',
    marginBottom: '1.75rem',
  },
  logoBadge: {
    width: '48px',
    height: '48px',
    borderRadius: '12px',
    background: 'linear-gradient(135deg, #2563eb 0%, #0284c7 100%)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 1rem',
    boxShadow: '0 4px 16px rgba(37, 99, 235, 0.4)',
  },
  title: {
    fontSize: '1.35rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '0.35rem',
  },
  subtitle: {
    fontSize: '0.85rem',
    color: 'var(--text-secondary)',
    lineHeight: '1.4',
  },
  userBox: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.85rem 1rem',
    backgroundColor: 'var(--bg-dark-input)',
    borderRadius: '8px',
    border: '1px solid var(--border-color)',
    marginBottom: '1.25rem',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  inputWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
  },
  inputIcon: {
    position: 'absolute',
    left: '0.85rem',
    color: 'var(--text-muted)',
    pointerEvents: 'none',
  },
};
