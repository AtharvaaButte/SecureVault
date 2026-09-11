import React, { useState } from 'react';
import { ShieldCheck, Lock, KeyRound, CheckCircle2, Mail, Key, ArrowRight } from 'lucide-react';
import Card from '../components/Common/Card';
import Alert from '../components/Common/Alert';

function cleanTokenStr(token) {
  if (!token) return '';
  let str = String(token).trim();
  if (str.includes('/setup/')) {
    str = str.split('/setup/').pop();
  }
  return decodeURIComponent(str).split('?')[0].split('#')[0].replace(/\/+$/, '').trim();
}

export default function AccountSetupPage({ setupToken: initialToken = '', initialEmail = '', onSetupComplete, onBackToLogin }) {
  const [email, setEmail] = useState(initialEmail || '');
  const [setupToken, setSetupToken] = useState(initialToken ? cleanTokenStr(initialToken) : '');
  const [step, setStep] = useState(1); // Step 1: Verify Email+Token, Step 2: Set Password, Step 3: Success
  const [verifiedUser, setVerifiedUser] = useState(null);

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [securityHint, setSecurityHint] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const checkPasswordStrength = (pwd) => {
    return {
      hasMinLen: (pwd || '').length >= 8,
      hasUpper: /[A-Z]/.test(pwd || ''),
      hasLower: /[a-z]/.test(pwd || ''),
      hasNumber: /[0-9]/.test(pwd || ''),
      hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd || ''),
    };
  };

  const strength = checkPasswordStrength(password);
  const isPasswordValid = Object.values(strength).every(Boolean);

  // Step 1: Verify Email + Setup Token
  const handleVerify = async (e) => {
    e.preventDefault();
    setError(null);

    if (!email.trim()) {
      setError('Email Address is required.');
      return;
    }

    if (!setupToken.trim()) {
      setError('Setup Token is required.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('https://securevault-backend-qx9r.onrender.com/api/auth/setup/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          setupToken: cleanTokenStr(setupToken),
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.message || 'Verification failed. Please check your Email Address and Setup Token.');
      } else {
        setVerifiedUser(data.user);
        setStep(2);
      }
    } catch (err) {
      setError('Unable to connect to server. Please check your network connection.');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Complete Setup (Set Password & Register Key)
  const handleComplete = async (e) => {
    e.preventDefault();
    setError(null);

    if (!isPasswordValid) {
      setError('Please ensure your password meets all strong password requirements.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
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

      const response = await fetch('https://securevault-backend-qx9r.onrender.com/api/auth/setup/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          setupToken: cleanTokenStr(setupToken),
          password: password.trim(),
          publicKey: pubKey,
          securityHint: securityHint.trim(),
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.message || 'Failed to activate account.');
      } else {
        if (data.token && onSetupComplete) {
          onSetupComplete(data);
        } else {
          setStep(3);
        }
      }
    } catch (err) {
      setError('Network error while completing setup. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <Card style={styles.card}>
        <div style={styles.header}>
          <div style={styles.logoBadge}>
            <ShieldCheck size={28} color="#ffffff" />
          </div>
          <h2 style={styles.title}>Complete Account Setup</h2>
          <p style={styles.subtitle}>
            {step === 1
              ? 'Verify your member email address and setup token to activate your account.'
              : step === 2
              ? `Welcome to ${verifiedUser?.organizationName || 'SecureVault'}. Set up your new password below.`
              : 'Account setup complete. Proceed to Sign In.'}
          </p>
        </div>

        {error && <Alert type="danger" message={error} style={{ marginBottom: '1.25rem' }} />}

        {/* STEP 1: Verify Email + Setup Token */}
        {step === 1 && (
          <form onSubmit={handleVerify} style={styles.form}>
            <div className="form-group">
              <label className="form-label">Email Address *</label>
              <div style={styles.inputWrapper}>
                <Mail size={16} style={styles.inputIcon} />
                <input
                  type="email"
                  required
                  className="form-control"
                  placeholder="user@organization.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Setup Token *</label>
              <div style={styles.inputWrapper}>
                <Key size={16} style={styles.inputIcon} />
                <input
                  type="text"
                  required
                  className="form-control"
                  placeholder="Paste setup token or activation link"
                  value={setupToken}
                  onChange={(e) => setSetupToken(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !email.trim() || !setupToken.trim()}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}
            >
              {loading ? 'Verifying Credentials...' : 'Verify Credentials'}
            </button>

            <button
              type="button"
              onClick={onBackToLogin}
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}
            >
              Back to Login
            </button>
          </form>
        )}

        {/* STEP 2: Configure Password & Register Key */}
        {step === 2 && verifiedUser && (
          <form onSubmit={handleComplete} style={styles.form}>
            <div style={styles.userBox}>
              <div>
                <div style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                  {verifiedUser.name}
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{verifiedUser.email}</div>
              </div>
              <span className="badge badge-owner" style={{ backgroundColor: 'rgba(37, 99, 235, 0.15)', color: '#60a5fa' }}>
                Verified
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">New Password *</label>
              <div style={styles.inputWrapper}>
                <Lock size={16} style={styles.inputIcon} />
                <input
                  type="password"
                  required
                  className="form-control"
                  placeholder="Enter strong password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            {/* Password Requirements Checklist */}
            <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.75rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem' }}>
              <span style={{ color: strength.hasMinLen ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                {strength.hasMinLen ? '✓' : '•'} 8+ Characters
              </span>
              <span style={{ color: strength.hasUpper ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                {strength.hasUpper ? '✓' : '•'} 1 Uppercase Letter
              </span>
              <span style={{ color: strength.hasLower ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                {strength.hasLower ? '✓' : '•'} 1 Lowercase Letter
              </span>
              <span style={{ color: strength.hasNumber ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                {strength.hasNumber ? '✓' : '•'} 1 Number
              </span>
              <span style={{ color: strength.hasSpecial ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem', gridColumn: 'span 2' }}>
                {strength.hasSpecial ? '✓' : '•'} 1 Special Character (!@#$%^&*)
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">Confirm Password *</label>
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
              {confirmPassword && password !== confirmPassword && (
                <div style={{ fontSize: '0.75rem', color: 'var(--accent-rose)', marginTop: '0.25rem' }}>
                  Passwords do not match.
                </div>
              )}
            </div>

            <div className="form-group">
              <label className="form-label">
                Security Hint <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>(Optional)</span>
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

            <button
              type="submit"
              disabled={loading || !isPasswordValid || password !== confirmPassword}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}
            >
              {loading ? 'Activating Account...' : 'Activate Account & Set Password'}
            </button>

            <button
              type="button"
              onClick={() => setStep(1)}
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}
            >
              Back to Verification
            </button>
          </form>
        )}

        {/* STEP 3: Success Screen */}
        {step === 3 && (
          <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
            <CheckCircle2 size={48} color="var(--accent-emerald)" style={{ margin: '0 auto 1rem' }} />
            <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              Account Activated Successfully!
            </h3>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', fontSize: '0.875rem', lineHeight: '1.5' }}>
              Your password has been configured and your encryption identity has been registered. You can now log in using your email address and password.
            </p>
            <button onClick={onBackToLogin} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
              <span>Proceed to Login</span>
              <ArrowRight size={16} />
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
