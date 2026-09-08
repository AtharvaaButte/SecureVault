import React, { useState } from 'react';
import { UserPlus, Mail, User, Lock, Link, Check, Copy } from 'lucide-react';
import Modal from '../Common/Modal';
import Alert from '../Common/Alert';

export default function CreateUserModal({ isOpen, onClose, onCreateUser, availableRoles }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [useSetupLink, setUseSetupLink] = useState(true);
  const [selectedRoleIds, setSelectedRoleIds] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [createdUserResult, setCreatedUserResult] = useState(null);
  const [copiedLink, setCopiedLink] = useState(false);

  if (!isOpen) return null;

  const handleToggleRole = (roleId) => {
    setSelectedRoleIds((prev) =>
      prev.includes(roleId) ? prev.filter((id) => id !== roleId) : [...prev, roleId]
    );
  };

  const checkPasswordStrength = (pwd) => {
    return {
      hasMinLen: (pwd || '').length >= 8,
      hasUpper: /[A-Z]/.test(pwd || ''),
      hasLower: /[a-z]/.test(pwd || ''),
      hasNumber: /[0-9]/.test(pwd || ''),
      hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd || ''),
    };
  };

  const pwdStrength = checkPasswordStrength(password);
  const isPwdValid = Object.values(pwdStrength).every(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError('Full name is required.');
      return;
    }

    if (!email.trim()) {
      setError('Email address is required.');
      return;
    }

    if (!useSetupLink && !isPwdValid) {
      setError('Initial password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character.');
      return;
    }

    if (!selectedRoleIds || selectedRoleIds.length === 0) {
      setError('Please select at least one role.');
      return;
    }

    setSubmitting(true);
    const payload = {
      name: name.trim(),
      email: email.trim().toLowerCase(),
      roleIds: selectedRoleIds,
      ...(useSetupLink ? {} : { password: password.trim() }),
    };

    const res = await onCreateUser(payload);
    setSubmitting(false);

    if (res.success) {
      if (res.user?.setupToken) {
        setCreatedUserResult(res.user);
      } else {
        handleResetAndClose();
      }
    } else {
      setError(res.error || 'Failed to create user account.');
    }
  };

  const handleResetAndClose = () => {
    setName('');
    setEmail('');
    setPassword('');
    setUseSetupLink(true);
    setSelectedRoleIds([]);
    setError(null);
    setCreatedUserResult(null);
    setCopiedLink(false);
    onClose();
  };

  const copySetupLink = () => {
    if (!createdUserResult?.setupToken) return;
    const fullUrl = `${window.location.origin}/setup/${createdUserResult.setupToken}`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 3000);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleResetAndClose}
      title="Create Organization Member"
    >
      {createdUserResult ? (
        <div style={{ padding: '0.5rem 0' }}>
          <Alert
            type="success"
            message={`User account for ${createdUserResult.name} was created with pending setup link.`}
            style={{ marginBottom: '1.25rem' }}
          />

          <div style={styles.tokenBox}>
            <div style={styles.tokenLabel}>Account Setup Token</div>
            <div style={styles.tokenValue}>{createdUserResult.setupToken}</div>
            <div style={styles.tokenHint}>
              Share this setup token with <strong>{createdUserResult.name}</strong> to allow them to activate their account and set a password.
            </div>
            <button
              type="button"
              onClick={copySetupLink}
              className="btn btn-secondary btn-sm"
              style={{ marginTop: '0.75rem', width: '100%', justifyContent: 'center' }}
            >
              {copiedLink ? <Check size={16} color="var(--accent-emerald)" /> : <Copy size={16} />}
              <span>{copiedLink ? 'Setup Token Copied!' : 'Copy Setup Token'}</span>
            </button>
          </div>

          <div style={{ marginTop: '1.5rem', textAlign: 'right' }}>
            <button onClick={handleResetAndClose} className="btn btn-primary">
              Done
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {error && <Alert type="danger" message={error} />}

          <div className="form-group">
            <label className="form-label">
              Full Name <span style={{ color: 'var(--accent-red)' }}>*</span>
            </label>
            <div style={styles.inputWrapper}>
              <User size={16} style={styles.inputIcon} />
              <input
                type="text"
                required
                className="form-control"
                placeholder="e.g. Atharva Butte"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={{ paddingLeft: '2.5rem' }}
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">
              Email Address <span style={{ color: 'var(--accent-red)' }}>*</span>
            </label>
            <div style={styles.inputWrapper}>
              <Mail size={16} style={styles.inputIcon} />
              <input
                type="email"
                required
                className="form-control"
                placeholder="e.g. user@organization.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{ paddingLeft: '2.5rem' }}
              />
            </div>
          </div>

          {/* Account Activation Mode Selection */}
          <div className="form-group">
            <label className="form-label">Account Setup Method</label>
            <div style={styles.radioGroup}>
              <label style={{ ...styles.radioLabel, ...(useSetupLink ? styles.radioSelected : {}) }}>
                <input
                  type="radio"
                  name="setupMethod"
                  checked={useSetupLink}
                  onChange={() => setUseSetupLink(true)}
                />
                <div>
                  <div style={{ fontWeight: '600', fontSize: '0.85rem' }}>Send Account Setup Link (Recommended)</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    User receives a setup token and activates their account by setting their own password.
                  </div>
                </div>
              </label>

              <label style={{ ...styles.radioLabel, ...(!useSetupLink ? styles.radioSelected : {}) }}>
                <input
                  type="radio"
                  name="setupMethod"
                  checked={!useSetupLink}
                  onChange={() => setUseSetupLink(false)}
                />
                <div>
                  <div style={{ fontWeight: '600', fontSize: '0.85rem' }}>Set Password Directly</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Admin specifies an initial password for immediate account activation.
                  </div>
                </div>
              </label>
            </div>
          </div>

          {!useSetupLink && (
            <div className="form-group">
              <label className="form-label">
                Initial Password <span style={{ color: 'var(--accent-red)' }}>*</span>
              </label>
              <div style={styles.inputWrapper}>
                <Lock size={16} style={styles.inputIcon} />
                <input
                  type="password"
                  required
                  className="form-control"
                  placeholder="Enter initial strong password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>

              {/* Password Requirements Checklist */}
              <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '0.65rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.725rem', marginTop: '0.5rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.35rem' }}>
                <span style={{ color: pwdStrength.hasMinLen ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  {pwdStrength.hasMinLen ? '✓' : '•'} 8+ Characters
                </span>
                <span style={{ color: pwdStrength.hasUpper ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  {pwdStrength.hasUpper ? '✓' : '•'} 1 Uppercase Letter
                </span>
                <span style={{ color: pwdStrength.hasLower ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  {pwdStrength.hasLower ? '✓' : '•'} 1 Lowercase Letter
                </span>
                <span style={{ color: pwdStrength.hasNumber ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  {pwdStrength.hasNumber ? '✓' : '•'} 1 Number
                </span>
                <span style={{ color: pwdStrength.hasSpecial ? 'var(--accent-emerald)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.3rem', gridColumn: 'span 2' }}>
                  {pwdStrength.hasSpecial ? '✓' : '•'} 1 Special Character (!@#$%^&*)
                </span>
              </div>
            </div>
          )}

          {/* Organization Roles Checklist */}
          {availableRoles && availableRoles.length > 0 && (
            <div className="form-group">
              <label className="form-label">
                Role(s) <span style={{ color: 'var(--accent-red)' }}>*</span>
              </label>
              <div style={styles.rolesBox}>
                {availableRoles.map((role) => {
                  const isChecked = selectedRoleIds.includes(role.id);
                  return (
                    <label key={role.id} style={styles.roleCheckboxLabel}>
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleToggleRole(role.id)}
                      />
                      <div>
                        <span style={{ fontWeight: '600', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                          {role.name}
                        </span>
                        {role.description && (
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{role.description}</div>
                        )}
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          )}

          <div style={styles.modalFooter}>
            <button type="button" onClick={handleResetAndClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={submitting} className="btn btn-primary">
              {submitting ? 'Creating User...' : 'Create Member Account'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

const styles = {
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
  radioGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  radioLabel: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.75rem',
    padding: '0.75rem 0.85rem',
    borderRadius: '8px',
    border: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-dark-input)',
    cursor: 'pointer',
  },
  radioSelected: {
    borderColor: 'var(--accent-blue)',
    backgroundColor: 'rgba(37, 99, 235, 0.08)',
  },
  rolesBox: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    maxHeight: '160px',
    overflowY: 'auto',
    padding: '0.5rem',
    backgroundColor: 'var(--bg-dark-input)',
    borderRadius: '8px',
    border: '1px solid var(--border-color)',
  },
  roleCheckboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    cursor: 'pointer',
    padding: '0.25rem 0.4rem',
  },
  tokenBox: {
    padding: '1.25rem',
    backgroundColor: 'var(--bg-dark-input)',
    borderRadius: '8px',
    border: '1px solid var(--border-color)',
  },
  tokenLabel: {
    fontSize: '0.75rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.05em',
    marginBottom: '0.35rem',
  },
  tokenValue: {
    fontFamily: 'monospace',
    fontSize: '1rem',
    fontWeight: '700',
    color: 'var(--accent-blue)',
    wordBreak: 'break-all',
    marginBottom: '0.5rem',
  },
  tokenHint: {
    fontSize: '0.8rem',
    color: 'var(--text-secondary)',
    lineHeight: '1.4',
  },
  modalFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-end',
    gap: '0.75rem',
    marginTop: '1rem',
    paddingTop: '1rem',
    borderTop: '1px solid var(--border-color)',
  },
};
