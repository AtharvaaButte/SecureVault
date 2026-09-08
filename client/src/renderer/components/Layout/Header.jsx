import React from 'react';
import { LogOut, Key, ShieldCheck } from 'lucide-react';

export default function Header({ currentUser, cryptoIdentity, onLogout, activeTabLabel }) {
  const isKeyActive = Boolean(
    cryptoIdentity?.hasIdentity ||
    cryptoIdentity?.publicKey ||
    currentUser?.publicKey ||
    currentUser?.publicKeyRegistered
  );

  return (
    <header style={styles.header}>
      {/* Current Page Title */}
      <div>
        <h2 style={styles.pageTitle}>{activeTabLabel || 'Overview'}</h2>
      </div>

      {/* User Context & Identity Control */}
      <div style={styles.rightGroup}>
        {/* Cryptographic Key Status */}
        <div style={styles.keyBadge}>
          <Key size={14} style={{ color: isKeyActive ? 'var(--accent-emerald)' : 'var(--accent-amber)' }} />
          <span>{isKeyActive ? 'X25519 Identity Active' : 'Key Registering...'}</span>
        </div>

        {/* User Profile Info */}
        {currentUser && (
          <div style={styles.userProfile}>
            <div style={styles.userNameGroup}>
              <div style={styles.userName}>{currentUser.name || currentUser.email}</div>
              {currentUser.name && <div style={styles.userEmail}>{currentUser.email}</div>}
            </div>
            <span className={`badge ${currentUser.isOwner ? 'badge-owner' : 'badge-active'}`}>
              {currentUser.isOwner ? 'OWNER' : 'MEMBER'}
            </span>
          </div>
        )}

        {/* Logout Button */}
        <button onClick={onLogout} className="btn btn-secondary btn-sm" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span>Logout</span>
          <LogOut size={14} />
        </button>
      </div>
    </header>
  );
}

const styles = {
  header: {
    height: '64px',
    backgroundColor: 'var(--bg-dark-sidebar)',
    borderBottom: '1px solid var(--border-color)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 2rem',
    flexShrink: 0,
  },
  pageTitle: {
    fontSize: '1.15rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
  },
  rightGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '1.25rem',
  },
  keyBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.775rem',
    fontWeight: '600',
    color: 'var(--text-secondary)',
    backgroundColor: 'var(--bg-dark-input)',
    padding: '0.35rem 0.75rem',
    borderRadius: '20px',
    border: '1px solid var(--border-color)',
  },
  userProfile: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
  },
  userNameGroup: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-end',
  },
  userName: {
    fontSize: '0.875rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    lineHeight: '1.2',
  },
  userEmail: {
    fontSize: '0.725rem',
    fontWeight: '400',
    color: 'var(--text-muted)',
  },
};
