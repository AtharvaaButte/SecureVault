import React from 'react';
import { LayoutDashboard, Lock, Users, Shield, Sliders, FileText } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, orgName, currentUser, userPermissions }) {
  const isOwner = currentUser?.isOwner;
  const hasPerm = (perm) => isOwner || (userPermissions && userPermissions.includes(perm));

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, visible: true },
    { id: 'files', label: 'Vault Files', icon: Lock, visible: true },
    { id: 'members', label: 'User Members', icon: Users, visible: true },
    { id: 'roles', label: 'Roles & RBAC', icon: Shield, visible: hasPerm('ROLE_MANAGE') || isOwner },
    { id: 'policies', label: 'Security Policies', icon: Sliders, visible: hasPerm('ORG_MANAGE') || isOwner },
    { id: 'audit', label: 'Audit Trail', icon: FileText, visible: hasPerm('ORG_MANAGE') || isOwner },
  ];

  return (
    <aside style={styles.sidebar}>
      {/* Brand Header */}
      <div style={styles.brandGroup}>
        <div style={styles.logoBadge}>SV</div>
        <div>
          <div style={styles.brandTitle}>SecureVault</div>
          <div style={styles.brandOrg}>{orgName || 'Enterprise Vault'}</div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={styles.navMenu}>
        <div style={styles.sectionLabel}>PLATFORM CONTROLS</div>
        {navItems.filter(item => item.visible).map((item) => {
          const isActive = activeTab === item.id;
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                ...styles.navButton,
                ...(isActive ? styles.navButtonActive : {}),
              }}
            >
              <Icon size={18} style={styles.navIcon} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={styles.sidebarFooter}>
        <div style={styles.zeroTrustBadge}>
          <span style={styles.pulseDot}></span>
          <span>Zero Trust Active</span>
        </div>
      </div>
    </aside>
  );
}

const styles = {
  sidebar: {
    width: '260px',
    backgroundColor: 'var(--bg-dark-sidebar)',
    borderRight: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    padding: '1.5rem 1rem',
    flexShrink: 0,
  },
  brandGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    paddingBottom: '1.25rem',
    borderBottom: '1px solid var(--border-color)',
  },
  logoBadge: {
    width: '40px',
    height: '40px',
    borderRadius: '10px',
    background: 'linear-gradient(135deg, #2563eb 0%, #0284c7 100%)',
    color: '#ffffff',
    fontWeight: '800',
    fontSize: '1.1rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0 4px 12px rgba(37, 99, 235, 0.35)',
  },
  brandTitle: {
    fontSize: '1.05rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    letterSpacing: '-0.01em',
  },
  brandOrg: {
    fontSize: '0.775rem',
    color: 'var(--text-muted)',
  },
  navMenu: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
    marginTop: '1.25rem',
    flex: 1,
  },
  sectionLabel: {
    fontSize: '0.675rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.08em',
    marginBottom: '0.5rem',
    paddingLeft: '0.5rem',
  },
  navButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    padding: '0.65rem 0.85rem',
    borderRadius: '8px',
    backgroundColor: 'transparent',
    border: 'none',
    color: 'var(--text-secondary)',
    fontSize: '0.875rem',
    fontWeight: '500',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all 0.15s ease',
  },
  navButtonActive: {
    backgroundColor: 'var(--bg-dark-card-hover)',
    color: 'var(--text-primary)',
    fontWeight: '600',
    borderLeft: '3px solid var(--accent-blue)',
  },
  navIcon: {
    flexShrink: 0,
  },
  sidebarFooter: {
    paddingTop: '1rem',
    borderTop: '1px solid var(--border-color)',
  },
  zeroTrustBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.5rem 0.75rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(16, 185, 129, 0.08)',
    border: '1px solid rgba(16, 185, 129, 0.2)',
    color: 'var(--accent-emerald)',
    fontSize: '0.75rem',
    fontWeight: '600',
  },
  pulseDot: {
    width: '7px',
    height: '7px',
    borderRadius: '50%',
    backgroundColor: 'var(--accent-emerald)',
    boxShadow: '0 0 8px var(--accent-emerald)',
  },
};
