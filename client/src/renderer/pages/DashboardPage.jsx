import React from 'react';
import { Lock, Share2, Users, Globe, FileText, CheckCircle2, ShieldCheck, User, Crown } from 'lucide-react';
import { StatCard, Card } from '../components/Common/Card';
import Badge from '../components/Common/Badge';

export default function DashboardPage({
  currentUser,
  currentOrg,
  fileList,
  sharedFileList,
  orgMembers,
  orgPolicy,
  auditVerification,
  onVerifyAuditChain,
  setActiveTab,
}) {
  const isOwner = Boolean(currentUser?.isOwner);
  const canManageOrg = isOwner || (currentUser?.permissions && currentUser.permissions.includes('ORG_MANAGE'));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Welcome Banner Card */}
      <Card style={{ background: 'linear-gradient(135deg, #111827 0%, #0d1322 100%)', border: '1px solid var(--border-color-muted)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '1.25rem', fontWeight: '700', color: 'var(--text-primary)' }}>
              Welcome back, {currentUser?.name || currentUser?.email}
            </div>
            {currentUser?.name && (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{currentUser.email}</div>
            )}
            <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
              Organization: <strong style={{ color: 'var(--text-primary)' }}>{currentOrg?.name || 'SecureVault Org'}</strong>
            </div>
          </div>

          <div>
            <span className={`badge ${currentUser?.isOwner ? 'badge-owner' : 'badge-active'}`} style={{ padding: '0.4rem 1rem', fontSize: '0.85rem', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
              {currentUser?.isOwner ? <Crown size={16} /> : <User size={16} />}
              <span>{currentUser?.isOwner ? 'ORGANIZATION OWNER' : 'MEMBER ACCOUNT'}</span>
            </span>
          </div>
        </div>
      </Card>

      {/* Real Metric Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
        <StatCard
          title="Owned Vault Files"
          value={fileList?.length || 0}
          subtext="AES-256-GCM Encrypted"
          icon={Lock}
          color="var(--accent-blue)"
          onClick={() => setActiveTab && setActiveTab('files')}
        />
        <StatCard
          title="Shared With Me"
          value={sharedFileList?.length || 0}
          subtext="X25519 DEK Wrapped"
          icon={Share2}
          color="var(--accent-cyan)"
          onClick={() => setActiveTab && setActiveTab('files')}
        />
        <StatCard
          title="Active Members"
          value={orgMembers?.length || 0}
          subtext="Org Member Accounts"
          icon={Users}
          color="var(--accent-emerald)"
        />
        {canManageOrg && (
          <StatCard
            title="Geo-Fencing Status"
            value={orgPolicy?.enforce_geo_fencing ? 'ENFORCED' : 'DISABLED'}
            subtext={orgPolicy?.enforce_geo_fencing ? 'Restricted to Allowed Locations' : 'Location Check Contextual'}
            icon={Globe}
            color={orgPolicy?.enforce_geo_fencing ? 'var(--accent-rose)' : 'var(--accent-amber)'}
          />
        )}
      </div>

      {/* Security Health & Policy Summary Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: canManageOrg ? '1fr 1fr' : '1fr', gap: '1.5rem' }}>
        {/* User Identity & Effective Permissions */}
        <Card title="Identity & Effective Permissions">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px dashed var(--border-color)' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Assigned Roles:</span>
              <span style={{ fontWeight: '600', color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                {currentUser?.isOwner ? 'Inherent Owner Authority' : currentUser?.roles?.map((r) => r.name).join(', ') || 'None'}
              </span>
            </div>

            <div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>Active System Permissions:</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                {currentUser?.permissions?.map((p) => (
                  <span
                    key={p}
                    style={{
                      backgroundColor: 'var(--bg-dark-input)',
                      color: 'var(--accent-blue)',
                      border: '1px solid rgba(59, 130, 246, 0.2)',
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.725rem',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: '600',
                    }}
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </Card>

        {/* Audit Chain Integrity Verification Card (Admin Only) */}
        {canManageOrg && (
          <Card title="Security Audit Log Hash Chain">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                All system events are recorded in a tamper-evident SHA-256 cryptographic hash chain. Verify database audit logs integrity live.
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <span className={`badge ${auditVerification?.valid ? 'badge-active' : 'badge-public'}`}>
                    {auditVerification?.valid ? 'CHAINS VALID & INTACT' : 'NOT VERIFIED YET'}
                  </span>
                  {auditVerification?.chainLength !== undefined && (
                    <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                      ({auditVerification.chainLength} Log Entries)
                    </span>
                  )}
                </div>

                <button onClick={onVerifyAuditChain} className="btn btn-secondary btn-sm">
                  Run Chain Check
                </button>
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
