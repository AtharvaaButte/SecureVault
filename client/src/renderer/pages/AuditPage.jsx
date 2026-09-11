import React from 'react';
import { ShieldCheck, FileText, RefreshCw, CheckCircle2 } from 'lucide-react';
import Card from '../components/Common/Card';

export default function AuditPage({
  auditLogs,
  auditVerification,
  onVerifyChain,
  userPermissions,
  currentUser,
}) {
  const isOwner = currentUser?.isOwner;
  const canView = isOwner || (userPermissions && userPermissions.includes('ORG_MANAGE'));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Audit Chain Verification Banner */}
      <Card style={{ backgroundColor: auditVerification?.valid ? 'rgba(16, 185, 129, 0.08)' : 'var(--bg-dark-card)', border: `1px solid ${auditVerification?.valid ? 'rgba(16, 185, 129, 0.3)' : 'var(--border-color)'}` }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldCheck size={20} color={auditVerification?.valid ? 'var(--accent-emerald)' : 'var(--accent-blue)'} />
              <span>Tamper-Evident SHA-256 Audit Log Hash Chain</span>
            </div>
            <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              Every event is linked cryptographically to the preceding log record. Current status:{' '}
              <strong style={{ color: auditVerification?.valid ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                {auditVerification?.valid
                  ? `CHAIN VALID & INTACT (${auditVerification.totalLogs || auditVerification.count || auditLogs?.length || 0} events verified)`
                  : auditVerification ? `TAMPERING DETECTED / INVALID: ${auditVerification.message || 'Chain mismatch'}` : 'NOT VERIFIED'}
              </strong>
            </div>
          </div>

          {onVerifyChain && (
            <button onClick={onVerifyChain} className="btn btn-primary btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
              <RefreshCw size={14} />
              <span>Validate Hash Chain & Detect Tampering</span>
            </button>
          )}
        </div>
      </Card>

      {/* Tamper-Evident Audit Logs Table */}
      <div className="table-container">
        <table className="table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Event Type</th>
              <th>Action</th>
              <th>Resource Type</th>
              <th>IP & Location Context</th>
              <th>SHA-256 Current Hash</th>
            </tr>
          </thead>
          <tbody>
            {auditLogs && auditLogs.length > 0 ? (
              auditLogs.map((log) => (
                <tr key={log.id}>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{new Date(log.created_at).toLocaleString()}</td>
                  <td className="font-mono" style={{ fontWeight: '600', fontSize: '0.8rem', color: 'var(--text-primary)' }}>{log.event_type}</td>
                  <td>
                    <span className={`badge ${log.action === 'ALLOW' ? 'badge-active' : 'badge-highly-confidential'}`}>
                      {log.action}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{log.resource_type || 'FILE'}</td>
                  <td style={{ fontSize: '0.8rem' }}>
                    <div style={{ fontWeight: '500' }}>{log.location_label || 'LOCAL/DEV'}</div>
                    <div className="font-mono" style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>{log.ip_address}</div>
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.725rem', color: 'var(--accent-cyan)' }} title={log.current_hash}>
                    {log.current_hash ? `${log.current_hash.substring(0, 16)}...` : 'N/A'}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6">
                  <div className="empty-state">
                    <FileText size={40} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
                    <div className="empty-state-title">No Audit Log Entries</div>
                    <div className="empty-state-desc">System security events will be recorded here automatically.</div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
