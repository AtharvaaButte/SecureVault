import React, { useState } from 'react';
import { Shield, Plus, Trash2, ListChecks, FileText, Users } from 'lucide-react';
import Card from '../components/Common/Card';

export default function RolesPage({
  orgRoles,
  allPermissions,
  permissionAuditRecords,
  onCreateRole,
  onDeleteRole,
  userPermissions,
  currentUser,
}) {
  const [activeSubTab, setActiveSubTab] = useState('roles');

  const isOwner = currentUser?.isOwner;
  const canManage = isOwner || (userPermissions && userPermissions.includes('ROLE_MANAGE'));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Sub Tabs */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '0.5rem', backgroundColor: 'var(--bg-dark-sidebar)', padding: '0.25rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveSubTab('roles')}
            style={{
              padding: '0.45rem 1rem',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: activeSubTab === 'roles' ? 'var(--bg-dark-card-hover)' : 'transparent',
              color: activeSubTab === 'roles' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontWeight: '600',
              fontSize: '0.85rem',
              cursor: 'pointer',
            }}
          >
            Organization Custom Roles ({orgRoles?.length || 0})
          </button>
          <button
            onClick={() => setActiveSubTab('catalog')}
            style={{
              padding: '0.45rem 1rem',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: activeSubTab === 'catalog' ? 'var(--bg-dark-card-hover)' : 'transparent',
              color: activeSubTab === 'catalog' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontWeight: '600',
              fontSize: '0.85rem',
              cursor: 'pointer',
            }}
          >
            System Permission Catalog ({allPermissions?.length || 0})
          </button>
          <button
            onClick={() => setActiveSubTab('audit')}
            style={{
              padding: '0.45rem 1rem',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: activeSubTab === 'audit' ? 'var(--bg-dark-card-hover)' : 'transparent',
              color: activeSubTab === 'audit' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontWeight: '600',
              fontSize: '0.85rem',
              cursor: 'pointer',
            }}
          >
            Permission Audit View ({permissionAuditRecords?.length || 0})
          </button>
        </div>

        {canManage && activeSubTab === 'roles' && (
          <button onClick={onCreateRole} className="btn btn-primary btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
            <Plus size={16} />
            <span>Create Custom Role</span>
          </button>
        )}
      </div>

      {/* Sub Tab Content */}
      {activeSubTab === 'roles' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.25rem' }}>
          {orgRoles && orgRoles.length > 0 ? (
            orgRoles.map((role) => (
              <Card key={role.id} title={role.name}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
                    {role.description || 'No role description provided.'}
                  </div>

                  <div>
                    <div style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                      Granted Permissions ({role.permissions?.length || 0}):
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                      {role.permissions?.map((p) => (
                        <span key={p.id || p.name || p} style={{ fontSize: '0.7rem', backgroundColor: 'var(--bg-dark-input)', color: 'var(--accent-cyan)', border: '1px solid rgba(6, 182, 212, 0.2)', padding: '0.15rem 0.4rem', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                          {p.name || p}
                        </span>
                      ))}
                    </div>
                  </div>

                  {canManage && (
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-color)' }}>
                      <button onClick={() => onDeleteRole(role.id)} className="btn btn-danger btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                        <Trash2 size={12} />
                        <span>Delete Role</span>
                      </button>
                    </div>
                  )}
                </div>
              </Card>
            ))
          ) : (
            <Card style={{ gridColumn: '1 / -1' }}>
              <div className="empty-state">
                <Shield size={40} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
                <div className="empty-state-title">No Custom Roles Found</div>
                <div className="empty-state-desc">Create custom organization-scoped roles to assign dynamic RBAC permissions to member accounts.</div>
              </div>
            </Card>
          )}
        </div>
      )}

      {activeSubTab === 'catalog' && (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Permission Symbol</th>
                <th>System Description</th>
              </tr>
            </thead>
            <tbody>
              {allPermissions && allPermissions.map((perm) => (
                <tr key={perm.id || perm.name}>
                  <td className="font-mono" style={{ fontWeight: '600', color: 'var(--accent-blue)' }}>{perm.name}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{perm.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeSubTab === 'audit' && (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>User Member</th>
                <th>Role Name</th>
                <th>Granted Permission</th>
                <th>Permission Description</th>
              </tr>
            </thead>
            <tbody>
              {permissionAuditRecords && permissionAuditRecords.length > 0 ? (
                permissionAuditRecords.map((rec, i) => (
                  <tr key={i}>
                    <td>
                      <div style={{ fontWeight: '600' }}>{rec.user_name || rec.user_email}</div>
                      {rec.user_name && <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>{rec.user_email}</div>}
                    </td>
                    <td><span className="badge badge-active">{rec.role_name}</span></td>
                    <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{rec.permission_name}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{rec.permission_description}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="4">
                    <div className="empty-state">
                      <FileText size={40} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
                      <div className="empty-state-title">No Permission Audit Records</div>
                      <div className="empty-state-desc">Assign custom roles to members to generate system permission audit mappings.</div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
