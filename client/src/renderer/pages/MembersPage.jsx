import React, { useState } from 'react';
import { Crown, UserCheck, UserPlus, Edit, Trash2, Key, Users, Check, Copy, AlertCircle, ShieldCheck, Clock, UserX, ShieldAlert } from 'lucide-react';
import Card from '../components/Common/Card';
import Badge from '../components/Common/Badge';
import CreateUserModal from '../components/Modals/CreateUserModal';

export default function MembersPage({
  orgMembers,
  ownerInfo,
  orgRoles,
  onCreateUser,
  onEditRoles,
  onDeleteUser,
  userPermissions,
  currentUser,
}) {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [copiedTokens, setCopiedTokens] = useState({});

  const isOwner = currentUser?.isOwner;
  const canCreate = isOwner || (userPermissions && userPermissions.includes('USER_CREATE'));
  const canManage = isOwner || (userPermissions && userPermissions.includes('USER_MANAGE'));

  const handleCopySetupLink = (memberId, token) => {
    if (!token) return;
    const fullUrl = `${window.location.origin}/setup/${token}`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedTokens((prev) => ({ ...prev, [memberId]: true }));
    setTimeout(() => {
      setCopiedTokens((prev) => ({ ...prev, [memberId]: false }));
    }, 3000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Header Action Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h3 style={{ fontSize: '1.2rem', fontWeight: '700', color: 'var(--text-primary)', margin: 0 }}>
            Organization Members
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.25rem 0 0' }}>
            Manage member identities, custom RBAC role assignments, and key registrations.
          </p>
        </div>

        {canCreate && (
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="btn btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <UserPlus size={16} />
            <span>Add Member</span>
          </button>
        )}
      </div>

      {/* Organization Owner Card (Separated & Highlighted) */}
      {ownerInfo && (
        <Card style={{ backgroundColor: 'rgba(139, 92, 246, 0.05)', border: '1px solid rgba(139, 92, 246, 0.25)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Crown size={18} color="#a78bfa" />
                <span style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                  {ownerInfo.name || ownerInfo.email}
                </span>
                <Badge type="owner" />
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                {ownerInfo.email} • Inherent Ownership Authority
              </div>
            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              Owner accounts are non-editable & non-deletable.
            </div>
          </div>
        </Card>
      )}

      {/* Organization Non-Owner Members Table */}
      <div className="table-container">
        <table className="table">
          <thead>
            <tr>
              <th>Member Name</th>
              <th>Status</th>
              <th>Assigned Roles</th>
              <th>Effective Permissions</th>
              <th>Created Date</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {orgMembers && orgMembers.length > 0 ? (
              orgMembers.map((member) => (
                <tr key={member.id}>
                  <td>
                    <div style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{member.name || member.email}</div>
                    {member.name && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{member.email}</div>}
                  </td>
                  <td>
                    {member.status === 'DISABLED' ? (
                      <span className="badge badge-highly-confidential" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                        <UserX size={12} /> DISABLED
                      </span>
                    ) : member.status === 'SETUP_REQUIRED' || !member.isActive ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span className="badge badge-key-pending" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                          <Clock size={12} /> SETUP REQUIRED
                        </span>
                        {member.setupToken && (
                          <button
                            onClick={() => handleCopySetupLink(member.id, member.setupToken)}
                            className="btn btn-secondary btn-sm"
                            title="Copy setup link"
                            style={{ padding: '0.2rem 0.4rem' }}
                          >
                            {copiedTokens[member.id] ? <Check size={12} color="var(--accent-emerald)" /> : <Copy size={12} />}
                          </button>
                        )}
                      </div>
                    ) : (
                      <span className="badge badge-active" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                        <UserCheck size={12} /> ACTIVE
                      </span>
                    )}
                  </td>
                  <td>
                    {member.roles && member.roles.length > 0 ? (
                      member.roles.map((r) => (
                        <span key={r.id} style={{ fontSize: '0.75rem', backgroundColor: 'var(--bg-dark-input)', padding: '0.2rem 0.5rem', borderRadius: '4px', border: '1px solid var(--border-color)', margin: '0 0.2rem' }}>
                          {r.name}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>No Roles Assigned</span>
                    )}
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {member.permissions?.slice(0, 3).join(', ')}{member.permissions?.length > 3 ? ` +${member.permissions.length - 3} more` : ''}
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{new Date(member.createdAt).toLocaleDateString()}</td>
                  <td style={{ textAlign: 'right' }}>
                    {canManage && (
                      <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                        <button
                          onClick={() => onEditRoles(member)}
                          className="btn btn-secondary btn-sm"
                          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Edit size={12} />
                          <span>Edit Roles</span>
                        </button>
                        <button
                          onClick={() => onDeleteUser(member.id)}
                          className="btn btn-danger btn-sm"
                          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Trash2 size={12} />
                          <span>Delete</span>
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6">
                  <div className="empty-state">
                    <Users size={36} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
                    <div className="empty-state-title">No Member Accounts</div>
                    <div className="empty-state-desc">Create non-owner organization member accounts using the button above.</div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create User Modal */}
      <CreateUserModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onCreateUser={onCreateUser}
        availableRoles={orgRoles}
      />
    </div>
  );
}
