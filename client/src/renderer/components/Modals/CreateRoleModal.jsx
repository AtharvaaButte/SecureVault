import React, { useState } from 'react';
import { Shield, Plus } from 'lucide-react';
import Modal from '../Common/Modal';
import Alert from '../Common/Alert';

export default function CreateRoleModal({ isOpen, allPermissions, onCreateRole, onClose }) {
  const [roleName, setRoleName] = useState('');
  const [roleDesc, setRoleDesc] = useState('');
  const [selectedPerms, setSelectedPerms] = useState([]);
  const [creating, setCreating] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const handlePermToggle = (permName) => {
    setSelectedPerms((prev) =>
      prev.includes(permName) ? prev.filter((p) => p !== permName) : [...prev, permName]
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!roleName) return;

    if (roleName.trim().toLowerCase() === 'owner') {
      setErrorMsg('"Owner" is a reserved name and cannot be created as a custom role.');
      return;
    }

    setCreating(true);
    setErrorMsg(null);

    const result = await onCreateRole({
      name: roleName.trim(),
      description: roleDesc.trim(),
      permissions: selectedPerms,
    });

    setCreating(false);

    if (result.success) {
      setRoleName('');
      setRoleDesc('');
      setSelectedPerms([]);
      onClose();
    } else {
      setErrorMsg(result.error || 'Failed to create role.');
    }
  };

  const filePermissionsList = ['FILE_READ', 'FILE_UPLOAD', 'FILE_SHARE', 'FILE_REVOKE', 'FILE_DELETE'];
  const adminPermissionsList = ['USER_CREATE', 'USER_MANAGE', 'ROLE_MANAGE', 'ORG_MANAGE'];

  const permissionLabels = {
    FILE_READ: 'Read Files',
    FILE_UPLOAD: 'Upload Files',
    FILE_SHARE: 'Share Files',
    FILE_REVOKE: 'Revoke File Access',
    FILE_DELETE: 'Delete Files',
    USER_CREATE: 'Create Members',
    USER_MANAGE: 'Manage Members',
    ROLE_MANAGE: 'Manage Roles',
    ORG_MANAGE: 'Manage Organization',
  };

  const filePermissions = (allPermissions || []).filter((p) => filePermissionsList.includes(p.name));
  const adminPermissions = (allPermissions || []).filter((p) => adminPermissionsList.includes(p.name));
  const otherPermissions = (allPermissions || []).filter((p) => !filePermissionsList.includes(p.name) && !adminPermissionsList.includes(p.name));

  return (
    <Modal
      isOpen={isOpen}
      title="Create Custom Organization Role"
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} className="btn btn-secondary btn-sm">
            Cancel
          </button>
          <button type="submit" form="create-role-form" disabled={creating || !roleName} className="btn btn-primary btn-sm">
            {creating ? 'Creating Role...' : 'Create Role'}
          </button>
        </>
      }
    >
      {errorMsg && <Alert type="danger" message={errorMsg} style={{ marginBottom: '1rem' }} />}

      <form id="create-role-form" onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div className="form-group">
          <label className="form-label">Role Name</label>
          <input
            type="text"
            className="form-input"
            placeholder="e.g. AuditManager, ComplianceOfficer"
            value={roleName}
            onChange={(e) => setRoleName(e.target.value)}
            required
          />
        </div>

        <div className="form-group">
          <label className="form-label">Role Description</label>
          <input
            type="text"
            className="form-input"
            placeholder="Brief description of role responsibilities"
            value={roleDesc}
            onChange={(e) => setRoleDesc(e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Assign System Permissions</label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxHeight: '260px', overflowY: 'auto', padding: '0.75rem', backgroundColor: 'var(--bg-dark-input)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            
            {/* File Permissions */}
            {filePermissions.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.4rem' }}>
                  File Permissions
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {filePermissions.map((perm) => (
                    <label key={perm.id || perm.name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={selectedPerms.includes(perm.name)}
                        onChange={() => handlePermToggle(perm.name)}
                      />
                      <span>
                        <strong style={{ color: 'var(--text-primary)' }}>{permissionLabels[perm.name] || perm.name}</strong>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: '0.25rem' }}>({perm.name})</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Administrative Permissions */}
            {adminPermissions.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#a855f7', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.4rem' }}>
                  Administrative Permissions
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {adminPermissions.map((perm) => (
                    <label key={perm.id || perm.name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={selectedPerms.includes(perm.name)}
                        onChange={() => handlePermToggle(perm.name)}
                      />
                      <span>
                        <strong style={{ color: 'var(--text-primary)' }}>{permissionLabels[perm.name] || perm.name}</strong>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: '0.25rem' }}>({perm.name})</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Other System Permissions */}
            {otherPermissions.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.4rem' }}>
                  Other Permissions
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {otherPermissions.map((perm) => (
                    <label key={perm.id || perm.name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={selectedPerms.includes(perm.name)}
                        onChange={() => handlePermToggle(perm.name)}
                      />
                      <span>{perm.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

          </div>
        </div>
      </form>
    </Modal>
  );
}
