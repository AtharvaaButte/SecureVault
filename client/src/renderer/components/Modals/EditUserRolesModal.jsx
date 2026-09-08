import React, { useState, useEffect } from 'react';
import Modal from '../Common/Modal';

export default function EditUserRolesModal({ isOpen, targetUser, orgRoles, onSave, onClose }) {
  const [selectedRoleIds, setSelectedRoleIds] = useState([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (targetUser && targetUser.roles) {
      setSelectedRoleIds(targetUser.roles.map((r) => r.id));
    }
  }, [targetUser]);

  if (!targetUser) return null;

  const handleToggle = (roleId) => {
    setSelectedRoleIds((prev) =>
      prev.includes(roleId) ? prev.filter((id) => id !== roleId) : [...prev, roleId]
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    await onSave(targetUser.id, selectedRoleIds);
    setSaving(false);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      title={`Assign Roles: ${targetUser.name || targetUser.email}`}
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} className="btn btn-secondary btn-sm">
            Cancel
          </button>
          <button type="submit" form="edit-user-roles-form" disabled={saving} className="btn btn-primary btn-sm">
            {saving ? 'Updating...' : 'Save Role Assignments'}
          </button>
        </>
      }
    >
      <form id="edit-user-roles-form" onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
          Select one or more custom organization roles for <strong>{targetUser.name || targetUser.email}</strong>:
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {orgRoles.map((role) => (
            <label
              key={role.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                backgroundColor: 'var(--bg-dark-input)',
                padding: '0.75rem',
                borderRadius: '6px',
                border: '1px solid var(--border-color)',
                cursor: 'pointer',
              }}
            >
              <input
                type="checkbox"
                checked={selectedRoleIds.includes(role.id)}
                onChange={() => handleToggle(role.id)}
              />
              <div>
                <div style={{ fontWeight: '600', color: 'var(--text-primary)', fontSize: '0.875rem' }}>{role.name}</div>
                {role.description && <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>{role.description}</div>}
              </div>
            </label>
          ))}
        </div>
      </form>
    </Modal>
  );
}
