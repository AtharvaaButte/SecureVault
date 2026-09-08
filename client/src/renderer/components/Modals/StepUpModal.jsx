import React, { useState } from 'react';
import { Lock, ShieldAlert } from 'lucide-react';
import Modal from '../Common/Modal';

export default function StepUpModal({ isOpen, reason, onConfirm, onCancel }) {
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!password) return;
    onConfirm(password);
    setPassword('');
  };

  return (
    <Modal
      isOpen={isOpen}
      title="Security Step-Up Re-Authentication"
      onClose={onCancel}
      footer={
        <>
          <button type="button" onClick={onCancel} className="btn btn-secondary btn-sm">
            Cancel
          </button>
          <button type="submit" form="step-up-form" className="btn btn-primary btn-sm">
            Verify Password & Continue
          </button>
        </>
      }
    >
      <form id="step-up-form" onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div
          style={{
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            border: '1px solid rgba(245, 158, 11, 0.25)',
            borderRadius: '8px',
            padding: '0.85rem',
            color: 'var(--accent-amber)',
            fontSize: '0.825rem',
            lineHeight: '1.4',
            display: 'flex',
            gap: '0.6rem',
            alignItems: 'flex-start',
          }}
        >
          <ShieldAlert size={18} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
          <div>
            <strong>High Impact Action Detected</strong>
            <div style={{ marginTop: '0.25rem' }}>{reason || 'Re-authentication is required by security policy to perform this operation.'}</div>
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">Account Password</label>
          <input
            type="password"
            className="form-input"
            placeholder="Enter your account password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
          />
        </div>
      </form>
    </Modal>
  );
}
