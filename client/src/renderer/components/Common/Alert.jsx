import React from 'react';

export default function Alert({ type = 'error', message, onClose }) {
  if (!message) return null;

  const isSuccess = type === 'success';

  return (
    <div className={isSuccess ? 'alert-success' : 'alert-error'} style={styles.alert}>
      <div style={styles.content}>
        <span>{isSuccess ? '✅' : '⚠️'}</span>
        <span>{message}</span>
      </div>
      {onClose && (
        <button onClick={onClose} style={styles.closeBtn}>
          ✕
        </button>
      )}
    </div>
  );
}

const styles = {
  alert: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '1.25rem',
  },
  content: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    fontWeight: '500',
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: 'inherit',
    cursor: 'pointer',
    opacity: 0.7,
    fontSize: '0.9rem',
  },
};
