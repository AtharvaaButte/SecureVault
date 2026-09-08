import React from 'react';
import { FileText, Shield } from 'lucide-react';
import Modal from '../Common/Modal';
import Badge from '../Common/Badge';

export default function FileDetailsModal({ isOpen, file, onClose }) {
  if (!file) return null;

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <Modal
      isOpen={isOpen}
      title={`Technical Security Details: ${file.originalName}`}
      onClose={onClose}
      footer={
        <button onClick={onClose} className="btn btn-secondary btn-sm">
          Close
        </button>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.85rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>File ID:</span>
          <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: '600', fontSize: '0.775rem' }}>{file.id}</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Original File Size:</span>
          <span className="font-mono" style={{ color: 'var(--accent-emerald)', fontWeight: '700' }}>
            {formatBytes(file.originalSize)} ({file.originalSize} bytes)
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Data Classification:</span>
          <Badge classification={file.dataClassification} />
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Symmetric Algorithm:</span>
          <span className="font-mono" style={{ color: 'var(--accent-blue)', fontWeight: '600' }}>{file.algorithm || 'AES-256-GCM'}</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Cloud Storage Key:</span>
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{file.storageKey}</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Initialization Vector (IV):</span>
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{file.iv ? `${file.iv.substring(0, 16)}...` : 'N/A'}</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Authentication Tag (AuthTag):</span>
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{file.authTag ? `${file.authTag.substring(0, 16)}...` : 'N/A'}</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Upload Date:</span>
          <span style={{ color: 'var(--text-primary)' }}>{new Date(file.createdAt).toLocaleString()}</span>
        </div>
      </div>
    </Modal>
  );
}
