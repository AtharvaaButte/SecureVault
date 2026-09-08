import React, { useState } from 'react';
import { Lock, FileUp, Download, Share2, Trash2, FileText, Info, FolderOpen, ShieldCheck, Eye, HardDrive, CheckCircle2, ShieldAlert } from 'lucide-react';
import Card from '../components/Common/Card';
import Badge from '../components/Common/Badge';
import FileDetailsModal from '../components/Modals/FileDetailsModal';

export default function FilesPage({
  fileList,
  sharedFileList,
  selectedFile,
  encryptResult,
  uploadClassification,
  setUploadClassification,
  onSelectFile,
  onEncryptFile,
  onUploadCiphertext,
  onDownloadFile,
  onDownloadSharedFile,
  onDeleteFile,
  onOpenShareModal,
  downloadStatus,
  sharedDownloadStatus,
  userPermissions,
  currentUser,
}) {
  const [activeSubTab, setActiveSubTab] = useState('owned');
  const [filterClassification, setFilterClassification] = useState('ALL');
  const [inspectingFile, setInspectingFile] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [encrypting, setEncrypting] = useState(false);
  const [uploading, setUploading] = useState(false);

  const isOwner = currentUser?.isOwner;
  const canUpload = isOwner || (userPermissions && userPermissions.includes('FILE_UPLOAD'));
  const canRead = isOwner || (userPermissions && userPermissions.includes('FILE_READ'));
  const canShare = isOwner || (userPermissions && userPermissions.includes('FILE_SHARE'));
  const canDelete = isOwner || (userPermissions && userPermissions.includes('FILE_DELETE'));

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleSelectAndEncrypt = async () => {
    const sel = await onSelectFile();
    if (!sel || sel.canceled) return;

    setEncrypting(true);
    await onEncryptFile(sel.filePath);
    setEncrypting(false);
  };

  const handleUploadSubmit = async () => {
    if (!encryptResult) return;
    setUploading(true);
    await onUploadCiphertext(encryptResult.fileId, uploadClassification);
    setUploading(false);
  };

  const handleDeleteSubmit = async (fileId) => {
    setDeletingId(fileId);
    await onDeleteFile(fileId);
    setDeletingId(null);
  };

  const filteredOwnedFiles = fileList?.filter((f) =>
    filterClassification === 'ALL' ? true : f.dataClassification === filterClassification
  ) || [];

  const filteredSharedFiles = sharedFileList?.filter((f) =>
    filterClassification === 'ALL' ? true : f.dataClassification === filterClassification
  ) || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Encryption & Upload Panel */}
      {canUpload && (
        <Card title="Local Encryption & Cloud Vault Upload">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: '1.4' }}>
                Select a local file to encrypt via AES-256-GCM. Ciphertext is uploaded to Backblaze B2 while your Data Encryption Key (DEK) is wrapped securely using X25519.
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <button
                  onClick={handleSelectAndEncrypt}
                  disabled={encrypting}
                  className="btn btn-secondary btn-sm"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  <FileUp size={16} />
                  <span>{encrypting ? 'Encrypting Locally...' : 'Select & Encrypt Local File'}</span>
                </button>

                {selectedFile && (
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: '600' }}>
                    {selectedFile.fileName} ({formatBytes(selectedFile.fileSize)})
                  </span>
                )}
              </div>
            </div>

            {encryptResult && (
              <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ fontSize: '0.775rem', color: 'var(--accent-emerald)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <CheckCircle2 size={14} /> File Encrypted Locally (Original: {formatBytes(encryptResult.originalSize)})
                </div>

                <div className="form-group">
                  <label className="form-label">Data Classification Level</label>
                  <select
                    className="form-select"
                    value={uploadClassification}
                    onChange={(e) => setUploadClassification(e.target.value)}
                  >
                    <option value="PUBLIC">PUBLIC - Unrestricted</option>
                    <option value="INTERNAL">INTERNAL - Standard Default</option>
                    <option value="CONFIDENTIAL">CONFIDENTIAL - Sensitive (Step-Up Required)</option>
                    <option value="HIGHLY_CONFIDENTIAL">HIGHLY CONFIDENTIAL - Highest Sensitivity</option>
                  </select>
                </div>

                <button
                  onClick={handleUploadSubmit}
                  disabled={uploading}
                  className="btn btn-primary btn-sm"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', justifyContent: 'center' }}
                >
                  <HardDrive size={16} />
                  <span>{uploading ? 'Uploading Ciphertext...' : 'Upload Encrypted Ciphertext'}</span>
                </button>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Filter & Sub-Tab Control Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', backgroundColor: 'var(--bg-dark-sidebar)', padding: '0.25rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveSubTab('owned')}
            style={{
              padding: '0.45rem 1rem',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: activeSubTab === 'owned' ? 'var(--bg-dark-card-hover)' : 'transparent',
              color: activeSubTab === 'owned' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontWeight: '600',
              fontSize: '0.85rem',
              cursor: 'pointer',
            }}
          >
            My Vault Files ({fileList?.length || 0})
          </button>
          <button
            onClick={() => setActiveSubTab('shared')}
            style={{
              padding: '0.45rem 1rem',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: activeSubTab === 'shared' ? 'var(--bg-dark-card-hover)' : 'transparent',
              color: activeSubTab === 'shared' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontWeight: '600',
              fontSize: '0.85rem',
              cursor: 'pointer',
            }}
          >
            Shared With Me ({sharedFileList?.length || 0})
          </button>
        </div>

        {/* Classification Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Filter Classification:</span>
          <select
            className="form-select"
            style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
            value={filterClassification}
            onChange={(e) => setFilterClassification(e.target.value)}
          >
            <option value="ALL">All Classifications</option>
            <option value="PUBLIC">PUBLIC</option>
            <option value="INTERNAL">INTERNAL</option>
            <option value="CONFIDENTIAL">CONFIDENTIAL</option>
            <option value="HIGHLY_CONFIDENTIAL">HIGHLY CONFIDENTIAL</option>
          </select>
        </div>
      </div>

      {/* Grid Layout of File Cards */}
      {activeSubTab === 'owned' ? (
        filteredOwnedFiles.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.25rem' }}>
            {filteredOwnedFiles.map((file) => (
              <Card key={file.id} style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '210px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                    <Badge classification={file.dataClassification} />
                    <button
                      onClick={() => setInspectingFile(file)}
                      style={{ background: 'none', border: 'none', color: 'var(--accent-blue)', fontSize: '0.775rem', cursor: 'pointer', fontWeight: '500', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                    >
                      <Eye size={14} />
                      <span>Details</span>
                    </button>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <FileText size={20} color="var(--accent-blue)" style={{ flexShrink: 0 }} />
                    <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={file.originalName}>
                      {file.originalName}
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                    <span>Original Size:</span>
                    <span className="font-mono" style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{formatBytes(file.originalSize)}</span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    <span>Uploaded Date:</span>
                    <span>{new Date(file.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end', marginTop: '1.25rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-color)' }}>
                  {canRead && (
                    <button
                      onClick={() => onDownloadFile(file.id)}
                      disabled={downloadStatus[file.id]}
                      className="btn btn-secondary btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                    >
                      <Download size={14} />
                      <span>{downloadStatus[file.id] ? 'Decrypting...' : 'Download'}</span>
                    </button>
                  )}

                  {canShare && (
                    <button
                      onClick={() => onOpenShareModal(file)}
                      className="btn btn-primary btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                    >
                      <Share2 size={14} />
                      <span>Share</span>
                    </button>
                  )}

                  {canDelete && (
                    <button
                      onClick={() => handleDeleteSubmit(file.id)}
                      disabled={deletingId === file.id}
                      className="btn btn-danger btn-sm"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                    >
                      <Trash2 size={14} />
                      <span>{deletingId === file.id ? 'Deleting...' : 'Delete'}</span>
                    </button>
                  )}
                </div>
              </Card>
            ))}
          </div>
        ) : (
          <Card>
            <div className="empty-state">
              <FolderOpen size={40} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
              <div className="empty-state-title">No Owned Vault Files</div>
              <div className="empty-state-desc">Select and encrypt a local file above to store it in your encrypted cloud vault.</div>
            </div>
          </Card>
        )
      ) : (
        /* Shared Files Grid */
        filteredSharedFiles.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.25rem' }}>
            {filteredSharedFiles.map((file) => {
              const isRestricted = file.blockedOperations && file.blockedOperations.length > 0;
              return (
                <Card key={file.id} style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '210px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                      <Badge classification={file.dataClassification} />
                      <span className={`badge ${isRestricted ? 'badge-owner' : 'badge-active'}`}>
                        {isRestricted ? 'RESTRICTED' : 'FULL ACCESS'}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                      <Lock size={18} color="var(--accent-emerald)" style={{ flexShrink: 0 }} />
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={file.originalName}>
                        {file.originalName}
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                      <span>Original Size:</span>
                      <span className="font-mono" style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{formatBytes(file.originalSize)}</span>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                      <span>Shared By:</span>
                      <span className="font-mono" style={{ color: 'var(--accent-blue)', fontWeight: '600' }}>
                        {file.ownerName || file.ownerEmail}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end', marginTop: '1.25rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-color)' }}>
                    {canRead && (
                      <button
                        onClick={() => onDownloadSharedFile(file.id)}
                        disabled={sharedDownloadStatus[file.id]}
                        className="btn btn-secondary btn-sm"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                      >
                        <Download size={14} />
                        <span>{sharedDownloadStatus[file.id] ? 'Unwrapping DEK...' : 'Download & Decrypt'}</span>
                      </button>
                    )}
                  </div>
                </Card>
              );
            })}
          </div>
        ) : (
          <Card>
            <div className="empty-state">
              <FolderOpen size={40} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
              <div className="empty-state-title">No Shared Files Found</div>
              <div className="empty-state-desc">Files shared with you by organization members will appear here.</div>
            </div>
          </Card>
        )
      )}

      {/* File Technical Metadata Inspection Modal */}
      <FileDetailsModal
        isOpen={Boolean(inspectingFile)}
        file={inspectingFile}
        onClose={() => setInspectingFile(null)}
      />
    </div>
  );
}
