import React, { useState, useEffect } from 'react';
import { Search, User, ShieldAlert, Share2, Trash2, CheckCircle2, Lock, Key, ShieldCheck } from 'lucide-react';
import Modal from '../Common/Modal';
import Alert from '../Common/Alert';

export default function FileShareModal({
  isOpen,
  file,
  fileShares,
  onShare,
  onRevoke,
  onClose,
  token,
  userPermissionsCache,
  onFetchPermissions,
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searching, setSearching] = useState(false);

  const [selectedRecipient, setSelectedRecipient] = useState(null);
  const [blockedOps, setBlockedOps] = useState([]);
  const [sharing, setSharing] = useState(false);
  const [revoking, setRevoking] = useState(null);
  const [statusMsg, setStatusMsg] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  // Perform recipient search when searchQuery changes
  useEffect(() => {
    if (!isOpen) return;

    const timer = setTimeout(async () => {
      if (!token) return;
      setSearching(true);
      try {
        let users = [];
        if (window.electronAPI && typeof window.electronAPI.searchOrganizationMembers === 'function') {
          const res = await window.electronAPI.searchOrganizationMembers({ query: searchQuery, token });
          if (res.success) users = res.users || [];
        } else {
          const response = await fetch(`http://localhost:5000/api/users/search?q=${encodeURIComponent(searchQuery || '')}`, {
            headers: { 'Authorization': `Bearer ${token}` },
          });
          const data = await response.json();
          if (response.ok) users = data.users || [];
        }
        setSearchResults(users);
      } catch (e) {
        console.error('[Search Members Error]:', e.message);
      } finally {
        setSearching(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [searchQuery, isOpen, token]);

  useEffect(() => {
    if (selectedRecipient && onFetchPermissions) {
      onFetchPermissions(selectedRecipient.id).then((permData) => {
        if (permData) {
          setSelectedRecipient((prev) =>
            prev && prev.id === selectedRecipient.id
              ? {
                  ...prev,
                  publicKey: permData.publicKey || prev.publicKey,
                  publicKeyRegistered: Boolean(permData.publicKey || permData.publicKeyRegistered),
                }
              : prev
          );
        }
      });
    }
  }, [selectedRecipient?.id]);

  if (!file) return null;

  const handleOpToggle = (op) => {
    setBlockedOps((prev) =>
      prev.includes(op) ? prev.filter((item) => item !== op) : [...prev, op]
    );
  };

  const handleSelectRecipient = (member) => {
    setSelectedRecipient(member);
    setStatusMsg(null);
    setErrorMsg(null);
  };

  const handleShareSubmit = async (e) => {
    e.preventDefault();
    if (!selectedRecipient) return;

    setSharing(true);
    setStatusMsg(null);
    setErrorMsg(null);

    let pubKey = selectedRecipient.publicKey;
    if (!pubKey && onFetchPermissions) {
      const permData = await onFetchPermissions(selectedRecipient.id);
      if (permData) pubKey = permData.publicKey;
    }

    const isRecipientActive = (selectedRecipient.status === 'ACTIVE' || selectedRecipient.isActive) && Boolean(pubKey);
    if (!isRecipientActive) {
      setSharing(false);
      setErrorMsg('Cannot share file with this member. The recipient account has pending setup and must set up their encryption keys before files can be shared with them.');
      return;
    }

    const result = await onShare({
      fileId: file.id,
      recipientUserId: selectedRecipient.id,
      recipientPublicKey: pubKey,
      accessLevel: blockedOps.length > 0 ? 'READ' : 'FULL',
      blockedOperations: blockedOps,
    });

    setSharing(false);
    if (result.success) {
      setStatusMsg(`File successfully shared with ${selectedRecipient.name || selectedRecipient.email}.`);
      setSelectedRecipient(null);
      setSearchQuery('');
    } else {
      setErrorMsg(result.error || 'Failed to share file.');
    }
  };

  const handleRevokeSubmit = async (recipientUserId) => {
    setRevoking(recipientUserId);
    setStatusMsg(null);
    setErrorMsg(null);

    const result = await onRevoke(file.id, recipientUserId);
    setRevoking(null);

    if (result.success) {
      setStatusMsg('Recipient file access revoked successfully.');
    } else {
      setErrorMsg(result.error || 'Failed to revoke file share.');
    }
  };

  const recipientPermissions = selectedRecipient
    ? userPermissionsCache?.[selectedRecipient.id]
    : null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Share File: ${file.originalName}`}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {statusMsg && <Alert type="success" message={statusMsg} />}
        {errorMsg && <Alert type="danger" message={errorMsg} />}

        {/* Share New Recipient Panel */}
        <form onSubmit={handleShareSubmit} style={styles.formContainer}>
          <div>
            <div style={{ fontWeight: '700', fontSize: '0.925rem', color: 'var(--text-primary)' }}>
              Select Recipient Member
            </div>
            <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Search non-owner members to grant end-to-end encrypted file access keys.
            </div>
          </div>

          {/* Search Input Box */}
          <div style={styles.searchWrapper}>
            <Search size={16} style={styles.searchIcon} />
            <input
              type="text"
              className="form-control"
              placeholder="Search by member name or email address..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ paddingLeft: '2.5rem' }}
            />
          </div>

          {/* Recipient Cards List */}
          <div style={styles.resultsList}>
            {searching ? (
              <div style={styles.searchingNotice}>Searching organization members...</div>
            ) : searchResults.length > 0 ? (
              searchResults.map((member) => {
                const isSelected = selectedRecipient?.id === member.id;
                const isMemberActive = (member.status === 'ACTIVE' || member.isActive) && Boolean(member.publicKeyRegistered && member.publicKey);
                const initial = (member.name || member.email || 'U').charAt(0).toUpperCase();

                return (
                  <div
                    key={member.id}
                    onClick={() => handleSelectRecipient(member)}
                    style={{
                      ...styles.resultItem,
                      ...(isSelected ? styles.resultItemSelected : {}),
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <div style={styles.avatarBadge}>
                        {initial}
                      </div>

                      <div>
                        <div style={{ fontWeight: '600', fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                          {member.name || member.email}
                        </div>
                        {member.name && (
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {member.email}
                          </div>
                        )}
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                      {isMemberActive ? (
                        <span className="badge badge-key-active">
                          <Key size={11} /> ACTIVE (E2EE Ready)
                        </span>
                      ) : (
                        <span className="badge badge-key-pending">
                          <ShieldAlert size={11} /> SETUP REQUIRED
                        </span>
                      )}

                      {isSelected && <CheckCircle2 size={18} color="var(--accent-emerald)" />}
                    </div>
                  </div>
                );
              })
            ) : (
              <div style={styles.searchingNotice}>No matching organization members found.</div>
            )}
          </div>

          {/* Selected Recipient & Restriction Configuration Panel */}
          {selectedRecipient && (() => {
            const isSelectedActive = (selectedRecipient.status === 'ACTIVE' || selectedRecipient.isActive) && Boolean(selectedRecipient.publicKeyRegistered && selectedRecipient.publicKey);

            return (
              <div style={styles.recipientConfigBox}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-color)' }}>
                  <div>
                    <div style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                      {selectedRecipient.name || selectedRecipient.email}
                    </div>
                    {recipientPermissions && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                        Roles: {recipientPermissions.roles?.map((r) => r.name).join(', ') || 'Standard Member'}
                      </div>
                    )}
                  </div>

                  <span className={`badge ${isSelectedActive ? 'badge-key-active' : 'badge-key-pending'}`}>
                    {isSelectedActive ? <Key size={11} /> : <ShieldAlert size={11} />}
                    {isSelectedActive ? 'ACTIVE (E2EE Ready)' : 'SETUP REQUIRED'}
                  </span>
                </div>

                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
                    Optionally Restrict Recipient Operations:
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {[
                      { op: 'FILE_SHARE', label: 'Block Re-sharing (Prevent recipient from sharing file)' },
                      { op: 'FILE_REVOKE', label: 'Block Revocation (Prevent recipient from revoking access)' },
                      { op: 'FILE_DELETE', label: 'Block File Deletion (Prevent recipient from deleting file)' },
                    ].map(({ op, label }) => {
                      const isBlocked = blockedOps.includes(op);
                      return (
                        <label
                          key={op}
                          style={{
                            ...styles.checkboxCard,
                            ...(isBlocked ? styles.checkboxCardActive : {}),
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={isBlocked}
                            onChange={() => handleOpToggle(op)}
                            disabled={!isSelectedActive}
                          />
                          <span>{label}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                {isSelectedActive ? (
                  <button
                    type="submit"
                    disabled={sharing}
                    className="btn btn-primary"
                    style={{ width: '100%', justifyContent: 'center', padding: '0.65rem' }}
                  >
                    <Share2 size={16} />
                    <span>{sharing ? 'Encrypting & Sharing DEK...' : `Share File Access`}</span>
                  </button>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <button
                      type="button"
                      disabled
                      className="btn btn-secondary"
                      style={{ width: '100%', justifyContent: 'center', padding: '0.65rem', opacity: 0.6, cursor: 'not-allowed' }}
                    >
                      <Lock size={16} />
                      <span>SETUP REQUIRED - CANNOT SHARE E2EE</span>
                    </button>
                    <Alert type="warning" message="This member has status 'SETUP REQUIRED' and has not set up their encryption keys yet. Tell the user to complete account setup first." />
                  </div>
                )}
              </div>
            );
          })()}
        </form>

        {/* Existing Active File Shares Table */}
        <div>
          <div style={{ fontWeight: '700', fontSize: '0.9rem', color: 'var(--text-primary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={16} color="var(--accent-blue)" />
            <span>Active File Access Shares ({fileShares?.length || 0})</span>
          </div>

          {fileShares && fileShares.length > 0 ? (
            <div className="table-container" style={{ maxHeight: '200px', overflowY: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Recipient</th>
                    <th>Access Status</th>
                    <th>Blocked Operations</th>
                    <th style={{ textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {fileShares.map((share) => (
                    <tr key={share.userId}>
                      <td>
                        <div style={{ fontWeight: '600', fontSize: '0.85rem' }}>{share.name || share.email}</div>
                        {share.name && <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>{share.email}</div>}
                      </td>
                      <td>
                        <span className={`badge ${share.blockedOperations?.length > 0 ? 'badge-restricted' : 'badge-active'}`}>
                          {share.blockedOperations?.length > 0 ? 'RESTRICTED' : 'FULL ACCESS'}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {share.blockedOperations?.length > 0 ? share.blockedOperations.join(', ') : 'None'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          onClick={() => handleRevokeSubmit(share.userId)}
                          disabled={revoking === share.userId}
                          className="btn btn-danger btn-sm"
                          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                        >
                          <Trash2 size={12} />
                          <span>{revoking === share.userId ? 'Revoking...' : 'Revoke'}</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ fontSize: '0.825rem', color: 'var(--text-muted)', fontStyle: 'italic', padding: '0.5rem 0' }}>
              This file is currently not shared with any organization members.
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}

const styles = {
  formContainer: {
    padding: '1.25rem',
    backgroundColor: 'var(--bg-dark-card)',
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  searchWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
    width: '100%',
  },
  searchIcon: {
    position: 'absolute',
    left: '0.9rem',
    color: 'var(--text-muted)',
    pointerEvents: 'none',
  },
  resultsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    maxHeight: '180px',
    overflowY: 'auto',
    paddingRight: '0.2rem',
  },
  resultItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.7rem 0.9rem',
    borderRadius: '8px',
    border: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-dark-input)',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  resultItemSelected: {
    borderColor: 'var(--accent-blue)',
    backgroundColor: 'rgba(59, 130, 246, 0.08)',
    boxShadow: '0 0 10px rgba(59, 130, 246, 0.15)',
  },
  avatarBadge: {
    width: '32px',
    height: '32px',
    borderRadius: '8px',
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'var(--accent-blue)',
    fontWeight: '700',
    fontSize: '0.85rem',
    flexShrink: 0,
  },
  searchingNotice: {
    fontSize: '0.825rem',
    color: 'var(--text-muted)',
    fontStyle: 'italic',
    padding: '0.8rem',
    textAlign: 'center',
    backgroundColor: 'var(--bg-dark-input)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
  },
  recipientConfigBox: {
    padding: '1rem',
    backgroundColor: 'var(--bg-dark-input)',
    borderRadius: '8px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem',
    marginTop: '0.25rem',
  },
  checkboxCard: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
    padding: '0.55rem 0.75rem',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-dark-card)',
    cursor: 'pointer',
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    transition: 'all 0.15s ease',
  },
  checkboxCardActive: {
    borderColor: 'var(--accent-amber)',
    backgroundColor: 'rgba(245, 158, 11, 0.06)',
    color: 'var(--text-primary)',
  },
};

