import React from 'react';

export default function Badge({ classification, type, text }) {
  if (classification) {
    const norm = String(classification).toUpperCase();
    if (norm === 'PUBLIC') return <span className="badge badge-public">PUBLIC</span>;
    if (norm === 'INTERNAL' || norm === 'NORMAL') return <span className="badge badge-internal">INTERNAL</span>;
    if (norm === 'CONFIDENTIAL' || norm === 'SENSITIVE') return <span className="badge badge-confidential">CONFIDENTIAL</span>;
    if (norm === 'HIGHLY_CONFIDENTIAL' || norm === 'HIGHLY_SENSITIVE') return <span className="badge badge-highly-confidential">HIGHLY CONFIDENTIAL</span>;
  }

  if (type === 'owner') return <span className="badge badge-owner">OWNER</span>;
  if (type === 'active') return <span className="badge badge-active">{text || 'ACTIVE'}</span>;

  return <span className="badge badge-public">{text || 'INFO'}</span>;
}
