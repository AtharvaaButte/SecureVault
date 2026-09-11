import React from 'react';

export default function Badge({ classification, type, text }) {
  if (classification) {
    const norm = String(classification).toUpperCase();
    if (norm === 'PUBLIC') return <span className="badge badge-public" title="Public resource: normal authorization, no step-up re-authentication required">PUBLIC</span>;
    if (norm === 'INTERNAL' || norm === 'NORMAL') return <span className="badge badge-internal" title="Internal resource: normal authorization, no step-up re-authentication required">INTERNAL</span>;
    if (norm === 'CONFIDENTIAL' || norm === 'SENSITIVE') return <span className="badge badge-confidential" title="Confidential resource: Download allowed without step-up; protected actions (Share, Revoke, Delete) require step-up">CONFIDENTIAL</span>;
    if (norm === 'HIGHLY_CONFIDENTIAL' || norm === 'HIGHLY_SENSITIVE') return <span className="badge badge-highly-confidential" title="Highly Confidential resource: EVERY action (including Download) requires step-up re-authentication">HIGHLY CONFIDENTIAL</span>;
  }

  if (type === 'owner') return <span className="badge badge-owner">OWNER</span>;
  if (type === 'active') return <span className="badge badge-active">{text || 'ACTIVE'}</span>;

  return <span className="badge badge-public">{text || 'INFO'}</span>;
}
