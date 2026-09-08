import React, { useState, useEffect } from 'react';
import { Sliders, Globe, Plus, Trash2 } from 'lucide-react';
import Card from '../components/Common/Card';

export default function PoliciesPage({
  orgPolicy,
  onUpdatePolicy,
  onAddGeoLocation,
  onRemoveGeoLocation,
  userPermissions,
  currentUser,
}) {
  const [requireStepUpLocation, setRequireStepUpLocation] = useState(true);
  const [requireStepUpSensitive, setRequireStepUpSensitive] = useState(true);
  const [enforceGeoFencing, setEnforceGeoFencing] = useState(false);
  const [updating, setUpdating] = useState(false);

  const [country, setCountry] = useState('IN');
  const [stateName, setStateName] = useState('');
  const [cityName, setCityName] = useState('');
  const [addingGeo, setAddingGeo] = useState(false);

  const isOwner = currentUser?.isOwner;
  const canManage = isOwner || (userPermissions && userPermissions.includes('ORG_MANAGE'));

  useEffect(() => {
    if (orgPolicy) {
      setRequireStepUpLocation(Boolean(orgPolicy.require_stepup_new_location));
      setRequireStepUpSensitive(Boolean(orgPolicy.require_stepup_sensitive_file));
      setEnforceGeoFencing(Boolean(orgPolicy.enforce_geo_fencing));
    }
  }, [orgPolicy]);

  const handlePolicyToggleSubmit = async (e) => {
    e.preventDefault();
    setUpdating(true);
    await onUpdatePolicy({
      require_stepup_new_location: requireStepUpLocation,
      require_stepup_sensitive_file: requireStepUpSensitive,
      enforce_geo_fencing: enforceGeoFencing,
    });
    setUpdating(false);
  };

  const handleAddGeoSubmit = async (e) => {
    e.preventDefault();
    if (!country) return;

    setAddingGeo(true);
    await onAddGeoLocation({
      allowedCountry: country.trim().toUpperCase(),
      allowedState: stateName.trim() || null,
      allowedCity: cityName.trim() || null,
    });
    setAddingGeo(false);
    setStateName('');
    setCityName('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Core Policy Switches */}
      <Card title="Organization Zero Trust Security Switches">
        <form onSubmit={handlePolicyToggleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.25rem' }}>
            {/* Policy Toggle 1 */}
            <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
                <span style={{ fontWeight: '600', color: 'var(--text-primary)', fontSize: '0.9rem' }}>Require Step-Up on Location Shift</span>
                <input
                  type="checkbox"
                  checked={requireStepUpLocation}
                  onChange={(e) => setRequireStepUpLocation(e.target.checked)}
                  disabled={!canManage}
                />
              </label>
              <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
                Triggers password re-authentication when client IP or geographic context shifts from previous known device session.
              </div>
            </div>

            {/* Policy Toggle 2 */}
            <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
                <span style={{ fontWeight: '600', color: 'var(--text-primary)', fontSize: '0.9rem' }}>Require Step-Up for Sensitive Operations</span>
                <input
                  type="checkbox"
                  checked={requireStepUpSensitive}
                  onChange={(e) => setRequireStepUpSensitive(e.target.checked)}
                  disabled={!canManage}
                />
              </label>
              <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
                Triggers step-up re-authentication for high-impact operations on CONFIDENTIAL files.
              </div>
            </div>

            {/* Policy Toggle 3 */}
            <div style={{ backgroundColor: 'var(--bg-dark-input)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
                <span style={{ fontWeight: '600', color: 'var(--text-primary)', fontSize: '0.9rem' }}>Enforce Strict Geo-Fencing</span>
                <input
                  type="checkbox"
                  checked={enforceGeoFencing}
                  onChange={(e) => setEnforceGeoFencing(e.target.checked)}
                  disabled={!canManage}
                />
              </label>
              <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
                Strictly denies access (HTTP 403) if client IP falls outside organization's multi-geographic allowed policy list.
              </div>
            </div>
          </div>

          {canManage && (
            <div>
              <button type="submit" disabled={updating} className="btn btn-primary btn-sm">
                {updating ? 'Updating Policies...' : 'Save Core Security Settings'}
              </button>
            </div>
          )}
        </form>
      </Card>

      {/* Multi-Geographic Allowed Locations Policy Table & Form */}
      <Card title="Multi-Geographic Allowed Locations (organization_geo_policies)">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {canManage && (
            <form onSubmit={handleAddGeoSubmit} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', backgroundColor: 'var(--bg-dark-input)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label">Country Code (ISO)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. IN, US, UK"
                  value={country}
                  onChange={(e) => setCountry(e.target.value)}
                  maxLength={2}
                  required
                />
              </div>

              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label">State / Region (Optional)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Maharashtra, California"
                  value={stateName}
                  onChange={(e) => setStateName(e.target.value)}
                />
              </div>

              <div className="form-group" style={{ flex: 1 }}>
                <label className="form-label">City (Optional)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Mumbai, San Francisco"
                  value={cityName}
                  onChange={(e) => setCityName(e.target.value)}
                />
              </div>

              <button type="submit" disabled={addingGeo || !country} className="btn btn-primary btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                <Plus size={14} />
                <span>{addingGeo ? 'Adding...' : 'Add Allowed Location'}</span>
              </button>
            </form>
          )}

          {/* Allowed Locations Table */}
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Allowed Country</th>
                  <th>Allowed State</th>
                  <th>Allowed City</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {orgPolicy?.allowedLocations && orgPolicy.allowedLocations.length > 0 ? (
                  orgPolicy.allowedLocations.map((loc) => (
                    <tr key={loc.id}>
                      <td className="font-mono" style={{ fontWeight: '600', color: 'var(--accent-emerald)' }}>{loc.allowed_country}</td>
                      <td>{loc.allowed_state || 'ALL STATES (*)'}</td>
                      <td>{loc.allowed_city || 'ALL CITIES (*)'}</td>
                      <td style={{ textAlign: 'right' }}>
                        {canManage && (
                          <button onClick={() => onRemoveGeoLocation(loc.id)} className="btn btn-danger btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                            <Trash2 size={12} />
                            <span>Remove</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4">
                      <div className="empty-state">
                        <Globe size={40} style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }} />
                        <div className="empty-state-title">No Allowed Geographic Rules Defined</div>
                        <div className="empty-state-desc">Add allowed country, state, or city rules above.</div>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </Card>
    </div>
  );
}
