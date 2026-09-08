import React from 'react';

export function Card({ title, action, children, style = {} }) {
  return (
    <div className="card" style={style}>
      {title && (
        <div className="card-header">
          <div className="card-title">{title}</div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

export function StatCard({ title, value, subtext, icon: Icon, color = 'var(--accent-blue)', onClick }) {
  const renderIcon = () => {
    if (!Icon) return null;
    if (React.isValidElement(Icon)) return Icon;
    if (typeof Icon === 'function' || typeof Icon === 'object') {
      const Component = Icon;
      return <Component size={24} color={color} />;
    }
    return Icon;
  };

  return (
    <div
      className="card"
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1.25rem',
        ...(onClick ? { cursor: 'pointer' } : {}),
      }}
    >
      {Icon && (
        <div
          style={{
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            backgroundColor: `${color}15`,
            border: `1px solid ${color}30`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: color,
            flexShrink: 0,
          }}
        >
          {renderIcon()}
        </div>
      )}
      <div>
        <div style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          {title}
        </div>
        <div style={{ fontSize: '1.6rem', fontWeight: '700', color: 'var(--text-primary)', margin: '0.2rem 0' }}>
          {value}
        </div>
        {subtext && (
          <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
            {subtext}
          </div>
        )}
      </div>
    </div>
  );
}

export default Card;
