import { useState, useCallback, memo } from 'react';
import { Lock, RotateCcw } from 'lucide-react';
import type { GroupedConnectionThreat } from './ThreatSidebar';
import {
  STRIDE_LABELS,
  THREAT_SEVERITY_LABELS,
  RISK_LEVEL_LABELS,
} from '../../data/schema';
import type { ThreatSeverity } from '../../data/schema';
import { useActions, useThreats } from '../../context/ThreatModelContext';
import { buildControlKey } from '../../utils/controlFingerprint';
import './ThreatCard.css';

interface ConnectionThreatCardProps {
  groupedThreat: GroupedConnectionThreat;
}

export default memo(function ConnectionThreatCard({ groupedThreat }: ConnectionThreatCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const { threat, connections, maxRiskScore, maxRiskLevel } = groupedThreat;
  const { setSeverityOverride, setControlImplemented } = useActions();
  const { implementedControls } = useThreats();

  // Connection threats use the first connection's overriddenSeverity (they share the same override)
  const overriddenSeverity = connections[0]?.overriddenSeverity;
  const displaySeverity = overriddenSeverity ?? threat.severity;
  const overrideKey = `connection::${threat.id}`;

  const handleSeverityChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    e.stopPropagation();
    const newSeverity = e.target.value as ThreatSeverity;
    setSeverityOverride(overrideKey, newSeverity === threat.severity ? null : newSeverity);
  }, [overrideKey, threat.severity, setSeverityOverride]);

  const handleSeverityReset = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setSeverityOverride(overrideKey, null);
  }, [overrideKey, setSeverityOverride]);

  return (
    <div className={`threat-card ${isExpanded ? 'expanded' : ''} risk-${maxRiskLevel} connection-threat-card`}>
      <button
        className="threat-card-header"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="threat-info">
          <div className="threat-name-row">
            <span className="threat-name">{threat.name}</span>
            <span className={`risk-badge risk-${maxRiskLevel}`}>
              {maxRiskScore}
            </span>
          </div>
          <span className="threat-source connection-count">
            Affects {connections.length} connection{connections.length !== 1 ? 's' : ''}
          </span>
        </div>
        <span className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>▶</span>
      </button>

      {isExpanded && (
        <div className="threat-card-content">
          <p className="threat-description">{threat.description}</p>

          <div className="threat-section">
            <h4>Affected Connections</h4>
            <ul className="connections-list">
              {connections.map(conn => (
                <li key={conn.edgeId} className="connection-item">
                  <span className="connection-path">
                    {conn.sourceNodeName} → {conn.targetNodeName}
                  </span>
                  {conn.label && (
                    <span className="connection-label">({conn.label})</span>
                  )}
                  {conn.zoneMultiplier && conn.zoneMultiplier < 1 && (
                    <span className="boundary-indicator" title={`Private network - ${Math.round((1 - conn.zoneMultiplier) * 100)}% reduction`}>
                      <Lock size={12} strokeWidth={2.5} />
                    </span>
                  )}
                  <span className={`connection-risk risk-${conn.riskLevel}`}>
                    {conn.riskScore}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="threat-section">
            <h4>Risk Assessment</h4>
            <div className="risk-details">
              <div className="risk-item severity-selector-item">
                <span className="risk-label">Severity:</span>
                <select
                  className={`severity-selector severity-${displaySeverity}`}
                  value={displaySeverity}
                  onChange={handleSeverityChange}
                  onClick={e => e.stopPropagation()}
                >
                  <option value="low">{THREAT_SEVERITY_LABELS.low}</option>
                  <option value="medium">{THREAT_SEVERITY_LABELS.medium}</option>
                  <option value="high">{THREAT_SEVERITY_LABELS.high}</option>
                  <option value="critical">{THREAT_SEVERITY_LABELS.critical}</option>
                </select>
                {overriddenSeverity && (
                  <button className="severity-reset" onClick={handleSeverityReset} title="Reset to default severity">
                    <RotateCcw size={12} />
                  </button>
                )}
              </div>
              <div className="risk-item">
                <span className="risk-label">Highest Risk:</span>
                <span className={`risk-level-tag risk-${maxRiskLevel}`}>
                  {RISK_LEVEL_LABELS[maxRiskLevel]} ({maxRiskScore})
                </span>
              </div>
            </div>
          </div>

          <div className="threat-section">
            <h4>STRIDE Classification</h4>
            <div className="tag-list">
              {threat.stride.map(category => (
                <span key={category} className={`tag stride-tag ${category}`}>
                  {STRIDE_LABELS[category]}
                </span>
              ))}
            </div>
          </div>

          <div className="threat-section">
            <h4>MITRE ATT&CK</h4>
            <div className="mitre-list">
              {threat.mitreTechniques.map(technique => (
                <div key={technique.id} className="mitre-item">
                  <a
                    href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mitre-link"
                  >
                    <span className="mitre-id">{technique.id}</span>
                    <span className="mitre-name">{technique.name}</span>
                  </a>
                  <span className="mitre-tactic">{technique.tactic}</span>
                </div>
              ))}
            </div>
          </div>

          {threat.controls.length > 0 && (
            <div className="threat-section">
              <h4>Mitigating Controls</h4>
              <ul className="controls-list">
                {threat.controls.map(control => {
                  const key = buildControlKey(
                    { kind: 'connection', threatId: threat.id },
                    control.description,
                  );
                  const implemented = !!implementedControls[key];
                  return (
                    <li key={control.id} className={`control-item ${implemented ? 'implemented' : ''}`}>
                      <label className="control-checkbox-label">
                        <input
                          type="checkbox"
                          className="control-checkbox"
                          checked={implemented}
                          onChange={e => setControlImplemented(key, e.target.checked)}
                          onClick={e => e.stopPropagation()}
                        />
                        <span className="control-text">{control.description}</span>
                      </label>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
});
