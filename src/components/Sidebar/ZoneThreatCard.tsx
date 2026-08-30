import { useState, useCallback, memo } from 'react';
import { RotateCcw } from 'lucide-react';
import type { GroupedZoneThreat } from './ThreatSidebar';
import {
  STRIDE_LABELS,
  THREAT_SEVERITY_LABELS,
  RISK_LEVEL_LABELS,
  ZONE_NETWORK_TYPE_LABELS,
} from '../../data/schema';
import type { ThreatSeverity } from '../../data/schema';
import { useActions, useThreats } from '../../context/ThreatModelContext';
import { buildControlKey } from '../../utils/controlFingerprint';
import './ThreatCard.css';

interface ZoneThreatCardProps {
  groupedThreat: GroupedZoneThreat;
}

export default memo(function ZoneThreatCard({ groupedThreat }: ZoneThreatCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const { threat, zones, maxRiskScore, maxRiskLevel } = groupedThreat;
  const { setSeverityOverride, setControlImplemented } = useActions();
  const { implementedControls } = useThreats();

  // Zone threats use the first zone's overriddenSeverity (they share the same override)
  const overriddenSeverity = zones[0]?.overriddenSeverity;
  const displaySeverity = overriddenSeverity ?? threat.severity;
  const overrideKey = `zone::${threat.id}`;

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
    <div className={`threat-card ${isExpanded ? 'expanded' : ''} risk-${maxRiskLevel} zone-threat-card`}>
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
          <span className="threat-source zone-count">
            Affects {zones.length} network zone{zones.length !== 1 ? 's' : ''}
          </span>
        </div>
        <span className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>▶</span>
      </button>

      {isExpanded && (
        <div className="threat-card-content">
          <p className="threat-description">{threat.description}</p>

          {threat.zoneContext && (
            <div className="threat-context">
              <span className="threat-context-label">In network zones:</span>
              <span className="threat-context-text">{threat.zoneContext}</span>
            </div>
          )}

          <div className="threat-section">
            <h4>Affected Network Zones</h4>
            <ul className="zones-list">
              {zones.map(zone => (
                <li key={zone.boundaryId} className="zone-item">
                  <span className="zone-name">{zone.zoneName}</span>
                  {zone.networkType && zone.networkType !== 'generic' && (
                    <span className="zone-type">
                      {ZONE_NETWORK_TYPE_LABELS[zone.networkType]}
                    </span>
                  )}
                  {zone.riskReductionPercent && (
                    <span
                      className="zone-reduction"
                      title={`Risk reduced by ${zone.riskReductionPercent}%`}
                    >
                      -{zone.riskReductionPercent}%
                    </span>
                  )}
                  <span className={`zone-risk risk-${zone.riskLevel}`}>
                    {zone.riskScore}
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
                    { kind: 'zone', threatId: threat.id },
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
