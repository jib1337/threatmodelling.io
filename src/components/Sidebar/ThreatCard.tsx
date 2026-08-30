import { useState, useCallback, memo } from 'react';
import { Lock, ArrowUp, ArrowDown, RotateCcw } from 'lucide-react';
import type { ActiveThreat, ThreatSeverity } from '../../data/schema';
import {
  STRIDE_LABELS,
  THREAT_SEVERITY_LABELS,
  DATA_SENSITIVITY_LABELS,
  RISK_LEVEL_LABELS,
  PATHWAY_MITIGATION_LABELS,
} from '../../data/schema';
import { useActions, useThreats } from '../../context/ThreatModelContext';
import { buildControlKey } from '../../utils/controlFingerprint';
import './ThreatCard.css';

interface ThreatCardProps {
  activeThreat: ActiveThreat;
}

export default memo(function ThreatCard({ activeThreat }: ThreatCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const { threat, sourceNodeId, sourceTechName, sourceTechnologyId, overriddenSeverity, riskLevel, riskScore, sensitivity, isEscalated, effectiveSensitivity, zoneMultiplier, context, pathwayMitigatedBy, techMitigations } = activeThreat;
  const { setSeverityOverride, setControlImplemented } = useActions();
  const { implementedControls } = useThreats();

  const displaySeverity = overriddenSeverity ?? threat.severity;
  const overrideKey = sourceTechnologyId ? `${sourceTechnologyId}::${threat.id}` : '';

  const handleSeverityChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    e.stopPropagation();
    if (!overrideKey) return;
    const newSeverity = e.target.value as ThreatSeverity;
    setSeverityOverride(overrideKey, newSeverity === threat.severity ? null : newSeverity);
  }, [overrideKey, threat.severity, setSeverityOverride]);

  const handleSeverityReset = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (!overrideKey) return;
    setSeverityOverride(overrideKey, null);
  }, [overrideKey, setSeverityOverride]);

  return (
    <div className={`threat-card ${isExpanded ? 'expanded' : ''} risk-${riskLevel}`}>
      <button
        className="threat-card-header"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="threat-info">
          <div className="threat-name-row">
            <span className="threat-name">{threat.name}</span>
            {isEscalated && (
              <span className="escalation-indicator" title="Risk elevated due to downstream system sensitivity">
                <ArrowUp size={12} strokeWidth={3} />
              </span>
            )}
            {zoneMultiplier && zoneMultiplier < 1 && (
              <span className="boundary-indicator" title={`${Math.round((1 - zoneMultiplier) * 100)}% risk reduction from private network`}>
                <Lock size={12} strokeWidth={2.5} />
              </span>
            )}
            {pathwayMitigatedBy && (
              <span
                className="pathway-mitigation-indicator"
                title={`Mitigated by ${pathwayMitigatedBy.mitigatingTechName} (${PATHWAY_MITIGATION_LABELS[pathwayMitigatedBy.mitigationType]}) - ${pathwayMitigatedBy.reductionPercent}% reduction`}
              >
                <ArrowDown size={12} strokeWidth={3} />
              </span>
            )}
            <span className={`risk-badge risk-${riskLevel}`}>
              {riskScore}
            </span>
          </div>
          <span className="threat-source">{sourceTechName}</span>
        </div>
        <span className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>▶</span>
      </button>

      {isExpanded && (
        <div className="threat-card-content">
          <p className="threat-description">{threat.description}</p>

          {context && (
            <div className="threat-context">
              <span className="threat-context-label">Examples for {sourceTechName}:</span>
              <span className="threat-context-text">{context}</span>
            </div>
          )}

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
                <span className="risk-label">Sensitivity:</span>
                <span className={`sensitivity-tag data-sensitivity-${sensitivity}`}>
                  {DATA_SENSITIVITY_LABELS[sensitivity]}
                </span>
              </div>
              {isEscalated && effectiveSensitivity && (
                <div className="risk-item escalation-note">
                  <span className="risk-label">Effective:</span>
                  <span className={`sensitivity-tag data-sensitivity-${effectiveSensitivity}`}>
                    {DATA_SENSITIVITY_LABELS[effectiveSensitivity]}
                  </span>
                  <span className="escalation-reason">↑ downstream</span>
                </div>
              )}
              <div className="risk-item">
                <span className="risk-label">Risk Level:</span>
                <span className={`risk-level-tag risk-${riskLevel}`}>
                  {RISK_LEVEL_LABELS[riskLevel]} ({riskScore})
                </span>
              </div>
              {zoneMultiplier && zoneMultiplier < 1 && (
                <div className="risk-item boundary-note">
                  <span className="risk-label">Network:</span>
                  <span className="boundary-tag">
                    Private ({Math.round((1 - zoneMultiplier) * 100)}% reduction)
                  </span>
                </div>
              )}
              {pathwayMitigatedBy && (
                <div className="risk-item pathway-mitigation-note">
                  <span className="risk-label">Mitigated:</span>
                  <span className="pathway-mitigation-tag">
                    {pathwayMitigatedBy.mitigatingTechName} ({pathwayMitigatedBy.reductionPercent}% reduction)
                  </span>
                </div>
              )}
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

          {(techMitigations && techMitigations.length > 0) ? (
            <div className="threat-section">
              <h4>Mitigating Controls</h4>
              <ul className="controls-list">
                {techMitigations.map((mitigation, index) => {
                  const key = buildControlKey(
                    { kind: 'node-tech', nodeId: sourceNodeId, threatId: threat.id },
                    mitigation,
                  );
                  const implemented = !!implementedControls[key];
                  return (
                    <li key={index} className={`control-item ${implemented ? 'implemented' : ''}`}>
                      <label className="control-checkbox-label">
                        <input
                          type="checkbox"
                          className="control-checkbox"
                          checked={implemented}
                          onChange={e => setControlImplemented(key, e.target.checked)}
                          onClick={e => e.stopPropagation()}
                        />
                        <span className="control-text">{mitigation}</span>
                      </label>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : threat.controls.length > 0 && (
            <div className="threat-section">
              <h4>Mitigating Controls</h4>
              <ul className="controls-list">
                {threat.controls.map(control => {
                  const key = buildControlKey(
                    { kind: 'node-generic', nodeId: sourceNodeId, threatId: threat.id },
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
