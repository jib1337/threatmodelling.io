import { useSelection, useActions } from '../../context/ThreatModelContext';
import { NETWORK_ZONE_LABELS, ZONE_NETWORK_TYPE_LABELS, type ZoneNetworkType } from '../../data/schema';
import './BoundaryPropertiesPanel.css';

export default function BoundaryPropertiesPanel() {
  const { selectedBoundaryId, deselectAll } = useSelection();
  const {
    getBoundaryById,
    updateBoundaryName,
    updateBoundaryType,
    updateBoundaryNetworkType,
    updateBoundaryRiskSettings,
    removeBoundary,
  } = useActions();

  if (!selectedBoundaryId) return null;

  const boundary = getBoundaryById(selectedBoundaryId);
  if (!boundary) return null;

  const { zoneType, networkType, customName, label, riskReductionEnabled, riskReductionPercent } = boundary.data;
  const isPrivate = zoneType === 'private';
  const enabled = riskReductionEnabled ?? true;
  const percent = riskReductionPercent ?? 20;
  const currentNetworkType = networkType ?? 'generic';

  const handleToggleType = () => {
    const newType = zoneType === 'public' ? 'private' : 'public';
    updateBoundaryType(selectedBoundaryId, newType);
  };

  const handleNetworkTypeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    updateBoundaryNetworkType(selectedBoundaryId, e.target.value as ZoneNetworkType);
  };

  const handleToggleReduction = () => {
    updateBoundaryRiskSettings(selectedBoundaryId, !enabled, percent);
  };

  const handlePercentChange = (value: number) => {
    const clampedValue = Math.min(100, Math.max(1, value));
    updateBoundaryRiskSettings(selectedBoundaryId, enabled, clampedValue);
  };

  const handleDelete = () => {
    removeBoundary(selectedBoundaryId);
    deselectAll();
  };

  return (
    <div className="boundary-properties-panel">
      <div className="panel-header">
        <h3>Properties</h3>
        <button
          className="close-button"
          onClick={deselectAll}
          title="Close panel"
        >
          &times;
        </button>
      </div>

      <div className="panel-content">
        <div className="property-section">
          <label className="property-label">Zone Type</label>
          <button
            className={`boundary-type-button boundary-type-${zoneType}`}
            onClick={handleToggleType}
          >
            <span className="boundary-type-label">{NETWORK_ZONE_LABELS[zoneType]}</span>
            <span className="boundary-type-toggle">Switch</span>
          </button>
        </div>

        {isPrivate && (
          <div className="property-section">
            <label className="property-label" htmlFor="network-type-select">
              Network Type
            </label>
            <select
              id="network-type-select"
              className="network-type-select"
              value={currentNetworkType}
              onChange={handleNetworkTypeChange}
            >
              {(Object.keys(ZONE_NETWORK_TYPE_LABELS) as ZoneNetworkType[]).map((type) => (
                <option key={type} value={type}>
                  {ZONE_NETWORK_TYPE_LABELS[type]}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="property-section">
          <label className="property-label" htmlFor="boundary-name-input">
            Display Name
          </label>
          <input
            id="boundary-name-input"
            type="text"
            className="display-name-input"
            value={customName || ''}
            placeholder={label}
            onChange={(e) => updateBoundaryName(selectedBoundaryId, e.target.value)}
          />
        </div>

        {isPrivate && (
          <div className="property-section risk-reduction-section">
            <label className="property-label">Risk Reduction</label>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={enabled}
                onChange={handleToggleReduction}
                className="risk-checkbox"
              />
              <span className="checkbox-text">Enable risk reduction</span>
            </label>

            {enabled && (
              <div className="reduction-slider-container">
                <label className="slider-label">
                  Reduction: <strong>{percent}%</strong>
                </label>
                <input
                  type="range"
                  min="1"
                  max="100"
                  value={percent}
                  onChange={(e) => handlePercentChange(parseInt(e.target.value))}
                  className="reduction-slider"
                />
                <div className="slider-ticks">
                  <span>1%</span>
                  <span>50%</span>
                  <span>100%</span>
                </div>
              </div>
            )}

            {!enabled && (
              <div className="reduction-disabled-info">
                Risk reduction is disabled. Threats in this zone will have their full risk score.
              </div>
            )}
          </div>
        )}

        {!isPrivate && (
          <div className="property-section">
            <div className="public-boundary-info">
              Public zones do not apply risk reduction. Switch to Private Network to enable risk reduction settings.
            </div>
          </div>
        )}

        <div className="property-section">
          <button
            className="delete-boundary-button"
            onClick={handleDelete}
          >
            Delete Zone
          </button>
        </div>
      </div>
    </div>
  );
}
