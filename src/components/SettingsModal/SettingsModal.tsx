import { useEffect } from 'react';
import { Zap, Shield, Timer, Network, ShieldCheck, EyeOff, ListChecks, Route } from 'lucide-react';
import { useSettings } from '../../context/ThreatModelContext';
import type { PathwayMitigationType, MitigatedVisibility } from '../../data/schema';
import {
  PATHWAY_MITIGATION_DEFINITIONS,
  PATHWAY_MITIGATION_LABELS,
  PATHWAY_MITIGATION_DESCRIPTIONS,
  DEFAULT_PATHWAY_MITIGATION_SETTINGS,
  PATHWAY_REDUCTION_MIN,
  PATHWAY_REDUCTION_MAX,
  PATHWAY_REDUCTION_STEP,
} from '../../data/schema';
import { MITIGATION_PROVIDER_NAMES } from '../../data/mitigationMappings';
import './SettingsModal.css';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

// Icons for known mitigation types; a type added by a newer catalogue gets the fallback.
const MITIGATION_ICONS: Partial<Record<PathwayMitigationType, typeof Zap>> = {
  'ddos-protection': Zap,
  'waf-protection': Shield,
  'rate-limiting': Timer,
  'network-firewall': Network,
};
const FALLBACK_MITIGATION_ICON = ShieldCheck;

// Every mitigation type the catalogue defines, in catalogue order.
const MITIGATION_TYPES = PATHWAY_MITIGATION_DEFINITIONS.map(m => m.id);

// One sub-toggle per kind of mitigation, under "Hide all mitigated threats".
const VISIBILITY_OPTIONS: { key: keyof MitigatedVisibility; label: string; description: string }[] = [
  {
    key: 'hideUpstream',
    label: 'Hide threats mitigated by upstream protection',
    description:
      'Threats removed by a protective technology earlier in the data flow. '
  },
  {
    key: 'hideConnection',
    label: 'Hide connection threats mitigated by enforced encryption',
    description: 'Connection threats where the service being called enforces encrypted connections.',
  },
  {
    key: 'hideControls',
    label: 'Hide threats mitigated by recommended controls',
    description: 'Threats marked as mitigated because all their recommended controls are ticked.'
  },
];

export default function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const { pathwayMitigationSettings, updatePathwayMitigationSettings } = useSettings();

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  // Settings are normalised on import, but fall back to defaults
  const getConfig = (type: PathwayMitigationType) =>
    pathwayMitigationSettings.mitigations[type] ?? DEFAULT_PATHWAY_MITIGATION_SETTINGS.mitigations[type];

  const handleMarkControlsToggle = () => {
    updatePathwayMitigationSettings({
      ...pathwayMitigationSettings,
      markControlsMitigated: !pathwayMitigationSettings.markControlsMitigated,
    });
  };

  const visibility = pathwayMitigationSettings.mitigatedVisibility;
  // Hiding control-mitigated threats only means something once they can be
  // marked as mitigated, so that toggle is disabled until then.
  const isOptionAvailable = (key: keyof MitigatedVisibility) =>
    key !== 'hideControls' || pathwayMitigationSettings.markControlsMitigated;
  const availableOptions = VISIBILITY_OPTIONS.filter(o => isOptionAvailable(o.key));
  const hiddenCount = availableOptions.filter(o => visibility[o.key]).length;
  const allHidden = hiddenCount === availableOptions.length;

  const setVisibility = (next: MitigatedVisibility) => {
    updatePathwayMitigationSettings({ ...pathwayMitigationSettings, mitigatedVisibility: next });
  };

  // The "hide all" toggle is on only when every available sub-toggle is;
  // switching it sets them all together. A disabled sub-toggle keeps its value.
  const handleHideAllToggle = () => {
    const next = { ...visibility };
    for (const o of availableOptions) next[o.key] = !allHidden;
    setVisibility(next);
  };

  const handleVisibilityToggle = (key: keyof MitigatedVisibility) => {
    setVisibility({ ...visibility, [key]: !visibility[key] });
  };

  const handleMasterToggle = () => {
    updatePathwayMitigationSettings({
      ...pathwayMitigationSettings,
      enabled: !pathwayMitigationSettings.enabled,
    });
  };

  const handleMitigationToggle = (type: PathwayMitigationType) => {
    const current = getConfig(type);
    updatePathwayMitigationSettings({
      ...pathwayMitigationSettings,
      mitigations: {
        ...pathwayMitigationSettings.mitigations,
        [type]: {
          ...current,
          enabled: !current.enabled,
        },
      },
    });
  };

  const handleModeChange = (type: PathwayMitigationType, mode: 'remove' | 'reduce') => {
    const current = getConfig(type);
    updatePathwayMitigationSettings({
      ...pathwayMitigationSettings,
      mitigations: {
        ...pathwayMitigationSettings.mitigations,
        [type]: {
          ...current,
          mode,
        },
      },
    });
  };

  const handleReductionChange = (type: PathwayMitigationType, percent: number) => {
    const current = getConfig(type);
    updatePathwayMitigationSettings({
      ...pathwayMitigationSettings,
      mitigations: {
        ...pathwayMitigationSettings.mitigations,
        [type]: {
          ...current,
          reductionPercent: percent,
        },
      },
    });
  };

  // One sub-option per mitigation type, under "Enable pathway mitigations".
  const renderMitigationOption = (type: PathwayMitigationType) => {
    const config = getConfig(type);
    const Icon = MITIGATION_ICONS[type] ?? FALLBACK_MITIGATION_ICON;
    const masterOn = pathwayMitigationSettings.enabled;
    const allProviderNames = MITIGATION_PROVIDER_NAMES[type] ?? [];
    const providerNames = allProviderNames.slice(0, 3).join(', ');
    const moreCount = allProviderNames.length - 3;

    return (
      <div key={type} className="pathway-option">
        <div className={`visibility-option ${masterOn ? '' : 'unavailable'}`}>
          <div className="visibility-option-text">
            <span className="visibility-option-label pathway-option-label">
              <Icon size={14} className="mitigation-icon" />
              {PATHWAY_MITIGATION_LABELS[type]}
            </span>
            <span className="mitigation-description">
              {PATHWAY_MITIGATION_DESCRIPTIONS[type]}
            </span>
            <span className="mitigation-providers">
              Technologies: {providerNames}{moreCount > 0 && `, +${moreCount} more`}
            </span>
          </div>
          <button
            className={`toggle-switch ${config.enabled ? 'on' : 'off'}`}
            onClick={() => handleMitigationToggle(type)}
            disabled={!masterOn}
            aria-label={`Toggle ${PATHWAY_MITIGATION_LABELS[type]}`}
            aria-pressed={config.enabled}
          >
            <span className="toggle-knob" />
          </button>
        </div>

        {config.enabled && masterOn && (
          <div className="pathway-option-settings">
            <div className="mode-selector">
              <label className="mode-option">
                <input
                  type="radio"
                  name={`${type}-mode`}
                  checked={config.mode === 'remove'}
                  onChange={() => handleModeChange(type, 'remove')}
                />
                <span>Remove threats</span>
              </label>
              <label className="mode-option">
                <input
                  type="radio"
                  name={`${type}-mode`}
                  checked={config.mode === 'reduce'}
                  onChange={() => handleModeChange(type, 'reduce')}
                />
                <span>Reduce severity</span>
              </label>
            </div>

            {config.mode === 'reduce' && (
              <div className="settings-reduction-slider">
                <div className="settings-reduction-label">
                  Reduction: <strong>{config.reductionPercent}%</strong>
                </div>
                <input
                  type="range"
                  min={PATHWAY_REDUCTION_MIN}
                  max={PATHWAY_REDUCTION_MAX}
                  step={PATHWAY_REDUCTION_STEP}
                  value={config.reductionPercent}
                  onChange={(e) => handleReductionChange(type, parseInt(e.target.value, 10))}
                  aria-label={`${PATHWAY_MITIGATION_LABELS[type]} reduction percentage`}
                />
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="settings-modal-overlay" onClick={handleOverlayClick}>
      <div className="settings-modal">
        <button className="settings-modal-close" onClick={onClose} title="Close">
          &times;
        </button>

        <h2 className="settings-modal-title">Model Settings</h2>

        <div className="settings-modal-content">
          <section className="settings-section">
            <div className="section-header">
              <h3>Threat Model Behaviour</h3>
            </div>

            <div
              className={`mitigation-card ${pathwayMitigationSettings.enabled ? 'enabled' : 'disabled'}`}
              role="group"
              aria-labelledby="pathway-mitigations-heading"
            >
              <div className="mitigation-header">
                <div className="mitigation-title">
                  <Route size={16} className="mitigation-icon" />
                  <span id="pathway-mitigations-heading">Pathway mitigations</span>
                </div>
              </div>

              <div className="mitigation-info">
                <span className="mitigation-description">
                  Protective technologies upstream in the data flow mitigate threats on downstream nodes.
                </span>
              </div>

              <div className="mitigation-options visibility-options">
                <div className="visibility-option">
                  <div className="visibility-option-text">
                    <span className="visibility-option-label">Enable pathway mitigations</span>
                  </div>
                  <button
                    className={`toggle-switch ${pathwayMitigationSettings.enabled ? 'on' : 'off'}`}
                    onClick={handleMasterToggle}
                    aria-label="Enable pathway mitigations"
                    aria-pressed={pathwayMitigationSettings.enabled}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>

                <div className="visibility-sub-options">
                  {MITIGATION_TYPES.map(renderMitigationOption)}
                </div>
              </div>
            </div>
          </section>

          {/* Not gated by the master toggle: encrypted connections are mitigated regardless */}
          <section className="settings-section">
            <div className="section-header">
              <h3>Display</h3>
            </div>

            <div className={`mitigation-card display-card ${pathwayMitigationSettings.markControlsMitigated ? 'enabled' : 'disabled'}`}>
              <div className="mitigation-header">
                <div className="mitigation-title">
                  <ListChecks size={16} className="mitigation-icon" />
                  <span>Mark threats with all recommended controls ticked as mitigated</span>
                </div>
                <button
                  className={`toggle-switch ${pathwayMitigationSettings.markControlsMitigated ? 'on' : 'off'}`}
                  onClick={handleMarkControlsToggle}
                  aria-label="Mark threats with all recommended controls ticked as mitigated"
                  aria-pressed={pathwayMitigationSettings.markControlsMitigated}
                >
                  <span className="toggle-knob" />
                </button>
              </div>

              <div className="mitigation-info">
                <span className="mitigation-description">
                  Moves these threats into the Mitigated group, so they no longer count towards risk totals.
                </span>
              </div>
            </div>

            <div
              className={`mitigation-card ${hiddenCount > 0 ? 'enabled' : 'disabled'}`}
              role="group"
              aria-labelledby="mitigated-visibility-heading"
            >
              <div className="mitigation-header">
                <div className="mitigation-title">
                  <EyeOff size={16} className="mitigation-icon" />
                  <span id="mitigated-visibility-heading">Mitigated threat visibility</span>
                </div>
              </div>

              <div className="mitigation-info">
                <span className="mitigation-description">
                  Hidden threats are removed from the threat list and left out of exported reports.
                </span>
              </div>

              <div className="mitigation-options visibility-options">
                <div className="visibility-option">
                  <div className="visibility-option-text">
                    <span className="visibility-option-label">Hide all mitigated threats in below categories</span>
                  </div>
                  <button
                    className={`toggle-switch ${allHidden ? 'on' : 'off'}`}
                    onClick={handleHideAllToggle}
                    aria-label="Hide all mitigated threats in below categories"
                    aria-pressed={allHidden ? true : hiddenCount > 0 ? 'mixed' : false}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>

                <div className="visibility-sub-options">
                  {VISIBILITY_OPTIONS.map(({ key, label, description }) => (
                    <div
                      key={key}
                      className={`visibility-option ${isOptionAvailable(key) ? '' : 'unavailable'}`}
                    >
                      <div className="visibility-option-text">
                        <span className="visibility-option-label">{label}</span>
                        <span className="mitigation-description">{description}</span>
                      </div>
                      <button
                        className={`toggle-switch ${visibility[key] ? 'on' : 'off'}`}
                        onClick={() => handleVisibilityToggle(key)}
                        disabled={!isOptionAvailable(key)}
                        aria-label={label}
                        aria-pressed={visibility[key]}
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
