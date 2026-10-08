import { useEffect } from 'react';
import { Zap, Shield, Timer, Network, ShieldCheck } from 'lucide-react';
import { useSettings } from '../../context/ThreatModelContext';
import type { PathwayMitigationType } from '../../data/schema';
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

  const renderMitigationCard = (type: PathwayMitigationType) => {
    const config = getConfig(type);
    const Icon = MITIGATION_ICONS[type] ?? FALLBACK_MITIGATION_ICON;
    const isEnabled = pathwayMitigationSettings.enabled && config.enabled;
    const allProviderNames = MITIGATION_PROVIDER_NAMES[type] ?? [];
    const providerNames = allProviderNames.slice(0, 3).join(', ');
    const moreCount = allProviderNames.length - 3;

    return (
      <div
        key={type}
        className={`mitigation-card ${isEnabled ? 'enabled' : 'disabled'}`}
      >
        <div className="mitigation-header">
          <div className="mitigation-title">
            <Icon size={16} className="mitigation-icon" />
            <span>{PATHWAY_MITIGATION_LABELS[type]}</span>
          </div>
          <button
            className={`toggle-switch ${config.enabled ? 'on' : 'off'}`}
            onClick={() => handleMitigationToggle(type)}
            disabled={!pathwayMitigationSettings.enabled}
            aria-label={`Toggle ${PATHWAY_MITIGATION_LABELS[type]}`}
          >
            <span className="toggle-knob" />
          </button>
        </div>

        <div className="mitigation-info">
          <span className="mitigation-description">
            {PATHWAY_MITIGATION_DESCRIPTIONS[type]}
          </span>
          <span className="mitigation-providers">
            Technologies: {providerNames}{moreCount > 0 && `, +${moreCount} more`}
          </span>
        </div>

        {config.enabled && pathwayMitigationSettings.enabled && (
          <div className="mitigation-options">
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
              <h3>Pathway Mitigations</h3>
              <button
                className={`toggle-switch master ${pathwayMitigationSettings.enabled ? 'on' : 'off'}`}
                onClick={handleMasterToggle}
                aria-label="Enable Pathway Mitigations"
              >
                <span className="toggle-knob" />
              </button>
            </div>

            <p className="section-description">
              When enabled, protective technologies upstream in the data flow will mitigate
              threats on downstream nodes.
            </p>

            <div className={`mitigation-cards ${!pathwayMitigationSettings.enabled ? 'master-disabled' : ''}`}>
              {MITIGATION_TYPES.map(renderMitigationCard)}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
