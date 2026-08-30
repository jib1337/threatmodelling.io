import { useEffect } from 'react';
import { Zap, Shield, Timer, Network } from 'lucide-react';
import { useSettings } from '../../context/ThreatModelContext';
import type { PathwayMitigationType } from '../../data/schema';
import {
  PATHWAY_MITIGATION_LABELS,
  PATHWAY_MITIGATION_DESCRIPTIONS,
} from '../../data/schema';
import { MITIGATION_PROVIDER_NAMES } from '../../data/mitigationMappings';
import './SettingsModal.css';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const MITIGATION_ICONS: Record<PathwayMitigationType, typeof Zap> = {
  'ddos-protection': Zap,
  'waf-protection': Shield,
  'rate-limiting': Timer,
  'network-firewall': Network,
};

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

  const handleMasterToggle = () => {
    updatePathwayMitigationSettings({
      ...pathwayMitigationSettings,
      enabled: !pathwayMitigationSettings.enabled,
    });
  };

  const handleMitigationToggle = (type: PathwayMitigationType) => {
    const current = pathwayMitigationSettings.mitigations[type];
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
    const current = pathwayMitigationSettings.mitigations[type];
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
    const current = pathwayMitigationSettings.mitigations[type];
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
    const config = pathwayMitigationSettings.mitigations[type];
    const Icon = MITIGATION_ICONS[type];
    const isEnabled = pathwayMitigationSettings.enabled && config.enabled;
    const providerNames = MITIGATION_PROVIDER_NAMES[type].slice(0, 3).join(', ');
    const moreCount = MITIGATION_PROVIDER_NAMES[type].length - 3;

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
                  min="10"
                  max="90"
                  step="5"
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

  const mitigationTypes: PathwayMitigationType[] = [
    'ddos-protection',
    'waf-protection',
    'rate-limiting',
    'network-firewall',
  ];

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
              {mitigationTypes.map(renderMitigationCard)}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
