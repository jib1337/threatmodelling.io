import { useState, useMemo, useEffect, useCallback } from 'react';
import { v4 as uuidv4 } from 'uuid';
import type { Technology, ServiceCategory, Threat, ThreatSeverity } from '../../data/schema';
import { CATEGORY_LABELS, STRIDE_LABELS, THREAT_SEVERITY_LABELS } from '../../data/schema';
import { getAllThreats, CATEGORY_THREAT_PRESETS } from '../../data';
import { useActions } from '../../context/ThreatModelContext';
import '../Sidebar/ThreatCard.css';
import './CustomTechModal.css';

interface CustomTechModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (technology: Technology) => void;
  editingTechnology?: Technology;
  existingSeverityOverrides?: Record<string, ThreatSeverity>;
}

// Categories available for custom technologies (exclude 'actor')
const AVAILABLE_CATEGORIES = (Object.keys(CATEGORY_LABELS) as ServiceCategory[]).filter(
  c => c !== 'actor'
);

const MAX_DESCRIPTION_LENGTH = 150;

export default function CustomTechModal({ isOpen, onClose, onSave, editingTechnology, existingSeverityOverrides }: CustomTechModalProps) {
  const isEditing = !!editingTechnology;
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<ServiceCategory>('compute');
  const [selectedThreatIds, setSelectedThreatIds] = useState<Set<string>>(new Set());
  const [threatSearch, setThreatSearch] = useState('');
  const [customSeverities, setCustomSeverities] = useState<Record<string, ThreatSeverity>>({});
  const [usePresets, setUsePresets] = useState(false);
  const { setSeverityOverride, setSeverityOverridesBatch } = useActions();

  // Get all threats excluding connection/zone threats (those are system-level)
  const availableThreats = useMemo(() => {
    return getAllThreats().filter(t => !t.isConnectionThreat && !t.isZoneThreat);
  }, []);

  // Filter threats by search
  const filteredThreats = useMemo(() => {
    const query = threatSearch.toLowerCase().trim();
    if (!query) return availableThreats;
    return availableThreats.filter(
      t =>
        t.name.toLowerCase().includes(query) ||
        t.description.toLowerCase().includes(query) ||
        t.stride.some(s => STRIDE_LABELS[s].toLowerCase().includes(query))
    );
  }, [availableThreats, threatSearch]);

  // Reset/populate state when modal opens
  useEffect(() => {
    if (isOpen) {
      if (editingTechnology) {
        setName(editingTechnology.name);
        setDescription(editingTechnology.description || '');
        setCategory(editingTechnology.category);
        setSelectedThreatIds(new Set(editingTechnology.threatIds));
        // Convert existing severity overrides (keyed as "techId::threatId") to just threatId keys
        const severities: Record<string, ThreatSeverity> = {};
        if (existingSeverityOverrides) {
          for (const [key, value] of Object.entries(existingSeverityOverrides)) {
            const threatId = key.split('::')[1];
            if (threatId) severities[threatId] = value;
          }
        }
        setCustomSeverities(severities);
      } else {
        setName('');
        setDescription('');
        setCategory('compute');
        setSelectedThreatIds(new Set());
        setCustomSeverities({});
      }
      setThreatSearch('');
      setUsePresets(false);
    }
  }, [isOpen, editingTechnology, existingSeverityOverrides]);

  // ESC to close
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const applyPresets = useCallback((cat: ServiceCategory) => {
    const presetIds = CATEGORY_THREAT_PRESETS[cat] || [];
    setSelectedThreatIds(new Set(presetIds));
    setCustomSeverities({});
  }, []);

  const handleTogglePresets = useCallback((checked: boolean) => {
    setUsePresets(checked);
    if (checked) {
      applyPresets(category);
    }
  }, [category, applyPresets]);

  const handleCategoryChange = useCallback((newCategory: ServiceCategory) => {
    setCategory(newCategory);
    if (usePresets) {
      applyPresets(newCategory);
    }
  }, [usePresets, applyPresets]);

  const handleOverlayClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose();
  }, [onClose]);

  const toggleThreat = useCallback((threatId: string) => {
    setSelectedThreatIds(prev => {
      const next = new Set(prev);
      if (next.has(threatId)) {
        next.delete(threatId);
        // Clean up custom severity when deselecting
        setCustomSeverities(prev => {
          const { [threatId]: _, ...rest } = prev;
          return rest;
        });
      } else {
        next.add(threatId);
      }
      return next;
    });
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedThreatIds(new Set());
    setCustomSeverities({});
    setUsePresets(false);
  }, []);

  const handleCustomSeverityChange = useCallback((threatId: string, severity: ThreatSeverity, defaultSeverity: ThreatSeverity) => {
    setCustomSeverities(prev => {
      if (severity === defaultSeverity) {
        const { [threatId]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [threatId]: severity };
    });
  }, []);

  const handleSave = useCallback(() => {
    const trimmedName = name.trim();
    if (!trimmedName) return;

    const techId = editingTechnology?.id ?? `custom-${uuidv4()}`;
    const technology: Technology = {
      id: techId,
      name: trimmedName,
      provider: 'custom',
      category,
      description: description.trim() || `Custom technology: ${trimmedName}`,
      threatIds: Array.from(selectedThreatIds),
      isCustom: true,
    };

    onSave(technology);

    // Build new severity overrides keyed by techId::threatId
    const overrides: Record<string, ThreatSeverity> = {};
    for (const [threatId, severity] of Object.entries(customSeverities)) {
      overrides[`${techId}::${threatId}`] = severity;
    }

    // When editing, remove old severity overrides that are no longer relevant
    if (editingTechnology && existingSeverityOverrides) {
      for (const key of Object.keys(existingSeverityOverrides)) {
        if (!(key in overrides)) {
          setSeverityOverride(key, null);
        }
      }
    }

    // Batch-set new severity overrides
    if (Object.keys(overrides).length > 0) {
      setSeverityOverridesBatch(overrides);
    }

    onClose();
  }, [name, description, category, selectedThreatIds, customSeverities, editingTechnology, existingSeverityOverrides, onSave, onClose, setSeverityOverridesBatch, setSeverityOverride]);

  if (!isOpen) return null;

  return (
    <div className="custom-tech-modal-overlay" onClick={handleOverlayClick}>
      <div className="custom-tech-modal">
        <button className="custom-tech-modal-close" onClick={onClose}>
          &times;
        </button>
        <h2 className="custom-tech-modal-title">{isEditing ? 'Edit Custom Component' : 'Create Custom Component'}</h2>

        <div className="custom-tech-modal-content">
          <div className="custom-tech-fields-column">
            <div className="custom-tech-field">
              <label htmlFor="custom-tech-name">Name</label>
              <input
                id="custom-tech-name"
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Internal Auth Service"
                autoFocus
              />
            </div>

            <div className="custom-tech-field">
              <div className="custom-tech-field-header">
                <label htmlFor="custom-tech-description">Description</label>
                <span className="custom-tech-char-count">{description.length}/{MAX_DESCRIPTION_LENGTH}</span>
              </div>
              <textarea
                id="custom-tech-description"
                value={description}
                onChange={e => setDescription(e.target.value.slice(0, MAX_DESCRIPTION_LENGTH))}
                placeholder="Brief description of this technology"
                rows={2}
                maxLength={MAX_DESCRIPTION_LENGTH}
              />
            </div>

            <div className="custom-tech-field">
              <label htmlFor="custom-tech-category">Category</label>
              <select
                id="custom-tech-category"
                value={category}
                onChange={e => handleCategoryChange(e.target.value as ServiceCategory)}
              >
                {AVAILABLE_CATEGORIES.map(cat => (
                  <option key={cat} value={cat}>
                    {CATEGORY_LABELS[cat]}
                  </option>
                ))}
              </select>
              <label className="custom-tech-preset-toggle">
                <input
                  type="checkbox"
                  checked={usePresets}
                  onChange={e => handleTogglePresets(e.target.checked)}
                />
                <span>Use threat presets for this category</span>
              </label>
            </div>
          </div>

          <div className="custom-tech-threats-column">
            <div className="threat-selection-header">
              <label>Threats</label>
              <div className="threat-selection-actions">
                <span className="threat-selection-count">
                  {selectedThreatIds.size} selected
                </span>
                {selectedThreatIds.size > 0 && (
                  <button
                    type="button"
                    className="threat-clear-button"
                    onClick={handleClearSelection}
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
            <input
              type="text"
              className="threat-search-input"
              value={threatSearch}
              onChange={e => setThreatSearch(e.target.value)}
              placeholder="Search threats..."
            />
            <div className="threat-list">
              {filteredThreats.length > 0 ? (
                filteredThreats.map(threat => (
                  <ThreatListItem
                    key={threat.id}
                    threat={threat}
                    selected={selectedThreatIds.has(threat.id)}
                    onToggle={toggleThreat}
                    customSeverity={customSeverities[threat.id]}
                    onSeverityChange={handleCustomSeverityChange}
                  />
                ))
              ) : (
                <div className="threat-list-empty">No threats match your search</div>
              )}
            </div>
          </div>
        </div>

        <div className="custom-tech-modal-footer">
          <button className="custom-tech-cancel-button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="custom-tech-create-button"
            onClick={handleSave}
            disabled={!name.trim()}
          >
            {isEditing ? 'Update Technology' : 'Create Technology'}
          </button>
        </div>
      </div>
    </div>
  );
}

function ThreatListItem({
  threat,
  selected,
  onToggle,
  customSeverity,
  onSeverityChange,
}: {
  threat: Threat;
  selected: boolean;
  onToggle: (id: string) => void;
  customSeverity?: ThreatSeverity;
  onSeverityChange: (threatId: string, severity: ThreatSeverity, defaultSeverity: ThreatSeverity) => void;
}) {
  const displaySeverity = customSeverity ?? threat.severity;

  return (
    <div
      className={`threat-list-item ${selected ? 'selected' : ''}`}
      onClick={() => onToggle(threat.id)}
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggle(threat.id)}
        onClick={e => e.stopPropagation()}
      />
      <div className="threat-list-item-info">
        <span className="threat-list-item-name">{threat.name}</span>
        <div className="threat-list-item-meta">
          {selected ? (
            <select
              className={`severity-selector severity-${displaySeverity}`}
              value={displaySeverity}
              onChange={e => {
                e.stopPropagation();
                onSeverityChange(threat.id, e.target.value as ThreatSeverity, threat.severity);
              }}
              onClick={e => e.stopPropagation()}
            >
              <option value="low">{THREAT_SEVERITY_LABELS.low}</option>
              <option value="medium">{THREAT_SEVERITY_LABELS.medium}</option>
              <option value="high">{THREAT_SEVERITY_LABELS.high}</option>
              <option value="critical">{THREAT_SEVERITY_LABELS.critical}</option>
            </select>
          ) : (
            <span className={`severity-selector severity-${threat.severity} severity-label`}>
              {THREAT_SEVERITY_LABELS[threat.severity]}
            </span>
          )}
          <span className="threat-list-item-stride">
            {threat.stride.map(s => STRIDE_LABELS[s]).join(', ')}
          </span>
        </div>
      </div>
    </div>
  );
}
