import { useState } from 'react';
import { useSelection, useActions, useDiagramState, useCustomTechnologies, useThreats } from '../../context/ThreatModelContext';
import type { DataSensitivity, ThreatSeverity } from '../../data/schema';
import { DATA_SENSITIVITY_LABELS, PROVIDER_LABELS, CATEGORY_LABELS, NETWORK_ZONE_LABELS } from '../../data/schema';
import { ShieldOff, Pencil, Trash2 } from 'lucide-react';
import CustomTechModal from '../CustomTechModal/CustomTechModal';
import ConfirmDeleteModal from '../ConfirmDeleteModal/ConfirmDeleteModal';
import './NodePropertiesPanel.css';

const SENSITIVITY_OPTIONS: DataSensitivity[] = ['public', 'internal', 'confidential', 'restricted'];

const SENSITIVITY_DESCRIPTIONS: Record<DataSensitivity, string> = {
  'public': 'Information intended for public disclosure',
  'internal': 'Internal business data, not for public sharing',
  'confidential': 'Sensitive business data requiring protection',
  'restricted': 'Highly sensitive data with strict access controls',
};

export default function NodePropertiesPanel() {
  const { selectedNodeId, selectedNodes, deselectAll } = useSelection();
  const { getNodeById, updateNodeSensitivity, updateSelectedNodesSensitivity, updateNodeCustomName, updateNodeThreatsDisabled, assignNodeToBoundary } = useActions();
  const { boundaries } = useDiagramState();
  const { removeCustomTechnology, updateCustomTechnology } = useCustomTechnologies();
  const { severityOverrides } = useThreats();
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  if (!selectedNodeId) return null;

  const node = getNodeById(selectedNodeId);
  if (!node) return null;

  const { technology, sensitivity, customName, threatsDisabled } = node.data;
  const multipleSelected = selectedNodes.length > 1;

  // Find current boundary assignment
  const currentBoundary = node.parentId ? boundaries.find(b => b.id === node.parentId) : null;
  const zoneType = currentBoundary?.data.zoneType;

  const handleSensitivityChange = (newSensitivity: DataSensitivity) => {
    if (multipleSelected) {
      updateSelectedNodesSensitivity(newSensitivity);
    } else {
      updateNodeSensitivity(selectedNodeId, newSensitivity);
    }
  };

  return (
    <div className="node-properties-panel">
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

      {multipleSelected && (
        <div className="multi-select-notice">
          {selectedNodes.length} nodes selected
        </div>
      )}

      <div className="panel-content">
        <div className="property-section">
          <label className="property-label">Technology</label>
          <div className="property-value">{technology.name}</div>
        </div>

        <div className="property-section">
          <label className="property-label">Description</label>
          <div className="property-value">{technology.description}</div>
        </div>

        <div className="property-section">
          <label className="property-label" htmlFor="display-name-input">
            Display Name
          </label>
          <input
            id="display-name-input"
            type="text"
            className="display-name-input"
            value={customName || ''}
            placeholder={technology.name}
            onChange={(e) => updateNodeCustomName(selectedNodeId, e.target.value)}
          />
        </div>

        <div className="property-section">
          <label className="property-label">Provider</label>
          <div className="property-value">{PROVIDER_LABELS[technology.provider]}</div>
        </div>

        {technology.provider !== 'actor' && (
          <div className="property-section">
            <label className="property-label">Category</label>
            <div className="property-value">{CATEGORY_LABELS[technology.category]}</div>
          </div>
        )}

        <div className="property-section">
          <label className="property-label" htmlFor="sensitivity-select">
            Data Sensitivity {multipleSelected && <span className="bulk-indicator">(applies to all)</span>}
          </label>
          <select
            id="sensitivity-select"
            className={`sensitivity-select sensitivity-${sensitivity}`}
            value={sensitivity}
            onChange={(e) => handleSensitivityChange(e.target.value as DataSensitivity)}
          >
            {SENSITIVITY_OPTIONS.map(option => (
              <option key={option} value={option}>
                {DATA_SENSITIVITY_LABELS[option]}
              </option>
            ))}
          </select>
          <div className="sensitivity-description">
            {multipleSelected
              ? `Will apply "${DATA_SENSITIVITY_LABELS[sensitivity]}" to all ${selectedNodes.length} selected nodes`
              : SENSITIVITY_DESCRIPTIONS[sensitivity]
            }
          </div>
        </div>

        {!multipleSelected && (
          <div className="property-section">
            <label className="property-label">Network Zone</label>
            <div className={`boundary-status ${zoneType ? `boundary-${zoneType}` : 'boundary-none'}`}>
              {zoneType ? (
                <>
                  <span>{NETWORK_ZONE_LABELS[zoneType]}</span>
                  <button
                    className="boundary-remove-button"
                    onClick={() => assignNodeToBoundary(selectedNodeId, null)}
                    title="Remove from boundary"
                  >
                    &times;
                  </button>
                </>
              ) : (
                <span className="boundary-none-text">Not in a zone</span>
              )}
            </div>
            {zoneType === 'private' && currentBoundary && (
              <div className="boundary-benefit">
                {currentBoundary.data.riskReductionEnabled !== false
                  ? `Risk reduction applied`
                  : 'Risk reduction disabled'}
              </div>
            )}
          </div>
        )}

        {!multipleSelected && (
          <div className="property-section threats-disabled-section">
            <div className="threats-disabled-header">
              <label className="property-label">Exclude from Threats</label>
              <button
                className={`toggle-switch ${threatsDisabled ? 'on' : 'off'}`}
                onClick={() => updateNodeThreatsDisabled(selectedNodeId, !threatsDisabled)}
                aria-label="Toggle exclude from threats"
              >
                <span className="toggle-knob" />
              </button>
            </div>
            <div className="threats-disabled-description">
              {threatsDisabled ? (
                <span className="threats-disabled-active">
                  <ShieldOff size={14} />
                  Threats for this node are hidden
                </span>
              ) : (
                <span>Enable to hide all threats for this technology</span>
              )}
            </div>
          </div>
        )}

        {technology.isCustom && !multipleSelected && (
          <div className="property-section custom-tech-actions">
            <button
              className="custom-tech-edit-button"
              onClick={() => setEditModalOpen(true)}
            >
              <Pencil size={14} />
              Edit Component
            </button>
            <button
              className="custom-tech-delete-button"
              onClick={() => setConfirmingDelete(true)}
            >
              <Trash2 size={14} />
              Delete Component
            </button>
          </div>
        )}
      </div>

      {editModalOpen && (
        <CustomTechModal
          isOpen={editModalOpen}
          onClose={() => setEditModalOpen(false)}
          onSave={updateCustomTechnology}
          editingTechnology={technology}
          existingSeverityOverrides={
            Object.fromEntries(
              Object.entries(severityOverrides).filter(([key]) => key.startsWith(`${technology.id}::`))
            ) as Record<string, ThreatSeverity>
          }
        />
      )}

      <ConfirmDeleteModal
        isOpen={confirmingDelete}
        onConfirm={() => {
          removeCustomTechnology(technology.id);
          setConfirmingDelete(false);
          deselectAll();
        }}
        onCancel={() => setConfirmingDelete(false)}
        title="Delete Custom Component"
        message={`This will permanently delete "${technology.name}" and remove all nodes using it from the diagram.`}
      />
    </div>
  );
}
