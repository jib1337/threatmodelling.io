import { memo } from 'react';
import { Handle, Position, type NodeProps, type Node } from '@xyflow/react';
import type { TechNodeData, DataSensitivity } from '../../data/schema';
import { PROVIDER_LABELS, DATA_SENSITIVITY_LABELS } from '../../data/schema';
import { useActions } from '../../context/ThreatModelContext';
import { isActor } from '../../data';
import { Globe, Building2, Lock, Ban, type LucideIcon } from 'lucide-react';
import ProviderIcon from '../ProviderIcon';
import ActorIcon from '../ActorIcon';
import './TechNode.css';

type TechNodeType = Node<TechNodeData>;

const SENSITIVITY_ICONS: Record<DataSensitivity, LucideIcon> = {
  'public': Globe,
  'internal': Building2,
  'confidential': Lock,
  'restricted': Ban,
};

const SENSITIVITY_ICON_SIZE = 14;

function TechNode({ id, data, selected }: NodeProps<TechNodeType>) {
  const { removeNode } = useActions();
  const { technology, sensitivity, customName } = data;
  const displayName = customName || technology.name;
  const isActorNode = isActor(technology.id);
  const SensitivityIcon = SENSITIVITY_ICONS[sensitivity];

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    removeNode(id);
  };

  return (
    <div className={`tech-node ${selected ? 'selected' : ''} provider-${technology.provider} sensitivity-${sensitivity}`}>
      {/*
        Each position has both source and target handles with explicit IDs.
        This allows connections to visually originate from and terminate at any position.
        Backwards compatibility is handled by setting default handle IDs during import.
      */}
      <Handle type="source" position={Position.Top} id="top-source" />
      <Handle type="target" position={Position.Top} id="top-target" />
      <Handle type="source" position={Position.Bottom} id="bottom-source" />
      <Handle type="target" position={Position.Bottom} id="bottom-target" />
      <Handle type="source" position={Position.Left} id="left-source" />
      <Handle type="target" position={Position.Left} id="left-target" />
      <Handle type="source" position={Position.Right} id="right-source" />
      <Handle type="target" position={Position.Right} id="right-target" />

      <div
        className={`sensitivity-indicator sensitivity-${sensitivity}`}
        title={`Data Sensitivity: ${DATA_SENSITIVITY_LABELS[sensitivity]}`}
      >
        <SensitivityIcon size={SENSITIVITY_ICON_SIZE} strokeWidth={2.25} aria-hidden="true" />
      </div>

      <button
        className="delete-button"
        onClick={handleDelete}
        title="Remove from diagram"
      >
        &times;
      </button>

      <div className="tech-node-content">
        <div className="tech-node-icon">
          {isActorNode ? (
            <ActorIcon actorId={technology.id} size="medium" />
          ) : (
            <ProviderIcon provider={technology.provider} size="medium" />
          )}
        </div>
        <div className="tech-node-name">{displayName}</div>
        {customName && (
          <div className="tech-node-subtitle">{technology.name}</div>
        )}
        <div className="tech-node-provider">
          {PROVIDER_LABELS[technology.provider]}
        </div>
      </div>
    </div>
  );
}

export default memo(TechNode);
