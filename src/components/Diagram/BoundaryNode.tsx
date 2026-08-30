import { memo, useState, useRef, useEffect } from 'react';
import { NodeResizer, type NodeProps, type Node } from '@xyflow/react';
import { ArrowLeftRight } from 'lucide-react';
import type { ZoneNodeData, NetworkZone } from '../../data/schema';
import { ZONE_NETWORK_TYPE_LABELS } from '../../data/schema';
import { useActions } from '../../context/ThreatModelContext';
import './BoundaryNode.css';

type BoundaryNodeType = Node<ZoneNodeData>;

function BoundaryNode({ id, data, selected }: NodeProps<BoundaryNodeType>) {
  const { removeBoundary, updateBoundaryType, updateBoundaryDimensions, updateBoundaryName } = useActions();
  const { zoneType, networkType, label, customName, onZoneChange } = data;
  const [isEditing, setIsEditing] = useState(false);
  const [editValue, setEditValue] = useState(customName || '');
  const inputRef = useRef<HTMLInputElement>(null);

  // Show network type for private zones with a non-generic network type
  const showNetworkType = zoneType === 'private' && networkType && networkType !== 'generic';
  const networkTypeLabel = showNetworkType ? ZONE_NETWORK_TYPE_LABELS[networkType] : null;

  // Focus input when editing starts
  useEffect(() => {
    if (isEditing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [isEditing]);

  const handleDoubleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setEditValue(customName || '');
    setIsEditing(true);
  };

  const handleSave = () => {
    updateBoundaryName(id, editValue.trim());
    setIsEditing(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSave();
    } else if (e.key === 'Escape') {
      setIsEditing(false);
      setEditValue(customName || '');
    }
  };

  const handleBlur = () => {
    handleSave();
  };

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    removeBoundary(id);
  };

  const handleToggleType = (e: React.MouseEvent) => {
    e.stopPropagation();
    const newType: NetworkZone = zoneType === 'public' ? 'private' : 'public';
    updateBoundaryType(id, newType);
  };

  const handleResize = (_event: unknown, params: { width: number; height: number }) => {
    updateBoundaryDimensions(id, params.width, params.height);
  };

  const handleResizeEnd = () => {
    // Check if any unassigned nodes should be assigned to this boundary
    // Use setTimeout to ensure state has been updated from the last handleResize call
    if (onZoneChange) {
      setTimeout(() => onZoneChange(id), 0);
    }
  };

  return (
    <div className={`boundary-node boundary-${zoneType} ${selected ? 'selected' : ''}`}>
      {/* Clickable border edges for selecting boundary by clicking edges */}
      <div className="boundary-border-top" />
      <div className="boundary-border-right" />
      <div className="boundary-border-bottom" />
      <div className="boundary-border-left" />
      <NodeResizer
        minWidth={200}
        minHeight={150}
        isVisible={selected}
        lineClassName="boundary-resize-line"
        handleClassName="boundary-resize-handle"
        onResize={handleResize}
        onResizeEnd={handleResizeEnd}
      />

      <div className={`boundary-header boundary-header-${zoneType}`}>
        {isEditing ? (
          <input
            ref={inputRef}
            type="text"
            className="boundary-name-input"
            value={editValue}
            onChange={(e) => setEditValue(e.target.value)}
            onKeyDown={handleKeyDown}
            onBlur={handleBlur}
            placeholder={label}
          />
        ) : (
          <span
            className="boundary-label"
            onDoubleClick={handleDoubleClick}
            title="Double-click to rename"
          >
            {customName ? (
              <>
                <span className="boundary-label-name">{customName}</span>
                <span className="boundary-label-details">
                  <span className="boundary-type-hint">{label}</span>
                  {networkTypeLabel && <span className="boundary-network-type">{networkTypeLabel}</span>}
                </span>
              </>
            ) : (
              <span className="boundary-label-details">
                <span className="boundary-label-name">{label}</span>
                {networkTypeLabel && <span className="boundary-network-type">{networkTypeLabel}</span>}
              </span>
            )}
          </span>
        )}

        <div className="boundary-actions">
          <button
            className="boundary-toggle-button"
            onClick={handleToggleType}
            title={`Switch to ${zoneType === 'public' ? 'Private' : 'Public'} Network`}
          >
            <ArrowLeftRight size={14} />
          </button>
          <button
            className="boundary-delete-button"
            onClick={handleDelete}
            title="Remove boundary"
          >
            &times;
          </button>
        </div>
      </div>
    </div>
  );
}

export default memo(BoundaryNode);
