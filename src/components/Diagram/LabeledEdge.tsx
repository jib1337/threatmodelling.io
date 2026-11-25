import { useState, useCallback, memo } from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  useStore,
  type EdgeProps,
  type ReactFlowState,
} from '@xyflow/react';
import { X } from 'lucide-react';
import './LabeledEdge.css';

export interface LabeledEdgeData {
  label?: string;
  onLabelChange?: (edgeId: string, label: string) => void;
  onDelete?: (edgeId: string) => void;
}
const BASE_LABEL_Z = 10;

function selectLabelZIndex(source: string, target: string, selected: boolean) {
  return (s: ReactFlowState) => {
    const elevated = (nodeId: string) => {
      const node = s.nodeLookup.get(nodeId);
      if (!node) return 0;
      return node.parentId || (s.elevateEdgesOnSelect && node.selected) ? node.internals.z : 0;
    };
    const edgeZ = (s.elevateEdgesOnSelect && selected ? 1000 : 0)
      + Math.max(elevated(source), elevated(target));
    return Math.max(BASE_LABEL_Z, edgeZ + 1);
  };
}

export default memo(function LabeledEdge({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
  selected,
}: EdgeProps) {
  const [isEditing, setIsEditing] = useState(false);
  const [editValue, setEditValue] = useState((data as LabeledEdgeData)?.label || '');

  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const labelZIndex = useStore(selectLabelZIndex(source, target, !!selected));

  const edgeData = data as LabeledEdgeData | undefined;
  const label = edgeData?.label || '';

  const handleDoubleClick = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setEditValue(label);
    setIsEditing(true);
  }, [label]);

  const handleBlur = useCallback(() => {
    setIsEditing(false);
    if (edgeData?.onLabelChange && editValue !== label) {
      edgeData.onLabelChange(id, editValue);
    }
  }, [id, editValue, label, edgeData]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleBlur();
    } else if (e.key === 'Escape') {
      setEditValue(label);
      setIsEditing(false);
    }
  }, [handleBlur, label]);

  const handleDelete = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (edgeData?.onDelete) {
      edgeData.onDelete(id);
    }
  }, [id, edgeData]);

  return (
    <>
      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          ...style,
          stroke: selected ? 'var(--accent-blue)' : 'var(--edge-color)',
          strokeWidth: 2,
        }}
      />
      <EdgeLabelRenderer>
        <div
          className={`edge-label-container ${selected ? 'selected' : ''}`}
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            pointerEvents: 'all',
            zIndex: labelZIndex,
          }}
          onDoubleClick={handleDoubleClick}
        >
          {isEditing ? (
            <input
              type="text"
              value={editValue}
              onChange={(e) => setEditValue(e.target.value)}
              onBlur={handleBlur}
              onKeyDown={handleKeyDown}
              className="edge-label-input"
              autoFocus
              placeholder="Enter data flow..."
            />
          ) : (
            <>
              <div className={`edge-label ${label ? 'has-label' : 'empty'}`}>
                {label || 'Double-click to label'}
              </div>
              {selected && (
                <button
                  className="edge-delete-button"
                  onClick={handleDelete}
                  title="Delete connection"
                  aria-label="Delete connection"
                >
                  <X size={11} strokeWidth={2.75} aria-hidden="true" />
                </button>
              )}
            </>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
})
