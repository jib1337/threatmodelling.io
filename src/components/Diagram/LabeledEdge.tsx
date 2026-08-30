import { useState, useCallback, memo } from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from '@xyflow/react';
import './LabeledEdge.css';

export interface LabeledEdgeData {
  label?: string;
  onLabelChange?: (edgeId: string, label: string) => void;
  onDelete?: (edgeId: string) => void;
}

export default memo(function LabeledEdge({
  id,
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
                >
                  ×
                </button>
              )}
            </>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
})
