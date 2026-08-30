import { useCallback, useRef, useMemo, useState, useEffect, type DragEvent } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  ControlButton,
  MiniMap,
  Panel,
  getNodesBounds,
  getViewportForBounds,
  MarkerType,
  SelectionMode,
  ConnectionMode,
  useNodesInitialized,
  type ReactFlowInstance,
  type Node,
  type OnSelectionChangeFunc,
  type OnConnectStart,
  type Connection,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { useDiagramState, useSelection, useActions, useDrawing } from '../../context/ThreatModelContext';
import { useTheme } from '../../context/ThemeContext';
import { getTechnologyById } from '../../data';
import type { TechNodeData, ZoneNodeData } from '../../data/schema';
import TechNode from './TechNode';
import BoundaryNode from './BoundaryNode';
import LabeledEdge from './LabeledEdge';
import NodePropertiesPanel from '../Sidebar/NodePropertiesPanel';
import BoundaryPropertiesPanel from '../Sidebar/BoundaryPropertiesPanel';
import { findBoundaryAtPosition, getNodeCenterPosition, calculateRelativePosition, calculateAbsolutePosition } from '../../utils/boundaryUtils';
import './DiagramCanvas.css';

const nodeTypes = {
  techNode: TechNode,
  boundaryNode: BoundaryNode,
};

const edgeTypes = {
  labeledEdge: LabeledEdge,
};

const IMAGE_WIDTH = 1920;
const IMAGE_HEIGHT = 1080;

function downloadImage(dataUrl: string, filename: string) {
  const link = document.createElement('a');
  link.download = filename;
  link.href = dataUrl;
  link.click();
}

export default function DiagramCanvas() {
  const { nodes, edges, boundaries, onNodesChange, onEdgesChange, onBoundariesChange, onConnect } = useDiagramState();
  const { selectedNodeId, selectedBoundaryId, setSelectedNode, setSelectedEdge, setSelectedBoundary, setSelectedNodes } = useSelection();
  const { addNode, updateEdgeLabel, removeEdge, setCenterCallback, setGetViewportCenterCallback, setFitViewCallback, addBoundary, assignNodeToBoundary, saveHistory } = useActions();
  const { drawingZoneType, isDrawing, startDrawingPublicZone, startDrawingPrivateZone, cancelDrawingMode } = useDrawing();
  const { theme } = useTheme();
  // Must match --edge-color in theme.css so edge strokes and arrow markers agree
  const edgeColor = useMemo(() => theme === 'light' ? '#5b6672' : '#30363d', [theme]);

  const edgeMarker = useMemo(() => ({
    type: MarkerType.ArrowClosed,
    width: 20,
    height: 20,
    color: edgeColor,
  }), [edgeColor]);

  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const reactFlowInstance = useRef<ReactFlowInstance<any, any> | null>(null);
  // Track where the user started dragging a connection from
  const connectionStartRef = useRef<{ nodeId: string | null; handleId: string | null }>({ nodeId: null, handleId: null });
  const [snapToGrid, setSnapToGrid] = useState(false);
  const [showMinimap, setShowMinimap] = useState(false);
  // Track previous boundary dimensions to detect resize changes
  const prevBoundaryDimensionsRef = useRef<Map<string, { width: number; height: number }>>(new Map());

  // Local state for drawing coordinates (kept local for performance - updates on every mousemove)
  const [drawStart, setDrawStart] = useState<{ x: number; y: number } | null>(null);
  const [drawCurrent, setDrawCurrent] = useState<{ x: number; y: number } | null>(null);

  // Check and assign unassigned nodes that are inside a boundary
  // Defined here so it can be passed to boundary nodes
  const checkNodesForBoundaryAssignment = useCallback(
    (boundaryId: string) => {
      const targetBoundary = boundaries.find(b => b.id === boundaryId);
      if (!targetBoundary) return;

      // Find all nodes that aren't assigned to any boundary
      const unassignedNodes = nodes.filter(n => !n.parentId);

      for (const node of unassignedNodes) {
        const nodeCenter = getNodeCenterPosition(node.position);
        if (findBoundaryAtPosition(nodeCenter, [targetBoundary])) {
          // Node is inside this boundary - assign it
          const relativePos = calculateRelativePosition(node.position, targetBoundary.position);
          onNodesChange([{
            id: node.id,
            type: 'position',
            position: relativePos,
          }]);
          assignNodeToBoundary(node.id, targetBoundary.id);
        }
      }
    },
    [nodes, boundaries, onNodesChange, assignNodeToBoundary]
  );

  // Watch for boundary dimension changes and check for node assignments
  // This handles the case where a boundary is resized to encompass existing nodes
  useEffect(() => {
    const prevDimensions = prevBoundaryDimensionsRef.current;

    for (const boundary of boundaries) {
      const width = boundary.width ?? boundary.measured?.width ?? (boundary.style?.width as number) ?? 300;
      const height = boundary.height ?? boundary.measured?.height ?? (boundary.style?.height as number) ?? 200;
      const prevDim = prevDimensions.get(boundary.id);

      // Check if boundary is new (could encompass existing nodes) or dimensions increased
      if (!prevDim || width > prevDim.width || height > prevDim.height) {
        checkNodesForBoundaryAssignment(boundary.id);
      }

      // Update tracked dimensions
      prevDimensions.set(boundary.id, { width, height });
    }

    // Clean up removed boundaries from tracking
    for (const id of prevDimensions.keys()) {
      if (!boundaries.some(b => b.id === id)) {
        prevDimensions.delete(id);
      }
    }
  }, [boundaries, checkNodesForBoundaryAssignment]);

  // Combine boundaries and nodes - boundaries first so they render behind nodes
  // Inject the checkNodesForBoundaryAssignment callback into boundary data
  const allNodes = useMemo(() => {
    const boundariesWithCallback = boundaries.map(b => ({
      ...b,
      data: {
        ...b.data,
        onZoneChange: checkNodesForBoundaryAssignment,
      },
    }));
    return [...boundariesWithCallback, ...nodes];
  }, [boundaries, nodes, checkNodesForBoundaryAssignment]);

  // Handle node changes - route to appropriate handler based on node type
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodesChange = useCallback((changes: any[]) => {
    // Separate changes for boundaries vs tech nodes
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const boundaryChanges: any[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const techNodeChanges: any[] = [];

    changes.forEach(change => {
      if ('id' in change) {
        const isBoundary = boundaries.some(b => b.id === change.id);
        if (isBoundary) {
          boundaryChanges.push(change);
        } else {
          techNodeChanges.push(change);
        }
      } else {
        // Changes without id go to tech nodes
        techNodeChanges.push(change);
      }
    });

    if (boundaryChanges.length > 0) {
      onBoundariesChange(boundaryChanges);
    }
    if (techNodeChanges.length > 0) {
      onNodesChange(techNodeChanges);
    }
  }, [boundaries, onNodesChange, onBoundariesChange]);

  // Snapshot history when a drag begins so the move is undoable.
  // Fires once per drag gesture (not per position frame).
  const onNodeDragStart = useCallback(() => {
    saveHistory();
  }, [saveHistory]);

  // Handle node drag stop to detect boundary assignment
  const onNodeDragStop = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (_event: React.MouseEvent, node: Node<any>) => {
      // Handle boundary drag - check if any unassigned nodes should be assigned
      if (node.type === 'boundaryNode') {
        checkNodesForBoundaryAssignment(node.id);
        return;
      }

      // Handle tech node drag
      if (node.type !== 'techNode') return;

      // Get the node's current boundary assignment
      const currentBoundaryId = node.parentId;
      const currentBoundary = currentBoundaryId
        ? boundaries.find(b => b.id === currentBoundaryId)
        : null;

      // Calculate the absolute position of the node
      // If node is in a boundary, its position is relative to that boundary
      const absoluteNodePosition = currentBoundary
        ? calculateAbsolutePosition(node.position, currentBoundary.position)
        : node.position;

      // Get the center position of the dragged node (in absolute coordinates)
      const nodeCenter = getNodeCenterPosition(absoluteNodePosition);

      // Find if the node is now inside a boundary
      const containingBoundary = findBoundaryAtPosition(nodeCenter, boundaries);

      if (containingBoundary && containingBoundary.id !== currentBoundaryId) {
        // Node moved into a new/different boundary - calculate relative position
        const relativePos = calculateRelativePosition(absoluteNodePosition, containingBoundary.position);
        // Update node position to be relative to boundary and assign to boundary
        onNodesChange([{
          id: node.id,
          type: 'position',
          position: relativePos,
        }]);
        assignNodeToBoundary(node.id, containingBoundary.id);
      } else if (!containingBoundary && currentBoundaryId) {
        // Node moved out of its boundary - position is already converted by React Flow
        // but we need to ensure it's absolute
        onNodesChange([{
          id: node.id,
          type: 'position',
          position: absoluteNodePosition,
        }]);
        assignNodeToBoundary(node.id, null);
      }
      // If node stayed in the same boundary (or no boundary), no action needed
    },
    [boundaries, assignNodeToBoundary, onNodesChange, checkNodesForBoundaryAssignment]
  );

  // Add callbacks to each edge's data
  const edgesWithCallbacks = useMemo(() => {
    return edges.map(edge => ({
      ...edge,
      markerEnd: edgeMarker,
      data: {
        ...edge.data,
        onLabelChange: updateEdgeLabel,
        onDelete: removeEdge,
      },
    }));
  }, [edges, updateEdgeLabel, removeEdge, edgeMarker]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const onInit = useCallback((instance: ReactFlowInstance<any, any>) => {
    reactFlowInstance.current = instance;
  }, []);

  // Set up the center callback for the context to use
  useEffect(() => {
    setCenterCallback((x: number, y: number) => {
      const instance = reactFlowInstance.current;
      if (instance) {
        // Keep the current zoom; setCenter defaults to max zoom otherwise
        instance.setCenter(x, y, { zoom: instance.getZoom() });
      }
    });
  }, [setCenterCallback]);

  // Fit the view after a model import/restore. The request is queued until
  // React Flow has measured the new nodes — fitting before measurement would
  // compute bounds from zero-sized nodes.
  const nodesInitialized = useNodesInitialized();
  const [fitViewQueued, setFitViewQueued] = useState(false);

  useEffect(() => {
    setFitViewCallback(() => setFitViewQueued(true));
  }, [setFitViewCallback]);

  useEffect(() => {
    if (!fitViewQueued || !nodesInitialized) return;
    setFitViewQueued(false);
    // Double rAF: when a model is imported over existing nodes,
    // nodesInitialized can still reflect the previous nodes in this commit.
    // Waiting two frames lets ResizeObserver measure the new nodes before
    // bounds are computed.
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        reactFlowInstance.current?.fitView({ padding: 0.2, maxZoom: 1.25, duration: 300 });
      });
    });
  }, [fitViewQueued, nodesInitialized]);

  // Set up the viewport center callback so palette can place nodes at viewport center
  useEffect(() => {
    setGetViewportCenterCallback(() => {
      const instance = reactFlowInstance.current;
      if (reactFlowWrapper.current && instance) {
        const bounds = reactFlowWrapper.current.getBoundingClientRect();
        // screenToFlowPosition expects absolute screen coordinates
        return instance.screenToFlowPosition({
          x: bounds.left + bounds.width / 2,
          y: bounds.top + bounds.height / 2,
        });
      }
      return null;
    });
  }, [setGetViewportCenterCallback]);

  const onDragOver = useCallback((event: DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: DragEvent) => {
      event.preventDefault();

      const technologyId = event.dataTransfer.getData('application/technology');
      if (!technologyId) return;

      const technology = getTechnologyById(technologyId);
      if (!technology) return;

      // Get the position where the item was dropped
      // screenToFlowPosition expects absolute screen coordinates (clientX/clientY)
      if (reactFlowWrapper.current && reactFlowInstance.current) {
        const position = reactFlowInstance.current.screenToFlowPosition({
          x: event.clientX,
          y: event.clientY,
        });

        // Check if the drop position is inside a boundary
        const nodeCenter = getNodeCenterPosition(position);
        const containingBoundary = findBoundaryAtPosition(nodeCenter, boundaries);

        if (containingBoundary) {
          // Convert to relative position within the boundary
          const relativePos = calculateRelativePosition(position, containingBoundary.position);
          addNode(technology, relativePos, containingBoundary.id);
        } else {
          addNode(technology, position);
        }
      }
    },
    [addNode, boundaries]
  );

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      if (node.type === 'boundaryNode') {
        setSelectedBoundary(node.id);
      } else {
        setSelectedNode(node.id);
      }
    },
    [setSelectedNode, setSelectedBoundary]
  );

  const onEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: { id: string }) => {
      setSelectedEdge(edge.id);
    },
    [setSelectedEdge]
  );

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setSelectedBoundary(null);
    setSelectedNodes([]);
  }, [setSelectedNode, setSelectedEdge, setSelectedBoundary, setSelectedNodes]);

  const onSelectionChange: OnSelectionChangeFunc = useCallback(
    ({ nodes: selectedNodes }) => {
      // Filter out boundary nodes — they are handled by onNodeClick → setSelectedBoundary.
      // setSelectedNodes internally dispatches SET_SELECTED_NODE with the first ID,
      // which would override the boundary selection if a boundary ID leaked through.
      const techNodes = selectedNodes.filter(n => n.type !== 'boundaryNode');
      const selectedIds = techNodes.map(n => n.id);
      setSelectedNodes(selectedIds);
    },
    [setSelectedNodes]
  );

  // Track which node and handle the user starts dragging a connection from
  const handleConnectStart: OnConnectStart = useCallback(
    (_event, { nodeId, handleId }) => {
      connectionStartRef.current = { nodeId, handleId };
    },
    []
  );

  // Convert a handle ID to its counterpart type at the same position
  // e.g., "top-target" -> "top-source", "bottom-source" -> "bottom-target"
  const convertHandleId = (handleId: string | null | undefined, toType: 'source' | 'target'): string => {
    if (!handleId) {
      // Default handles for backwards compatibility
      return toType === 'source' ? 'bottom-source' : 'top-target';
    }
    // Extract position from handle ID (e.g., "top" from "top-source" or "top-target")
    const position = handleId.replace(/-source$|-target$/, '');
    return `${position}-${toType}`;
  };

  // Ensure connection direction matches drag direction (from start node to end node)
  const handleConnect = useCallback(
    (connection: Connection) => {
      const { nodeId: startNodeId, handleId: startHandleId } = connectionStartRef.current;

      // If we tracked the start node and it doesn't match the connection's source,
      // swap source and target to match the user's drag direction
      if (startNodeId && connection.source !== startNodeId && connection.target === startNodeId) {
        // User dragged from startNodeId but React Flow made it the target - swap it
        // Also convert handle IDs to the correct type for each end
        const correctedConnection: Connection = {
          ...connection,
          source: connection.target,
          target: connection.source,
          // The handle user started from becomes the source handle
          sourceHandle: convertHandleId(startHandleId, 'source'),
          // The handle user ended on becomes the target handle
          targetHandle: convertHandleId(connection.sourceHandle, 'target'),
        };
        onConnect(correctedConnection);
      } else {
        // Connection direction is correct, but ensure handle IDs are set
        const normalizedConnection: Connection = {
          ...connection,
          sourceHandle: connection.sourceHandle || 'bottom-source',
          targetHandle: convertHandleId(connection.targetHandle, 'target'),
        };
        onConnect(normalizedConnection);
      }

      // Clear the ref
      connectionStartRef.current = { nodeId: null, handleId: null };
    },
    [onConnect]
  );

  // Enter drawing mode for zone creation (using context)
  const handleStartDrawPublicZone = useCallback(() => {
    startDrawingPublicZone();
    setDrawStart(null);
    setDrawCurrent(null);
  }, [startDrawingPublicZone]);

  const handleStartDrawPrivateZone = useCallback(() => {
    startDrawingPrivateZone();
    setDrawStart(null);
    setDrawCurrent(null);
  }, [startDrawingPrivateZone]);

  const handleCancelDrawingMode = useCallback(() => {
    cancelDrawingMode();
    setDrawStart(null);
    setDrawCurrent(null);
  }, [cancelDrawingMode]);

  // Mouse handlers for drawing zones
  const handleDrawingMouseDown = useCallback(
    (event: React.MouseEvent) => {
      if (!isDrawing || !reactFlowInstance.current) return;

      // screenToFlowPosition expects absolute screen coordinates
      const position = reactFlowInstance.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      setDrawStart(position);
      setDrawCurrent(position);
    },
    [isDrawing]
  );

  const handleDrawingMouseMove = useCallback(
    (event: React.MouseEvent) => {
      if (!isDrawing || !drawStart || !reactFlowInstance.current) return;

      const position = reactFlowInstance.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      setDrawCurrent(position);
    },
    [isDrawing, drawStart]
  );

  const handleDrawingMouseUp = useCallback(() => {
    if (!isDrawing || !drawStart || !drawCurrent || !drawingZoneType) return;

    // Calculate the rectangle bounds (handle drawing in any direction)
    const x = Math.min(drawStart.x, drawCurrent.x);
    const y = Math.min(drawStart.y, drawCurrent.y);
    const width = Math.abs(drawCurrent.x - drawStart.x);
    const height = Math.abs(drawCurrent.y - drawStart.y);

    // Only create if the drawn area is large enough (minimum 50x50)
    if (width >= 50 && height >= 50) {
      addBoundary({ x, y }, drawingZoneType, width, height);
    }

    // Exit drawing mode
    handleCancelDrawingMode();
  }, [isDrawing, drawStart, drawCurrent, drawingZoneType, addBoundary, handleCancelDrawingMode]);

  // Touch handlers for drawing zones on mobile devices
  const handleDrawingTouchStart = useCallback(
    (event: React.TouchEvent) => {
      if (!isDrawing || !reactFlowInstance.current) return;

      // Prevent default to avoid scrolling while drawing
      event.preventDefault();

      const touch = event.touches[0];
      const position = reactFlowInstance.current.screenToFlowPosition({
        x: touch.clientX,
        y: touch.clientY,
      });

      setDrawStart(position);
      setDrawCurrent(position);
    },
    [isDrawing]
  );

  const handleDrawingTouchMove = useCallback(
    (event: React.TouchEvent) => {
      if (!isDrawing || !drawStart || !reactFlowInstance.current) return;

      // Prevent default to avoid scrolling while drawing
      event.preventDefault();

      const touch = event.touches[0];
      const position = reactFlowInstance.current.screenToFlowPosition({
        x: touch.clientX,
        y: touch.clientY,
      });

      setDrawCurrent(position);
    },
    [isDrawing, drawStart]
  );

  const handleDrawingTouchEnd = useCallback(
    (event: React.TouchEvent) => {
      // Prevent default to avoid any touch-related side effects
      event.preventDefault();

      // Reuse the same logic as mouse up
      if (!isDrawing || !drawStart || !drawCurrent || !drawingZoneType) return;

      const x = Math.min(drawStart.x, drawCurrent.x);
      const y = Math.min(drawStart.y, drawCurrent.y);
      const width = Math.abs(drawCurrent.x - drawStart.x);
      const height = Math.abs(drawCurrent.y - drawStart.y);

      if (width >= 50 && height >= 50) {
        addBoundary({ x, y }, drawingZoneType, width, height);
      }

      handleCancelDrawingMode();
    },
    [isDrawing, drawStart, drawCurrent, drawingZoneType, addBoundary, handleCancelDrawingMode]
  );

  // Cancel drawing mode on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isDrawing) {
        handleCancelDrawingMode();
      }
    };

    if (isDrawing) {
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isDrawing, handleCancelDrawingMode]);

  // Calculate preview rectangle dimensions (in screen coordinates relative to container)
  const previewRect = useMemo(() => {
    if (!drawStart || !drawCurrent || !reactFlowWrapper.current || !reactFlowInstance.current) return null;

    const bounds = reactFlowWrapper.current.getBoundingClientRect();

    // Convert flow coordinates to screen coordinates
    const startScreen = reactFlowInstance.current.flowToScreenPosition(drawStart);
    const currentScreen = reactFlowInstance.current.flowToScreenPosition(drawCurrent);

    // Make coordinates relative to the container
    const x1 = startScreen.x - bounds.left;
    const y1 = startScreen.y - bounds.top;
    const x2 = currentScreen.x - bounds.left;
    const y2 = currentScreen.y - bounds.top;

    return {
      x: Math.min(x1, x2),
      y: Math.min(y1, y2),
      width: Math.abs(x2 - x1),
      height: Math.abs(y2 - y1),
    };
  }, [drawStart, drawCurrent]);

  const handleExportPng = useCallback(async () => {
    const viewport = document.querySelector('.react-flow__viewport') as HTMLElement;
    if (!viewport || allNodes.length === 0) return;

    // Dynamically import html-to-image
    const { toPng } = await import('html-to-image');

    const nodesBounds = getNodesBounds(allNodes);
    const { x, y, zoom } = getViewportForBounds(
      nodesBounds,
      IMAGE_WIDTH,
      IMAGE_HEIGHT,
      0.5,
      2,
      0.2
    );

    // Get the current background color from CSS variable
    const bgColor = getComputedStyle(document.documentElement)
      .getPropertyValue('--bg-primary')
      .trim();

    const dataUrl = await toPng(viewport, {
      backgroundColor: bgColor || '#0d1117',
      width: IMAGE_WIDTH,
      height: IMAGE_HEIGHT,
      style: {
        width: String(IMAGE_WIDTH),
        height: String(IMAGE_HEIGHT),
        transform: `translate(${x}px, ${y}px) scale(${zoom})`,
      },
    });
    downloadImage(dataUrl, 'threat-model.png');
  }, [allNodes]);

  const handleExportSvg = useCallback(async () => {
    const viewport = document.querySelector('.react-flow__viewport') as HTMLElement;
    if (!viewport || allNodes.length === 0) return;

    // Dynamically import html-to-image
    const { toSvg } = await import('html-to-image');

    const nodesBounds = getNodesBounds(allNodes);
    const { x, y, zoom } = getViewportForBounds(
      nodesBounds,
      IMAGE_WIDTH,
      IMAGE_HEIGHT,
      0.5,
      2,
      0.2
    );

    // Get the current background color from CSS variable
    const bgColor = getComputedStyle(document.documentElement)
      .getPropertyValue('--bg-primary')
      .trim();

    const dataUrl = await toSvg(viewport, {
      backgroundColor: bgColor || '#0d1117',
      width: IMAGE_WIDTH,
      height: IMAGE_HEIGHT,
      style: {
        width: String(IMAGE_WIDTH),
        height: String(IMAGE_HEIGHT),
        transform: `translate(${x}px, ${y}px) scale(${zoom})`,
      },
    });
    downloadImage(dataUrl, 'threat-model.svg');
  }, [allNodes]);

  return (
    <div
      className={`diagram-canvas ${isDrawing ? 'drawing-mode' : ''}`}
      ref={reactFlowWrapper}
      onMouseDown={isDrawing ? handleDrawingMouseDown : undefined}
      onMouseMove={isDrawing ? handleDrawingMouseMove : undefined}
      onMouseUp={isDrawing ? handleDrawingMouseUp : undefined}
      onMouseLeave={isDrawing && drawStart ? handleDrawingMouseUp : undefined}
      onTouchStart={isDrawing ? handleDrawingTouchStart : undefined}
      onTouchMove={isDrawing ? handleDrawingTouchMove : undefined}
      onTouchEnd={isDrawing ? handleDrawingTouchEnd : undefined}
    >
      <ReactFlow
        nodes={allNodes}
        edges={edgesWithCallbacks}
        onNodesChange={handleNodesChange}
        onEdgesChange={onEdgesChange}
        onConnectStart={handleConnectStart}
        onConnect={handleConnect}
        connectionMode={ConnectionMode.Loose}
        onInit={onInit}
        onDragOver={onDragOver}
        onDrop={onDrop}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onNodeDragStart={onNodeDragStart}
        onSelectionDragStart={onNodeDragStart}
        onNodeDragStop={onNodeDragStop}
        onPaneClick={onPaneClick}
        onSelectionChange={onSelectionChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        snapToGrid={snapToGrid}
        snapGrid={[20, 20]}
        selectionOnDrag={!isDrawing}
        selectionMode={SelectionMode.Partial}
        panOnDrag={!isDrawing}
        zoomOnDoubleClick={!isDrawing}
        zoomOnPinch={!isDrawing}
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{
          type: 'labeledEdge',
          markerEnd: edgeMarker,
        }}
      >
        <Background color="var(--canvas-dot)" gap={20} size={1} />
        <Controls>
          <ControlButton
            onClick={() => setSnapToGrid(prev => !prev)}
            title={snapToGrid ? 'Disable snap to grid' : 'Enable snap to grid'}
            className={`snap-toggle-button ${snapToGrid ? 'active' : ''}`}
          >
            <svg viewBox="0 0 24 24" fill="currentColor">
              <path d="M3 3h2v2H3V3zm4 0h2v2H7V3zm4 0h2v2h-2V3zm4 0h2v2h-2V3zm4 0h2v2h-2V3zM3 7h2v2H3V7zm16 0h2v2h-2V7zM3 11h2v2H3v-2zm16 0h2v2h-2v-2zM3 15h2v2H3v-2zm16 0h2v2h-2v-2zM3 19h2v2H3v-2zm4 0h2v2H7v-2zm4 0h2v2h-2v-2zm4 0h2v2h-2v-2zm4 0h2v2h-2v-2z" />
            </svg>
          </ControlButton>
        </Controls>
        <Panel position="top-left" className="boundary-toolbox">
          <div className="toolbox-header">Network Zones</div>
          <div className="toolbox-buttons">
            <button
              className={`toolbox-button boundary-public ${drawingZoneType === 'public' ? 'active' : ''}`}
              onClick={drawingZoneType === 'public' ? handleCancelDrawingMode : handleStartDrawPublicZone}
              title={drawingZoneType === 'public' ? 'Cancel drawing' : 'Draw Public Network zone'}
            >
              <span className="toolbox-label">Public</span>
            </button>
            <button
              className={`toolbox-button boundary-private ${drawingZoneType === 'private' ? 'active' : ''}`}
              onClick={drawingZoneType === 'private' ? handleCancelDrawingMode : handleStartDrawPrivateZone}
              title={drawingZoneType === 'private' ? 'Cancel drawing' : 'Draw Private Network zone'}
            >
              <span className="toolbox-label">Private</span>
            </button>
          </div>
          {isDrawing && (
            <div className="toolbox-hint">
              Drag on canvas to draw zone
              <span className="hint-shortcut">ESC to cancel</span>
            </div>
          )}
        </Panel>
        <div className="minimap-container">
          <button
            className={`minimap-trigger ${showMinimap ? 'active' : ''}`}
            onClick={() => setShowMinimap(prev => !prev)}
            title={showMinimap ? 'Hide minimap' : 'Show minimap'}
          >
            <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
              <path d="M3 5a2 2 0 012-2h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5zm2 0v14h14V5H5zm2 2h4v4H7V7zm6 0h4v2h-4V7zm0 4h4v2h-4v-2zm-6 2h4v4H7v-4zm6 2h4v2h-4v-2z" />
            </svg>
          </button>
          {showMinimap && (
            <MiniMap
              nodeColor={(node: Node<TechNodeData | ZoneNodeData>) => {
                // Handle boundary nodes
                if (node.type === 'boundaryNode') {
                  const boundaryData = node.data as ZoneNodeData;
                  return boundaryData.zoneType === 'private' ? '#52b3ff' : '#f97316';
                }
                // Handle tech nodes
                const techData = node.data as TechNodeData;
                const provider = techData?.technology?.provider;
                switch (provider) {
                  case 'aws':
                    return '#ff9900';
                  case 'gcp':
                    return '#42BFF4';
                  case 'azure':
                    return '#0078d4';
                  case 'saas':
                    return '#e91e8c';
                  case 'actor':
                    return '#9333ea';
                  default:
                    return '#6b7280';
                }
              }}
              maskColor={theme === 'light' ? 'rgba(87, 96, 106, 0.25)' : 'rgba(0, 0, 0, 0.8)'}
              style={{ background: 'var(--bg-secondary)' }}
              className="minimap-panel"
            />
          )}
        </div>
        <Panel position="top-right" className="export-panel">
          <button
            className="export-button"
            onClick={handleExportPng}
            disabled={allNodes.length === 0}
            title="Export as PNG"
          >
            📷 PNG
          </button>
          <button
            className="export-button"
            onClick={handleExportSvg}
            disabled={allNodes.length === 0}
            title="Export as SVG"
          >
            🖼️ SVG
          </button>
        </Panel>
      </ReactFlow>

      {/* Drawing preview rectangle */}
      {isDrawing && previewRect && previewRect.width > 0 && previewRect.height > 0 && (
        <svg className="drawing-preview-overlay" style={{ pointerEvents: 'none' }}>
          <rect
            x={previewRect.x}
            y={previewRect.y}
            width={previewRect.width}
            height={previewRect.height}
            className={`drawing-preview-rect ${drawingZoneType}`}
          />
        </svg>
      )}

      {/* Mobile drawing mode indicator */}
      {isDrawing && (
        <div className="mobile-drawing-indicator">
          <span>Drawing {drawingZoneType === 'public' ? 'Public' : 'Private'} Zone</span>
          <button onClick={handleCancelDrawingMode}>Cancel</button>
        </div>
      )}

      {selectedNodeId && <NodePropertiesPanel />}
      {selectedBoundaryId && <BoundaryPropertiesPanel />}

      {nodes.length === 0 && boundaries.length === 0 && (
        <div className="empty-canvas-message">
          <p>Drag technologies from the palette to start modelling</p>
          <p className="hint">Press ? for keyboard shortcuts</p>
        </div>
      )}
    </div>
  );
}
