import {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  type ReactNode,
} from 'react';
import {
  type Node,
  type Edge,
  type NodeChange,
  type EdgeChange,
  type OnNodesChange,
  type OnEdgesChange,
  type OnConnect,
  type Connection,
  applyNodeChanges,
  applyEdgeChanges,
  addEdge,
} from '@xyflow/react';
import { v4 as uuidv4 } from 'uuid';
import type { Technology, ThreatModel, ActiveThreat, TechNodeData, ZoneNodeData, DataSensitivity, NetworkZone, ZoneNetworkType, ClipboardState, ClipboardNode, ClipboardEdge, ClipboardZone, PathwayMitigationSettings, ThreatSeverity, CloudProvider } from '../data/schema';
import { NETWORK_ZONE_LABELS, DEFAULT_PATHWAY_MITIGATION_SETTINGS } from '../data/schema';
import { resolveActiveThreats } from '../utils/threatResolver';
import { getTechnologyById, registerCustomTechnology as registerCustomTechInCache, unregisterCustomTechnology as unregisterCustomTechInCache, registerCustomTechnologies as registerCustomTechsInCache, clearCustomTechnologies as clearCustomTechsInCache, loadProviders, providerFromTechId } from '../data';
import { findBoundaryAtPosition, getNodeCenterPosition, calculateRelativePosition, calculateAbsolutePosition } from '../utils/boundaryUtils';
import { pruneNodeControlKeys } from '../utils/controlFingerprint';
import { loadPersistedModel, savePersistedModel, clearPersistedModel, modelHasContent } from '../utils/modelPersistence';
import { showToast } from '../utils/toast';

// Idle delay before an autosave write fires, to avoid thrashing localStorage
// while the user is actively editing.
const AUTOSAVE_DEBOUNCE_MS = 800;

// State types
interface DiagramState {
  nodes: Node<TechNodeData>[];
  edges: Edge[];
  boundaries: Node<ZoneNodeData>[];
  customTechnologies: Technology[];
  severityOverrides: Record<string, ThreatSeverity>;
  implementedControls: Record<string, true>;
}

interface ThreatModelState {
  nodes: Node<TechNodeData>[];
  edges: Edge[];
  boundaries: Node<ZoneNodeData>[];
  customTechnologies: Technology[];
  severityOverrides: Record<string, ThreatSeverity>;
  implementedControls: Record<string, true>;
  modelName: string;
  history: DiagramState[];
  historyIndex: number;
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  selectedBoundaryId: string | null;
  selectedNodes: string[];
  clipboard: ClipboardState | null;
  pasteCount: number;
  drawingZoneType: NetworkZone | null;
  pathwayMitigationSettings: PathwayMitigationSettings;
}

// Action types
type ThreatModelAction =
  | { type: 'ADD_NODE'; payload: { technology: Technology; position: { x: number; y: number }; boundaryId?: string } }
  | { type: 'REMOVE_NODE'; payload: { nodeId: string } }
  | { type: 'SET_NODES'; payload: Node<TechNodeData>[] }
  | { type: 'SET_EDGES'; payload: Edge[] }
  | { type: 'ADD_EDGE'; payload: Edge }
  | { type: 'REMOVE_EDGE'; payload: { edgeId: string } }
  | { type: 'UPDATE_EDGE_LABEL'; payload: { edgeId: string; label: string } }
  | { type: 'CLEAR_DIAGRAM' }
  | { type: 'IMPORT_MODEL'; payload: ThreatModel }
  | { type: 'SET_MODEL_NAME'; payload: string }
  | { type: 'UNDO' }
  | { type: 'REDO' }
  | { type: 'SAVE_HISTORY' }
  | { type: 'SET_SELECTED_NODE'; payload: string | null }
  | { type: 'SET_SELECTED_EDGE'; payload: string | null }
  | { type: 'UPDATE_NODE_SENSITIVITY'; payload: { nodeId: string; sensitivity: DataSensitivity } }
  | { type: 'UPDATE_NODE_CUSTOM_NAME'; payload: { nodeId: string; customName: string } }
  | { type: 'UPDATE_NODE_THREATS_DISABLED'; payload: { nodeId: string; threatsDisabled: boolean } }
  | { type: 'SET_SELECTED_NODES'; payload: string[] }
  | { type: 'COPY_SELECTION'; payload: { nodes: ClipboardNode[]; edges: ClipboardEdge[]; zones: ClipboardZone[]; copyOrigin: { x: number; y: number } } }
  | { type: 'PASTE_CLIPBOARD' }
  | { type: 'REMOVE_NODES'; payload: { nodeIds: string[] } }
  | { type: 'NUDGE_NODES'; payload: { nodeIds: string[]; dx: number; dy: number } }
  | { type: 'UPDATE_NODES_SENSITIVITY'; payload: { nodeIds: string[]; sensitivity: DataSensitivity } }
  | { type: 'ADD_BOUNDARY'; payload: { position: { x: number; y: number }; zoneType: NetworkZone; width?: number; height?: number } }
  | { type: 'REMOVE_BOUNDARY'; payload: { boundaryId: string } }
  | { type: 'UPDATE_BOUNDARY_TYPE'; payload: { boundaryId: string; zoneType: NetworkZone } }
  | { type: 'UPDATE_BOUNDARY_DIMENSIONS'; payload: { boundaryId: string; width: number; height: number } }
  | { type: 'UPDATE_BOUNDARY_NAME'; payload: { boundaryId: string; customName: string } }
  | { type: 'SET_BOUNDARIES'; payload: Node<ZoneNodeData>[] }
  | { type: 'ASSIGN_NODE_TO_BOUNDARY'; payload: { nodeId: string; boundaryId: string | null } }
  | { type: 'SET_SELECTED_BOUNDARY'; payload: string | null }
  | { type: 'UPDATE_BOUNDARY_RISK_SETTINGS'; payload: { boundaryId: string; riskReductionEnabled: boolean; riskReductionPercent: number } }
  | { type: 'UPDATE_BOUNDARY_NETWORK_TYPE'; payload: { boundaryId: string; networkType: ZoneNetworkType } }
  | { type: 'START_DRAWING_ZONE'; payload: NetworkZone }
  | { type: 'CANCEL_DRAWING_MODE' }
  | { type: 'APPLY_NODE_CHANGES'; payload: NodeChange<Node<TechNodeData>>[] }
  | { type: 'APPLY_EDGE_CHANGES'; payload: EdgeChange[] }
  | { type: 'APPLY_BOUNDARY_CHANGES'; payload: NodeChange<Node<ZoneNodeData>>[] }
  | { type: 'CONNECT_NODES'; payload: Connection }
  | { type: 'UPDATE_PATHWAY_MITIGATION_SETTINGS'; payload: PathwayMitigationSettings }
  | { type: 'SET_SEVERITY_OVERRIDE'; payload: { key: string; severity: ThreatSeverity | null } }
  | { type: 'SET_SEVERITY_OVERRIDES_BATCH'; payload: Record<string, ThreatSeverity> }
  | { type: 'REGISTER_CUSTOM_TECHNOLOGY'; payload: Technology }
  | { type: 'REMOVE_CUSTOM_TECHNOLOGY'; payload: { technologyId: string } }
  | { type: 'UPDATE_CUSTOM_TECHNOLOGY'; payload: Technology }
  | { type: 'SET_CONTROL_IMPLEMENTED'; payload: { key: string; implemented: boolean } };

// Initial state
const initialState: ThreatModelState = {
  nodes: [],
  edges: [],
  boundaries: [],
  customTechnologies: [],
  severityOverrides: {},
  implementedControls: {},
  modelName: 'Untitled Threat Model',
  history: [{ nodes: [], edges: [], boundaries: [], customTechnologies: [], severityOverrides: {}, implementedControls: {} }],
  historyIndex: 0,
  selectedNodeId: null,
  selectedEdgeId: null,
  selectedBoundaryId: null,
  selectedNodes: [],
  clipboard: null,
  pasteCount: 0,
  drawingZoneType: null,
  pathwayMitigationSettings: DEFAULT_PATHWAY_MITIGATION_SETTINGS,
};

const MAX_HISTORY = 50;

// Helper to save current state to history
// Uses efficient slicing to avoid O(n) shift() operations
function saveToHistory(state: ThreatModelState): ThreatModelState {
  const newHistoryEntry: DiagramState = {
    nodes: state.nodes,
    edges: state.edges,
    boundaries: state.boundaries,
    customTechnologies: state.customTechnologies,
    severityOverrides: state.severityOverrides,
    implementedControls: state.implementedControls,
  };

  // Calculate how many entries to keep (remove future history if not at end)
  const keepCount = state.historyIndex + 1;

  // Calculate start index to respect MAX_HISTORY limit
  // If adding one more would exceed limit, drop oldest entries
  const startIndex = keepCount >= MAX_HISTORY ? keepCount - MAX_HISTORY + 1 : 0;

  // Single slice operation: removes future history AND trims oldest if needed
  const history = startIndex > 0
    ? [...state.history.slice(startIndex, keepCount), newHistoryEntry]
    : [...state.history.slice(0, keepCount), newHistoryEntry];

  return {
    ...state,
    history,
    historyIndex: history.length - 1,
  };
}

// Reducer
function threatModelReducer(
  state: ThreatModelState,
  action: ThreatModelAction
): ThreatModelState {
  switch (action.type) {
    case 'ADD_NODE': {
      const { technology, position, boundaryId } = action.payload;
      const newNode: Node<TechNodeData> = {
        id: uuidv4(),
        type: 'techNode',
        position,
        zIndex: 1,
        data: {
          technology,
          label: technology.name,
          sensitivity: 'internal',
        },
        ...(boundaryId && { parentId: boundaryId }),
      };
      return {
        ...state,
        nodes: [...state.nodes, newNode],
      };
    }

    case 'REMOVE_NODE': {
      const { nodeId } = action.payload;
      return {
        ...state,
        nodes: state.nodes.filter(node => node.id !== nodeId),
        edges: state.edges.filter(
          edge => edge.source !== nodeId && edge.target !== nodeId
        ),
        implementedControls: pruneNodeControlKeys(state.implementedControls, nodeId),
      };
    }

    case 'SET_NODES':
      return { ...state, nodes: action.payload };

    case 'SET_EDGES':
      return { ...state, edges: action.payload };

    case 'ADD_EDGE':
      return { ...state, edges: [...state.edges, action.payload] };

    case 'REMOVE_EDGE':
      return {
        ...state,
        edges: state.edges.filter(edge => edge.id !== action.payload.edgeId),
      };

    case 'UPDATE_EDGE_LABEL': {
      const { edgeId, label } = action.payload;
      return {
        ...state,
        edges: state.edges.map(edge =>
          edge.id === edgeId
            ? { ...edge, data: { ...edge.data, label } }
            : edge
        ),
      };
    }

    case 'CLEAR_DIAGRAM':
      clearCustomTechsInCache();
      return { ...state, nodes: [], edges: [], boundaries: [], customTechnologies: [], severityOverrides: {}, implementedControls: {} };

    case 'IMPORT_MODEL': {
      const { nodes: exportedNodes, edges: exportedEdges, zones: exportedZones = [], name, pathwayMitigationSettings: importedSettings, customTechnologies: importedCustomTechs = [], severityOverrides: importedSeverityOverrides, implementedControls: importedImplementedControls } = action.payload;

      // Validate and sanitize custom tech descriptions (max 150 chars)
      const sanitizedCustomTechs = importedCustomTechs.map(tech =>
        tech.description && tech.description.length > 150
          ? { ...tech, description: tech.description.slice(0, 150) }
          : tech
      );

      // Ensure custom techs are in cache (defensive - normally done by importModel callback)
      sanitizedCustomTechs.forEach(tech => {
        if (!getTechnologyById(tech.id)) {
          registerCustomTechInCache(tech);
        }
      });

      // Reconstruct boundaries first
      const boundaries: Node<ZoneNodeData>[] = exportedZones.map(eb => ({
        id: eb.id,
        type: 'boundaryNode',
        position: eb.position,
        style: { width: eb.dimensions.width, height: eb.dimensions.height },
        zIndex: -1,
        data: {
          zoneType: eb.zoneType,
          // Only private zones can have a network type; public zones are always generic
          networkType: eb.zoneType === 'private' ? eb.networkType : undefined,
          label: NETWORK_ZONE_LABELS[eb.zoneType],
          customName: eb.customName,
          // Default to enabled for private boundaries, disabled for public
          riskReductionEnabled: eb.riskReductionEnabled ?? (eb.zoneType === 'private'),
          riskReductionPercent: eb.riskReductionPercent ?? 20,
        },
      }));

      const nodes: Node<TechNodeData>[] = exportedNodes
        .map(en => {
          const technology = getTechnologyById(en.technologyId);
          if (!technology) return null;
          return {
            id: en.id,
            type: 'techNode',
            position: en.position,
            zIndex: 1,
            data: {
              technology,
              label: technology.name,
              sensitivity: en.sensitivity || 'internal',
              customName: en.customName,
              threatsDisabled: en.threatsDisabled,
            },
            ...(en.zoneId && { parentId: en.zoneId }),
          } as Node<TechNodeData>;
        })
        .filter((n): n is Node<TechNodeData> => n !== null);

      const edges: Edge[] = exportedEdges.map(ee => ({
        id: ee.id,
        source: ee.source,
        target: ee.target,
        // Set default handle IDs for backwards compatibility with old edges
        // Old edges were created with source at bottom, target at top
        sourceHandle: ee.sourceHandle || 'bottom-source',
        targetHandle: ee.targetHandle || 'top-target',
        type: 'labeledEdge',
        data: { label: ee.label || '' },
      }));

      // Load pathway mitigation settings from import, or use defaults (feature OFF) for older versions
      const pathwayMitigationSettings = importedSettings ?? DEFAULT_PATHWAY_MITIGATION_SETTINGS;

      return {
        ...state,
        nodes,
        edges,
        boundaries,
        customTechnologies: sanitizedCustomTechs,
        severityOverrides: importedSeverityOverrides ?? {},
        implementedControls: importedImplementedControls ?? {},
        modelName: name,
        selectedNodeId: null,
        selectedBoundaryId: null,
        pathwayMitigationSettings,
      };
    }

    case 'SET_MODEL_NAME':
      return { ...state, modelName: action.payload };

    case 'SAVE_HISTORY':
      return saveToHistory(state);

    case 'UNDO': {
      if (state.historyIndex <= 0) return state;
      const newIndex = state.historyIndex - 1;
      const historyState = state.history[newIndex];
      // Resync custom technologies in data layer
      clearCustomTechsInCache();
      if (historyState.customTechnologies?.length) {
        registerCustomTechsInCache(historyState.customTechnologies);
      }
      return {
        ...state,
        nodes: historyState.nodes,
        edges: historyState.edges,
        boundaries: historyState.boundaries || [],
        customTechnologies: historyState.customTechnologies || [],
        severityOverrides: historyState.severityOverrides || {},
        implementedControls: historyState.implementedControls || {},
        historyIndex: newIndex,
      };
    }

    case 'REDO': {
      if (state.historyIndex >= state.history.length - 1) return state;
      const newIndex = state.historyIndex + 1;
      const historyState = state.history[newIndex];
      // Resync custom technologies in data layer
      clearCustomTechsInCache();
      if (historyState.customTechnologies?.length) {
        registerCustomTechsInCache(historyState.customTechnologies);
      }
      return {
        ...state,
        nodes: historyState.nodes,
        edges: historyState.edges,
        boundaries: historyState.boundaries || [],
        customTechnologies: historyState.customTechnologies || [],
        severityOverrides: historyState.severityOverrides || {},
        implementedControls: historyState.implementedControls || {},
        historyIndex: newIndex,
      };
    }

    case 'SET_SELECTED_NODE':
      return { ...state, selectedNodeId: action.payload, selectedEdgeId: action.payload ? null : state.selectedEdgeId, selectedBoundaryId: action.payload ? null : state.selectedBoundaryId };

    case 'SET_SELECTED_EDGE':
      return { ...state, selectedEdgeId: action.payload, selectedNodeId: action.payload ? null : state.selectedNodeId, selectedBoundaryId: action.payload ? null : state.selectedBoundaryId };

    case 'UPDATE_NODE_SENSITIVITY': {
      const { nodeId, sensitivity } = action.payload;
      return {
        ...state,
        nodes: state.nodes.map(node =>
          node.id === nodeId
            ? { ...node, data: { ...node.data, sensitivity } }
            : node
        ),
      };
    }

    case 'UPDATE_NODE_CUSTOM_NAME': {
      const { nodeId, customName } = action.payload;
      return {
        ...state,
        nodes: state.nodes.map(node =>
          node.id === nodeId
            ? { ...node, data: { ...node.data, customName: customName || undefined } }
            : node
        ),
      };
    }

    case 'UPDATE_NODE_THREATS_DISABLED': {
      const { nodeId, threatsDisabled } = action.payload;
      return {
        ...state,
        nodes: state.nodes.map(node =>
          node.id === nodeId
            ? { ...node, data: { ...node.data, threatsDisabled: threatsDisabled || undefined } }
            : node
        ),
      };
    }

    case 'SET_SELECTED_NODES':
      return { ...state, selectedNodes: action.payload };

    case 'COPY_SELECTION': {
      const { nodes, edges, zones, copyOrigin } = action.payload;
      return {
        ...state,
        clipboard: { nodes, edges, zones, copyOrigin },
        pasteCount: 0,
      };
    }

    case 'PASTE_CLIPBOARD': {
      if (!state.clipboard || (state.clipboard.nodes.length === 0 && state.clipboard.zones.length === 0)) {
        return state;
      }

      const offset = 40 * (state.pasteCount + 1);
      const nodeIdMap = new Map<string, string>();
      const boundaryIdMap = new Map<string, string>();

      // Create new boundaries first (so we can reference them in nodes)
      const newBoundaries: Node<ZoneNodeData>[] = state.clipboard.zones.map(clipZone => {
        const newId = uuidv4();
        boundaryIdMap.set(clipZone.originalId, newId);

        return {
          id: newId,
          type: 'boundaryNode',
          position: {
            x: state.clipboard!.copyOrigin.x + clipZone.relativePosition.x + offset,
            y: state.clipboard!.copyOrigin.y + clipZone.relativePosition.y + offset,
          },
          style: { width: clipZone.dimensions.width, height: clipZone.dimensions.height },
          zIndex: -1,
          data: {
            zoneType: clipZone.zoneType,
            // Only private zones can have a network type; public zones are always generic
            networkType: clipZone.zoneType === 'private' ? clipZone.networkType : undefined,
            label: NETWORK_ZONE_LABELS[clipZone.zoneType],
            customName: clipZone.customName,
            riskReductionEnabled: clipZone.riskReductionEnabled ?? (clipZone.zoneType === 'private'),
            riskReductionPercent: clipZone.riskReductionPercent ?? 20,
          },
        };
      });

      // Register any custom technologies from clipboard that aren't already registered
      const newCustomTechs: Technology[] = [];
      state.clipboard.nodes.forEach(clipNode => {
        if (clipNode.customTechnology && !getTechnologyById(clipNode.technologyId)) {
          registerCustomTechInCache(clipNode.customTechnology);
          newCustomTechs.push(clipNode.customTechnology);
        }
      });

      // Create new nodes with new IDs and offset positions
      const newNodes: Node<TechNodeData>[] = state.clipboard.nodes.map(clipNode => {
        const newId = uuidv4();
        nodeIdMap.set(clipNode.originalId, newId);

        const technology = getTechnologyById(clipNode.technologyId);
        if (!technology) return null;

        // Check if this node was in a boundary that was also copied
        const originalBoundaryId = state.clipboard!.zones.find(z =>
          z.containedNodeIds.includes(clipNode.originalId)
        )?.originalId;
        const newBoundaryId = originalBoundaryId ? boundaryIdMap.get(originalBoundaryId) : undefined;

        return {
          id: newId,
          type: 'techNode',
          position: {
            x: state.clipboard!.copyOrigin.x + clipNode.relativePosition.x + offset,
            y: state.clipboard!.copyOrigin.y + clipNode.relativePosition.y + offset,
          },
          zIndex: 1,
          data: {
            technology,
            label: technology.name,
            sensitivity: clipNode.sensitivity,
            customName: clipNode.customName,
          },
          ...(newBoundaryId && { parentId: newBoundaryId }),
        } as Node<TechNodeData>;
      }).filter((n): n is Node<TechNodeData> => n !== null);

      // Create new edges with mapped IDs
      const newEdges: Edge[] = state.clipboard.edges
        .filter(clipEdge =>
          nodeIdMap.has(clipEdge.originalSourceId) && nodeIdMap.has(clipEdge.originalTargetId)
        )
        .map(clipEdge => ({
          id: uuidv4(),
          source: nodeIdMap.get(clipEdge.originalSourceId)!,
          target: nodeIdMap.get(clipEdge.originalTargetId)!,
          type: 'labeledEdge',
          data: { label: clipEdge.label || '' },
        }));

      // Select the newly pasted nodes (not boundaries)
      const newNodeIds = newNodes.map(n => n.id);

      return {
        ...state,
        nodes: [...state.nodes, ...newNodes],
        edges: [...state.edges, ...newEdges],
        boundaries: [...state.boundaries, ...newBoundaries],
        customTechnologies: newCustomTechs.length > 0
          ? [...state.customTechnologies, ...newCustomTechs]
          : state.customTechnologies,
        selectedNodes: newNodeIds,
        selectedNodeId: newNodeIds[0] || null,
        pasteCount: state.pasteCount + 1,
      };
    }

    case 'REMOVE_NODES': {
      const { nodeIds } = action.payload;
      const nodeIdSet = new Set(nodeIds);
      return {
        ...state,
        nodes: state.nodes.filter(node => !nodeIdSet.has(node.id)),
        edges: state.edges.filter(
          edge => !nodeIdSet.has(edge.source) && !nodeIdSet.has(edge.target)
        ),
        selectedNodes: [],
        selectedNodeId: null,
      };
    }

    case 'NUDGE_NODES': {
      const { nodeIds, dx, dy } = action.payload;
      const nodeIdSet = new Set(nodeIds);

      // First, update positions
      const updatedNodes = state.nodes.map(node => {
        if (!nodeIdSet.has(node.id)) return node;
        return {
          ...node,
          position: { x: node.position.x + dx, y: node.position.y + dy },
        };
      });

      // Then, check boundary assignments for nudged nodes
      const nodesWithBoundaryUpdates = updatedNodes.map(node => {
        if (!nodeIdSet.has(node.id)) return node;

        // Get the node's current boundary assignment
        const currentBoundaryId = node.parentId;
        const currentBoundary = currentBoundaryId
          ? state.boundaries.find(b => b.id === currentBoundaryId)
          : null;

        // Calculate the absolute position of the node
        // If node is in a boundary, its position is relative to that boundary
        const absoluteNodePosition = currentBoundary
          ? calculateAbsolutePosition(node.position, currentBoundary.position)
          : node.position;

        // Get the center position of the node (in absolute coordinates)
        const nodeCenter = getNodeCenterPosition(absoluteNodePosition);

        // Find if the node is now inside a boundary
        const containingBoundary = findBoundaryAtPosition(nodeCenter, state.boundaries);

        if (containingBoundary && containingBoundary.id !== currentBoundaryId) {
          // Node moved into a new/different boundary - calculate relative position
          const relativePos = calculateRelativePosition(absoluteNodePosition, containingBoundary.position);
          return {
            ...node,
            position: relativePos,
            parentId: containingBoundary.id,
          };
        } else if (!containingBoundary && currentBoundaryId) {
          // Node moved out of its boundary - convert to absolute position
          return {
            ...node,
            position: absoluteNodePosition,
            parentId: undefined,
          };
        }

        // Node stayed in the same boundary (or no boundary), no change needed
        return node;
      });

      return {
        ...state,
        nodes: nodesWithBoundaryUpdates,
      };
    }

    case 'UPDATE_NODES_SENSITIVITY': {
      const { nodeIds, sensitivity } = action.payload;
      const nodeIdSet = new Set(nodeIds);
      return {
        ...state,
        nodes: state.nodes.map(node =>
          nodeIdSet.has(node.id)
            ? { ...node, data: { ...node.data, sensitivity } }
            : node
        ),
      };
    }

    case 'ADD_BOUNDARY': {
      const { position, zoneType, width = 300, height = 200 } = action.payload;
      const newBoundary: Node<ZoneNodeData> = {
        id: uuidv4(),
        type: 'boundaryNode',
        position,
        style: { width, height },
        zIndex: -1,
        data: {
          zoneType,
          label: NETWORK_ZONE_LABELS[zoneType],
          riskReductionEnabled: false,
          riskReductionPercent: 20,
        },
      };
      return {
        ...state,
        boundaries: [...state.boundaries, newBoundary],
      };
    }

    case 'REMOVE_BOUNDARY': {
      const { boundaryId } = action.payload;
      // Also unassign any nodes from this boundary
      return {
        ...state,
        boundaries: state.boundaries.filter(b => b.id !== boundaryId),
        nodes: state.nodes.map(node =>
          node.parentId === boundaryId
            ? { ...node, parentId: undefined, extent: undefined }
            : node
        ),
      };
    }

    case 'UPDATE_BOUNDARY_TYPE': {
      const { boundaryId, zoneType } = action.payload;
      return {
        ...state,
        boundaries: state.boundaries.map(b => {
          if (b.id !== boundaryId) return b;
          const wasPrivate = b.data.zoneType === 'private';
          // When switching to private, preserve existing value if already private, otherwise default to off
          // When switching to public, disable risk reduction
          const riskReductionEnabled = zoneType === 'private'
            ? (wasPrivate ? b.data.riskReductionEnabled ?? false : false)
            : false;
          // Public zones are always generic; private zones keep their networkType
          const networkType = zoneType === 'public' ? undefined : b.data.networkType;
          return {
            ...b,
            data: {
              ...b.data,
              zoneType,
              networkType,
              label: NETWORK_ZONE_LABELS[zoneType],
              riskReductionEnabled,
              riskReductionPercent: b.data.riskReductionPercent ?? 20,
            },
          };
        }),
      };
    }

    case 'UPDATE_BOUNDARY_DIMENSIONS': {
      const { boundaryId, width, height } = action.payload;
      return {
        ...state,
        boundaries: state.boundaries.map(b =>
          b.id === boundaryId
            ? { ...b, style: { ...b.style, width, height } }
            : b
        ),
      };
    }

    case 'UPDATE_BOUNDARY_NAME': {
      const { boundaryId, customName } = action.payload;
      return {
        ...state,
        boundaries: state.boundaries.map(b =>
          b.id === boundaryId
            ? { ...b, data: { ...b.data, customName: customName || undefined } }
            : b
        ),
      };
    }

    case 'SET_BOUNDARIES':
      return { ...state, boundaries: action.payload };

    case 'ASSIGN_NODE_TO_BOUNDARY': {
      const { nodeId, boundaryId } = action.payload;
      return {
        ...state,
        nodes: state.nodes.map(node =>
          node.id === nodeId
            ? {
                ...node,
                parentId: boundaryId || undefined,
              }
            : node
        ),
      };
    }

    case 'SET_SELECTED_BOUNDARY':
      return { ...state, selectedBoundaryId: action.payload, selectedNodeId: null, selectedEdgeId: null };

    case 'UPDATE_BOUNDARY_RISK_SETTINGS': {
      const { boundaryId, riskReductionEnabled, riskReductionPercent } = action.payload;
      return {
        ...state,
        boundaries: state.boundaries.map(b =>
          b.id === boundaryId
            ? { ...b, data: { ...b.data, riskReductionEnabled, riskReductionPercent } }
            : b
        ),
      };
    }

    case 'UPDATE_BOUNDARY_NETWORK_TYPE': {
      const { boundaryId, networkType } = action.payload;
      return {
        ...state,
        boundaries: state.boundaries.map(b =>
          b.id === boundaryId
            ? { ...b, data: { ...b.data, networkType } }
            : b
        ),
      };
    }

    case 'START_DRAWING_ZONE': {
      return {
        ...state,
        drawingZoneType: action.payload,
      };
    }

    case 'CANCEL_DRAWING_MODE': {
      return {
        ...state,
        drawingZoneType: null,
      };
    }

    case 'APPLY_NODE_CHANGES': {
      const removedIds = action.payload.flatMap(change =>
        change.type === 'remove' ? [change.id] : []
      );
      const prunedControls = removedIds.reduce(
        (acc, id) => pruneNodeControlKeys(acc, id),
        state.implementedControls,
      );
      return {
        ...state,
        nodes: applyNodeChanges(action.payload, state.nodes),
        implementedControls: prunedControls,
      };
    }

    case 'APPLY_EDGE_CHANGES': {
      return {
        ...state,
        edges: applyEdgeChanges(action.payload, state.edges),
      };
    }

    case 'APPLY_BOUNDARY_CHANGES': {
      return {
        ...state,
        boundaries: applyNodeChanges(action.payload, state.boundaries),
      };
    }

    case 'CONNECT_NODES': {
      const newEdge: Edge = {
        ...action.payload,
        id: uuidv4(),
        type: 'labeledEdge',
        data: { label: '' },
        source: action.payload.source || '',
        target: action.payload.target || '',
      };
      return {
        ...state,
        edges: addEdge(newEdge, state.edges),
      };
    }

    case 'UPDATE_PATHWAY_MITIGATION_SETTINGS': {
      return {
        ...state,
        pathwayMitigationSettings: action.payload,
      };
    }

    case 'REGISTER_CUSTOM_TECHNOLOGY': {
      const tech = action.payload;
      registerCustomTechInCache(tech);
      return {
        ...state,
        customTechnologies: [...state.customTechnologies, tech],
      };
    }

    case 'REMOVE_CUSTOM_TECHNOLOGY': {
      const { technologyId } = action.payload;
      unregisterCustomTechInCache(technologyId);
      // Calculate affected node IDs before filtering
      const removedNodeIds = new Set(
        state.nodes.filter(n => n.data.technology.id === technologyId).map(n => n.id)
      );
      return {
        ...state,
        customTechnologies: state.customTechnologies.filter(t => t.id !== technologyId),
        nodes: state.nodes.filter(n => !removedNodeIds.has(n.id)),
        edges: state.edges.filter(
          edge => !removedNodeIds.has(edge.source) && !removedNodeIds.has(edge.target)
        ),
      };
    }

    case 'UPDATE_CUSTOM_TECHNOLOGY': {
      const tech = action.payload;
      registerCustomTechInCache(tech);
      return {
        ...state,
        customTechnologies: state.customTechnologies.map(t =>
          t.id === tech.id ? tech : t
        ),
        nodes: state.nodes.map(node =>
          node.data.technology.id === tech.id
            ? { ...node, data: { ...node.data, technology: tech, label: tech.name } }
            : node
        ),
      };
    }

    case 'SET_SEVERITY_OVERRIDE': {
      const { key, severity } = action.payload;
      if (severity === null) {
        // Remove override
        const { [key]: _, ...rest } = state.severityOverrides;
        return { ...state, severityOverrides: rest };
      }
      return {
        ...state,
        severityOverrides: { ...state.severityOverrides, [key]: severity },
      };
    }

    case 'SET_SEVERITY_OVERRIDES_BATCH': {
      return {
        ...state,
        severityOverrides: { ...state.severityOverrides, ...action.payload },
      };
    }

    case 'SET_CONTROL_IMPLEMENTED': {
      const { key, implemented } = action.payload;
      if (!implemented) {
        // Remove from map so unchecked state is represented by absence,
        // keeping the record sparse and exports clean.
        const { [key]: _, ...rest } = state.implementedControls;
        return { ...state, implementedControls: rest };
      }
      return {
        ...state,
        implementedControls: { ...state.implementedControls, [key]: true },
      };
    }

    default:
      return state;
  }
}

// ============================================================================
// SPLIT CONTEXT TYPES - Each context has a focused responsibility
// ============================================================================

// 1. Diagram State Context - nodes, edges, boundaries and their change handlers
interface DiagramStateContextValue {
  nodes: Node<TechNodeData>[];
  edges: Edge[];
  boundaries: Node<ZoneNodeData>[];
  onNodesChange: OnNodesChange<Node<TechNodeData>>;
  onEdgesChange: OnEdgesChange;
  onBoundariesChange: OnNodesChange<Node<ZoneNodeData>>;
  onConnect: OnConnect;
}

// 2. Selection Context - selection state (changes frequently on clicks)
interface SelectionContextValue {
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  selectedBoundaryId: string | null;
  selectedNodes: string[];
  setSelectedNode: (nodeId: string | null) => void;
  setSelectedEdge: (edgeId: string | null) => void;
  setSelectedBoundary: (boundaryId: string | null) => void;
  setSelectedNodes: (nodeIds: string[]) => void;
  selectAll: () => void;
  deselectAll: () => void;
}

// 3. Threats Context - computed threats (only changes when threat-relevant data changes)
interface ThreatsContextValue {
  activeThreats: ActiveThreat[];
  severityOverrides: Record<string, ThreatSeverity>;
  implementedControls: Record<string, true>;
}

// 4. Actions Context - stable action functions (never changes reference)
interface ActionsContextValue {
  addNode: (technology: Technology, position: { x: number; y: number }, boundaryId?: string) => void;
  removeNode: (nodeId: string) => void;
  removeEdge: (edgeId: string) => void;
  updateEdgeLabel: (edgeId: string, label: string) => void;
  updateNodeSensitivity: (nodeId: string, sensitivity: DataSensitivity) => void;
  updateSelectedNodesSensitivity: (sensitivity: DataSensitivity) => void;
  updateNodeCustomName: (nodeId: string, customName: string) => void;
  updateNodeThreatsDisabled: (nodeId: string, threatsDisabled: boolean) => void;
  getNodeById: (nodeId: string) => Node<TechNodeData> | undefined;
  getBoundaryById: (boundaryId: string) => Node<ZoneNodeData> | undefined;
  removeSelectedNodes: () => void;
  nudgeNodes: (dx: number, dy: number) => void;
  // Boundary operations
  addBoundary: (position: { x: number; y: number }, zoneType: NetworkZone, width?: number, height?: number) => void;
  removeBoundary: (boundaryId: string) => void;
  updateBoundaryType: (boundaryId: string, zoneType: NetworkZone) => void;
  updateBoundaryDimensions: (boundaryId: string, width: number, height: number) => void;
  updateBoundaryName: (boundaryId: string, customName: string) => void;
  updateBoundaryRiskSettings: (boundaryId: string, enabled: boolean, percent: number) => void;
  updateBoundaryNetworkType: (boundaryId: string, networkType: ZoneNetworkType) => void;
  assignNodeToBoundary: (nodeId: string, boundaryId: string | null) => void;
  setCenterCallback: (callback: (x: number, y: number) => void) => void;
  centerOnPosition: (x: number, y: number) => void;
  setGetViewportCenterCallback: (callback: () => { x: number; y: number } | null) => void;
  getViewportCenter: () => { x: number; y: number } | null;
  setFitViewCallback: (callback: () => void) => void;
  setSeverityOverride: (key: string, severity: ThreatSeverity | null) => void;
  setSeverityOverridesBatch: (overrides: Record<string, ThreatSeverity>) => void;
  setControlImplemented: (key: string, implemented: boolean) => void;
  saveHistory: () => void;
}

// 5. History Context - undo/redo state
interface HistoryContextValue {
  canUndo: boolean;
  canRedo: boolean;
  undo: () => void;
  redo: () => void;
}

// 6. Drawing Context - drawing mode for zones
interface DrawingContextValue {
  drawingZoneType: NetworkZone | null;
  isDrawing: boolean;
  startDrawingPublicZone: () => void;
  startDrawingPrivateZone: () => void;
  cancelDrawingMode: () => void;
}

// 7. Model Context - model metadata and file operations
interface ModelContextValue {
  modelName: string;
  setModelName: (name: string) => void;
  exportModel: () => ThreatModel;
  importModel: (model: ThreatModel) => Promise<void>;
  clearDiagram: () => void;
}

// 8. Clipboard Context - clipboard operations
interface ClipboardContextValue {
  hasClipboard: boolean;
  copySelection: () => void;
  pasteClipboard: () => void;
  cutSelection: () => void;
  duplicateSelection: () => void;
}

// 9. Settings Context - pathway mitigation settings
interface SettingsContextValue {
  pathwayMitigationSettings: PathwayMitigationSettings;
  updatePathwayMitigationSettings: (settings: PathwayMitigationSettings) => void;
}

// 10. Custom Technologies Context
interface CustomTechContextValue {
  customTechnologies: Technology[];
  registerCustomTechnology: (tech: Technology) => void;
  removeCustomTechnology: (technologyId: string) => void;
  updateCustomTechnology: (tech: Technology) => void;
}

// Combined context for backward compatibility
interface ThreatModelContextValue extends
  DiagramStateContextValue,
  SelectionContextValue,
  ThreatsContextValue,
  ActionsContextValue,
  HistoryContextValue,
  DrawingContextValue,
  ModelContextValue,
  ClipboardContextValue,
  SettingsContextValue,
  CustomTechContextValue {}

// Create individual contexts
const DiagramStateContext = createContext<DiagramStateContextValue | null>(null);
const SelectionContext = createContext<SelectionContextValue | null>(null);
const ThreatsContext = createContext<ThreatsContextValue | null>(null);
const ActionsContext = createContext<ActionsContextValue | null>(null);
const HistoryContext = createContext<HistoryContextValue | null>(null);
const DrawingContext = createContext<DrawingContextValue | null>(null);
const ModelContext = createContext<ModelContextValue | null>(null);
const ClipboardContext = createContext<ClipboardContextValue | null>(null);
const SettingsContext = createContext<SettingsContextValue | null>(null);
const CustomTechContext = createContext<CustomTechContextValue | null>(null);

// Legacy combined context for backward compatibility
const ThreatModelContext = createContext<ThreatModelContextValue | null>(null);

// Extract only threat-relevant data from nodes (excludes position, selection, etc.)
function extractThreatRelevantNodeData(nodes: Node<TechNodeData>[]) {
  return nodes.map(node => ({
    id: node.id,
    parentId: node.parentId,
    technologyId: node.data.technology.id,
    sensitivity: node.data.sensitivity,
    customName: node.data.customName,
    threatsDisabled: node.data.threatsDisabled,
  }));
}

// Extract only threat-relevant data from edges
function extractThreatRelevantEdgeData(edges: Edge[]) {
  return edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: (edge.data as { label?: string } | undefined)?.label,
  }));
}

// Extract only threat-relevant data from boundaries (excludes position, dimensions)
function extractThreatRelevantBoundaryData(boundaries: Node<ZoneNodeData>[]) {
  return boundaries.map(boundary => ({
    id: boundary.id,
    zoneType: boundary.data.zoneType,
    networkType: boundary.data.networkType,
    customName: boundary.data.customName,
    riskReductionEnabled: boundary.data.riskReductionEnabled,
    riskReductionPercent: boundary.data.riskReductionPercent,
  }));
}

// Create a fingerprint of threat-relevant data for cache invalidation
function createThreatFingerprint(
  nodes: ReturnType<typeof extractThreatRelevantNodeData>,
  edges: ReturnType<typeof extractThreatRelevantEdgeData>,
  boundaries: ReturnType<typeof extractThreatRelevantBoundaryData>
): string {
  // Sort by ID for consistent ordering regardless of array order changes
  const sortedNodes = [...nodes].sort((a, b) => a.id.localeCompare(b.id));
  const sortedEdges = [...edges].sort((a, b) => a.id.localeCompare(b.id));
  const sortedBoundaries = [...boundaries].sort((a, b) => a.id.localeCompare(b.id));

  return JSON.stringify({ nodes: sortedNodes, edges: sortedEdges, boundaries: sortedBoundaries });
}

// Provider component
export function ThreatModelProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(threatModelReducer, initialState);
  const centerCallbackRef = useRef<((x: number, y: number) => void) | null>(null);
  const getViewportCenterCallbackRef = useRef<(() => { x: number; y: number } | null) | null>(null);
  const fitViewCallbackRef = useRef<(() => void) | null>(null);

  // Cache for threat computation - only recompute when threat-relevant data changes
  const threatCacheRef = useRef<{
    fingerprint: string;
    threats: ActiveThreat[];
  }>({ fingerprint: '', threats: [] });

  // Extract threat-relevant data (memoized to avoid recalculation)
  // Also include pathwayMitigationSettings as it affects threat computation
  const threatRelevantData = useMemo(() => {
    const nodes = extractThreatRelevantNodeData(state.nodes);
    const edges = extractThreatRelevantEdgeData(state.edges);
    const boundaries = extractThreatRelevantBoundaryData(state.boundaries);
    const baseFingerprint = createThreatFingerprint(nodes, edges, boundaries);
    // Include pathway mitigation settings, severity overrides, and custom tech threatIds in fingerprint
    const customTechFingerprint = state.customTechnologies.map(t => `${t.id}:${t.threatIds.join(',')}`).join('|');
    const fingerprint = baseFingerprint + JSON.stringify(state.pathwayMitigationSettings) + JSON.stringify(state.severityOverrides) + customTechFingerprint;
    return { nodes, edges, boundaries, fingerprint, pathwayMitigationSettings: state.pathwayMitigationSettings, severityOverrides: state.severityOverrides };
  }, [state.nodes, state.edges, state.boundaries, state.pathwayMitigationSettings, state.severityOverrides, state.customTechnologies]);

  // Compute active threats only when fingerprint changes (smart caching)
  const activeThreats = useMemo(() => {
    const { nodes, edges, boundaries, fingerprint, pathwayMitigationSettings, severityOverrides } = threatRelevantData;

    // Return cached threats if fingerprint hasn't changed
    if (fingerprint === threatCacheRef.current.fingerprint) {
      return threatCacheRef.current.threats;
    }

    // Fingerprint changed - recompute threats
    const diagramNodes = nodes.map(n => ({
      id: n.id,
      parentId: n.parentId,
      data: {
        technologyId: n.technologyId,
        sensitivity: n.sensitivity,
        customName: n.customName,
        threatsDisabled: n.threatsDisabled,
      },
    }));
    const diagramEdges = edges.map(e => ({
      id: e.id,
      source: e.source,
      target: e.target,
      data: e.label ? { label: e.label } : undefined,
    }));
    const diagramBoundaries = boundaries.map(b => ({
      id: b.id,
      zoneType: b.zoneType,
      networkType: b.networkType,
      customName: b.customName,
      riskReductionEnabled: b.riskReductionEnabled,
      riskReductionPercent: b.riskReductionPercent,
    }));

    const threats = resolveActiveThreats(diagramNodes, diagramEdges, diagramBoundaries, pathwayMitigationSettings, severityOverrides);

    // Update cache
    threatCacheRef.current = { fingerprint, threats };

    return threats;
  }, [threatRelevantData]);

  // Computed undo/redo state
  const canUndo = state.historyIndex > 0;
  const canRedo = state.historyIndex < state.history.length - 1;

  // Undo/Redo handlers
  const undo = useCallback(() => {
    dispatch({ type: 'UNDO' });
  }, []);

  const redo = useCallback(() => {
    dispatch({ type: 'REDO' });
  }, []);

  // Center callback for ReactFlow integration
  const setCenterCallback = useCallback((callback: (x: number, y: number) => void) => {
    centerCallbackRef.current = callback;
  }, []);

  const centerOnPosition = useCallback((x: number, y: number) => {
    if (centerCallbackRef.current) {
      centerCallbackRef.current(x, y);
    }
  }, []);

  const setGetViewportCenterCallback = useCallback((callback: () => { x: number; y: number } | null) => {
    getViewportCenterCallbackRef.current = callback;
  }, []);

  const getViewportCenter = useCallback((): { x: number; y: number } | null => {
    if (getViewportCenterCallbackRef.current) {
      return getViewportCenterCallbackRef.current();
    }
    return null;
  }, []);

  const setFitViewCallback = useCallback((callback: () => void) => {
    fitViewCallbackRef.current = callback;
  }, []);

  // Action handlers
  const addNode = useCallback(
    (technology: Technology, position: { x: number; y: number }, boundaryId?: string) => {
      dispatch({ type: 'SAVE_HISTORY' });
      dispatch({ type: 'ADD_NODE', payload: { technology, position, boundaryId } });
    },
    []
  );

  const removeNode = useCallback((nodeId: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'REMOVE_NODE', payload: { nodeId } });
  }, []);

  const removeEdge = useCallback((edgeId: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'REMOVE_EDGE', payload: { edgeId } });
  }, []);

  const updateEdgeLabel = useCallback((edgeId: string, label: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_EDGE_LABEL', payload: { edgeId, label } });
  }, []);

  const clearDiagram = useCallback(() => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'CLEAR_DIAGRAM' });
  }, []);

  const registerCustomTechnology = useCallback((tech: Technology) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'REGISTER_CUSTOM_TECHNOLOGY', payload: tech });
  }, []);

  const removeCustomTechnology = useCallback((technologyId: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'REMOVE_CUSTOM_TECHNOLOGY', payload: { technologyId } });
  }, []);

  const updateCustomTechnology = useCallback((tech: Technology) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_CUSTOM_TECHNOLOGY', payload: tech });
  }, []);

  const setModelName = useCallback((name: string) => {
    dispatch({ type: 'SET_MODEL_NAME', payload: name });
  }, []);

  const exportModel = useCallback((): ThreatModel => {
    const now = new Date().toISOString();
    return {
      version: '1.5',
      name: state.modelName,
      createdAt: now,
      updatedAt: now,
      nodes: state.nodes.map(node => ({
        id: node.id,
        technologyId: node.data.technology.id,
        position: node.position,
        sensitivity: node.data.sensitivity,
        customName: node.data.customName,
        zoneId: node.parentId,
        threatsDisabled: node.data.threatsDisabled,
      })),
      edges: state.edges.map(edge => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        sourceHandle: edge.sourceHandle ?? undefined,
        targetHandle: edge.targetHandle ?? undefined,
        label: (edge.data as { label?: string } | undefined)?.label,
      })),
      zones: state.boundaries.map(boundary => ({
        id: boundary.id,
        zoneType: boundary.data.zoneType,
        networkType: boundary.data.networkType,
        position: boundary.position,
        dimensions: {
          // Check multiple locations for dimensions (NodeResizer may store them differently)
          width: boundary.width ?? boundary.measured?.width ?? (boundary.style?.width as number) ?? 300,
          height: boundary.height ?? boundary.measured?.height ?? (boundary.style?.height as number) ?? 200,
        },
        customName: boundary.data.customName,
        riskReductionEnabled: boundary.data.riskReductionEnabled,
        riskReductionPercent: boundary.data.riskReductionPercent,
      })),
      pathwayMitigationSettings: state.pathwayMitigationSettings,
      ...(state.customTechnologies.length > 0 && {
        customTechnologies: state.customTechnologies,
      }),
      ...(Object.keys(state.severityOverrides).length > 0 && {
        severityOverrides: state.severityOverrides,
      }),
      ...(Object.keys(state.implementedControls).length > 0 && {
        implementedControls: state.implementedControls,
      }),
    };
  }, [state.nodes, state.edges, state.boundaries, state.modelName, state.pathwayMitigationSettings, state.customTechnologies, state.severityOverrides, state.implementedControls]);

  const importModel = useCallback(async (model: ThreatModel) => {
    // Sanitize custom tech descriptions before registering
    if (model.customTechnologies?.length) {
      model = {
        ...model,
        customTechnologies: model.customTechnologies.map(tech =>
          tech.description && tech.description.length > 150
            ? { ...tech, description: tech.description.slice(0, 150) }
            : tech
        ),
      };
    }
    // Determine which providers are referenced by the model's nodes and load
    // them before dispatching — the IMPORT_MODEL reducer calls getTechnologyById
    // synchronously, so provider data must be in the map before it runs.
    const neededProviders = new Set(
      model.nodes
        .map(n => providerFromTechId(n.technologyId))
        .filter((p): p is CloudProvider => p !== null && p !== 'actor' && p !== 'custom')
    );
    await loadProviders([...neededProviders]);
    // Register custom technologies before import so getTechnologyById finds them
    clearCustomTechsInCache();
    if (model.customTechnologies?.length) {
      registerCustomTechsInCache(model.customTechnologies);
    }
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'IMPORT_MODEL', payload: model });
    // Bring the imported content into view; a model authored at different
    // coordinates would otherwise land off-screen.
    if (model.nodes.length > 0 || (model.zones?.length ?? 0) > 0) {
      fitViewCallbackRef.current?.();
    }
  }, []);

  // --- Autosave ---
  // Guards saving until the one-time restore attempt has completed, so the empty
  // initial state can never clobber a model persisted from a previous session.
  const hasHydratedRef = useRef(false);
  // Ensures the restore toast fires once even under StrictMode's double-mount.
  const restoreNotifiedRef = useRef(false);

  // Restore a previously autosaved model on first mount.
  useEffect(() => {
    const saved = loadPersistedModel();
    if (saved && modelHasContent(saved)) {
      // importModel is async (loads providers + registers custom techs); mark
      // hydration complete only once it resolves so the save effect stays idle
      // until the restored state has actually been applied.
      importModel(saved)
        .then(() => {
          if (restoreNotifiedRef.current) return;
          restoreNotifiedRef.current = true;
          showToast('Restored your last session', {
            actionLabel: 'Start fresh',
            onAction: () => {
              dispatch({ type: 'SAVE_HISTORY' });
              dispatch({ type: 'CLEAR_DIAGRAM' });
              dispatch({ type: 'SET_MODEL_NAME', payload: 'Untitled Threat Model' });
              clearPersistedModel();
            },
          });
        })
        .finally(() => {
          hasHydratedRef.current = true;
        });
    } else {
      hasHydratedRef.current = true;
    }
    // Run once on mount; importModel is a stable useCallback.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Debounced persistence: exportModel's identity changes whenever any
  // model-relevant state changes, so this re-runs on every meaningful edit.
  useEffect(() => {
    if (!hasHydratedRef.current) return;
    const handle = setTimeout(() => {
      savePersistedModel(exportModel());
    }, AUTOSAVE_DEBOUNCE_MS);
    return () => clearTimeout(handle);
  }, [exportModel]);

  const updatePathwayMitigationSettings = useCallback((settings: PathwayMitigationSettings) => {
    dispatch({ type: 'UPDATE_PATHWAY_MITIGATION_SETTINGS', payload: settings });
  }, []);

  const setSeverityOverride = useCallback((key: string, severity: ThreatSeverity | null) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'SET_SEVERITY_OVERRIDE', payload: { key, severity } });
  }, []);

  const setSeverityOverridesBatch = useCallback((overrides: Record<string, ThreatSeverity>) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'SET_SEVERITY_OVERRIDES_BATCH', payload: overrides });
  }, []);

  const setControlImplemented = useCallback((key: string, implemented: boolean) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'SET_CONTROL_IMPLEMENTED', payload: { key, implemented } });
  }, []);

  // Snapshot the current state into history without mutating anything else.
  // Used at the start of interactions (drags, nudge bursts) whose subsequent
  // changes flow through actions that don't save history themselves.
  const saveHistory = useCallback(() => {
    dispatch({ type: 'SAVE_HISTORY' });
  }, []);

  const setSelectedNode = useCallback((nodeId: string | null) => {
    dispatch({ type: 'SET_SELECTED_NODE', payload: nodeId });
  }, []);

  const setSelectedEdge = useCallback((edgeId: string | null) => {
    dispatch({ type: 'SET_SELECTED_EDGE', payload: edgeId });
  }, []);

  const updateNodeSensitivity = useCallback((nodeId: string, sensitivity: DataSensitivity) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_NODE_SENSITIVITY', payload: { nodeId, sensitivity } });
  }, []);

  const updateSelectedNodesSensitivity = useCallback((sensitivity: DataSensitivity) => {
    if (state.selectedNodes.length === 0) return;
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_NODES_SENSITIVITY', payload: { nodeIds: state.selectedNodes, sensitivity } });
  }, [state.selectedNodes]);

  const updateNodeCustomName = useCallback((nodeId: string, customName: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_NODE_CUSTOM_NAME', payload: { nodeId, customName } });
  }, []);

  const updateNodeThreatsDisabled = useCallback((nodeId: string, threatsDisabled: boolean) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_NODE_THREATS_DISABLED', payload: { nodeId, threatsDisabled } });
  }, []);

  const getNodeById = useCallback((nodeId: string) => {
    return state.nodes.find(node => node.id === nodeId);
  }, [state.nodes]);

  const getBoundaryById = useCallback((boundaryId: string) => {
    return state.boundaries.find(boundary => boundary.id === boundaryId);
  }, [state.boundaries]);

  const setSelectedBoundary = useCallback((boundaryId: string | null) => {
    dispatch({ type: 'SET_SELECTED_BOUNDARY', payload: boundaryId });
  }, []);

  const setSelectedNodes = useCallback((nodeIds: string[]) => {
    dispatch({ type: 'SET_SELECTED_NODES', payload: nodeIds });
    // Update selectedNodeId to first selected or null
    dispatch({ type: 'SET_SELECTED_NODE', payload: nodeIds[0] || null });
  }, []);

  const copySelection = useCallback(() => {
    if (state.selectedNodes.length === 0) return;

    const selectedNodeSet = new Set(state.selectedNodes);
    const selectedNodesData = state.nodes.filter(n => selectedNodeSet.has(n.id));

    if (selectedNodesData.length === 0) return;

    // Find boundaries that contain selected nodes
    const boundaryIdsToInclude = new Set<string>();
    selectedNodesData.forEach(node => {
      if (node.parentId) {
        boundaryIdsToInclude.add(node.parentId);
      }
    });
    const selectedBoundariesData = state.boundaries.filter(b => boundaryIdsToInclude.has(b.id));

    // Calculate copy origin (centroid of selected nodes and boundaries)
    const allPositions = [
      ...selectedNodesData.map(n => n.position),
      ...selectedBoundariesData.map(b => b.position),
    ];
    const sumX = allPositions.reduce((sum, p) => sum + p.x, 0);
    const sumY = allPositions.reduce((sum, p) => sum + p.y, 0);
    const copyOrigin = {
      x: sumX / allPositions.length,
      y: sumY / allPositions.length,
    };

    // Convert to clipboard format with relative positions
    const clipboardNodes: ClipboardNode[] = selectedNodesData.map(node => ({
      originalId: node.id,
      technologyId: node.data.technology.id,
      relativePosition: {
        x: node.position.x - copyOrigin.x,
        y: node.position.y - copyOrigin.y,
      },
      sensitivity: node.data.sensitivity,
      customName: node.data.customName,
      ...(node.data.technology.isCustom && { customTechnology: node.data.technology }),
    }));

    // Get edges where both source and target are in selection
    const clipboardEdges: ClipboardEdge[] = state.edges
      .filter(e => selectedNodeSet.has(e.source) && selectedNodeSet.has(e.target))
      .map(edge => ({
        originalSourceId: edge.source,
        originalTargetId: edge.target,
        label: (edge.data as { label?: string } | undefined)?.label,
      }));

    // Convert boundaries to clipboard format
    // Check multiple locations for dimensions (React Flow may store them differently)
    const clipboardZones: ClipboardZone[] = selectedBoundariesData.map(boundary => {
      const width = boundary.width
        ?? boundary.measured?.width
        ?? (boundary.style?.width as number)
        ?? 300;
      const height = boundary.height
        ?? boundary.measured?.height
        ?? (boundary.style?.height as number)
        ?? 200;

      return {
        originalId: boundary.id,
        zoneType: boundary.data.zoneType,
        networkType: boundary.data.networkType,
        relativePosition: {
          x: boundary.position.x - copyOrigin.x,
          y: boundary.position.y - copyOrigin.y,
        },
        dimensions: { width, height },
        customName: boundary.data.customName,
        riskReductionEnabled: boundary.data.riskReductionEnabled,
        riskReductionPercent: boundary.data.riskReductionPercent,
        containedNodeIds: selectedNodesData
          .filter(n => n.parentId === boundary.id)
          .map(n => n.id),
      };
    });

    dispatch({
      type: 'COPY_SELECTION',
      payload: { nodes: clipboardNodes, edges: clipboardEdges, zones: clipboardZones, copyOrigin },
    });
  }, [state.selectedNodes, state.nodes, state.edges, state.boundaries]);

  const pasteClipboard = useCallback(() => {
    if (!state.clipboard) return;
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'PASTE_CLIPBOARD' });
  }, [state.clipboard]);

  const cutSelection = useCallback(() => {
    copySelection();
    if (state.selectedNodes.length > 0) {
      dispatch({ type: 'SAVE_HISTORY' });
      dispatch({ type: 'REMOVE_NODES', payload: { nodeIds: state.selectedNodes } });
    }
  }, [copySelection, state.selectedNodes]);

  const duplicateSelection = useCallback(() => {
    copySelection();
    // Need to wait for copy to complete, then paste
    // Since dispatch is synchronous, this works:
    setTimeout(() => {
      dispatch({ type: 'SAVE_HISTORY' });
      dispatch({ type: 'PASTE_CLIPBOARD' });
    }, 0);
  }, [copySelection]);

  const removeSelectedNodes = useCallback(() => {
    if (state.selectedNodes.length === 0) return;
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'REMOVE_NODES', payload: { nodeIds: state.selectedNodes } });
  }, [state.selectedNodes]);

  const selectAll = useCallback(() => {
    const allNodeIds = state.nodes.map(n => n.id);
    dispatch({ type: 'SET_SELECTED_NODES', payload: allNodeIds });
    dispatch({ type: 'SET_SELECTED_NODE', payload: allNodeIds[0] || null });
  }, [state.nodes]);

  const deselectAll = useCallback(() => {
    dispatch({ type: 'SET_SELECTED_NODES', payload: [] });
    dispatch({ type: 'SET_SELECTED_NODE', payload: null });
    dispatch({ type: 'SET_SELECTED_EDGE', payload: null });
    dispatch({ type: 'SET_SELECTED_BOUNDARY', payload: null });
  }, []);

  const nudgeNodes = useCallback((dx: number, dy: number) => {
    if (state.selectedNodes.length === 0) return;
    dispatch({ type: 'NUDGE_NODES', payload: { nodeIds: state.selectedNodes, dx, dy } });
  }, [state.selectedNodes]);

  // Boundary action handlers
  const addBoundary = useCallback(
    (position: { x: number; y: number }, zoneType: NetworkZone, width?: number, height?: number) => {
      dispatch({ type: 'SAVE_HISTORY' });
      dispatch({ type: 'ADD_BOUNDARY', payload: { position, zoneType, width, height } });
    },
    []
  );

  const removeBoundary = useCallback((boundaryId: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'REMOVE_BOUNDARY', payload: { boundaryId } });
  }, []);

  const updateBoundaryType = useCallback((boundaryId: string, zoneType: NetworkZone) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_BOUNDARY_TYPE', payload: { boundaryId, zoneType } });
  }, []);

  const updateBoundaryDimensions = useCallback((boundaryId: string, width: number, height: number) => {
    dispatch({ type: 'UPDATE_BOUNDARY_DIMENSIONS', payload: { boundaryId, width, height } });
  }, []);

  const updateBoundaryName = useCallback((boundaryId: string, customName: string) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_BOUNDARY_NAME', payload: { boundaryId, customName } });
  }, []);

  const updateBoundaryRiskSettings = useCallback((boundaryId: string, enabled: boolean, percent: number) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_BOUNDARY_RISK_SETTINGS', payload: { boundaryId, riskReductionEnabled: enabled, riskReductionPercent: percent } });
  }, []);

  const updateBoundaryNetworkType = useCallback((boundaryId: string, networkType: ZoneNetworkType) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'UPDATE_BOUNDARY_NETWORK_TYPE', payload: { boundaryId, networkType } });
  }, []);

  const assignNodeToBoundary = useCallback((nodeId: string, boundaryId: string | null) => {
    dispatch({ type: 'SAVE_HISTORY' });
    dispatch({ type: 'ASSIGN_NODE_TO_BOUNDARY', payload: { nodeId, boundaryId } });
  }, []);

  const onBoundariesChange: OnNodesChange<Node<ZoneNodeData>> = useCallback(
    changes => {
      dispatch({ type: 'APPLY_BOUNDARY_CHANGES', payload: changes });
    },
    []
  );

  // Drawing mode for zones
  const isDrawing = state.drawingZoneType !== null;

  const startDrawingPublicZone = useCallback(() => {
    dispatch({ type: 'START_DRAWING_ZONE', payload: 'public' });
  }, []);

  const startDrawingPrivateZone = useCallback(() => {
    dispatch({ type: 'START_DRAWING_ZONE', payload: 'private' });
  }, []);

  const cancelDrawingMode = useCallback(() => {
    dispatch({ type: 'CANCEL_DRAWING_MODE' });
  }, []);

  // React Flow handlers - stable callbacks that dispatch to reducer
  const onNodesChange: OnNodesChange<Node<TechNodeData>> = useCallback(
    changes => {
      dispatch({ type: 'APPLY_NODE_CHANGES', payload: changes });
    },
    []
  );

  const onEdgesChange: OnEdgesChange = useCallback(
    changes => {
      dispatch({ type: 'APPLY_EDGE_CHANGES', payload: changes });
    },
    []
  );

  const onConnect: OnConnect = useCallback(
    connection => {
      dispatch({ type: 'SAVE_HISTORY' });
      dispatch({ type: 'CONNECT_NODES', payload: connection });
    },
    []
  );

  // ============================================================================
  // MEMOIZED CONTEXT VALUES - Each context updates independently
  // ============================================================================

  // 1. Diagram State - updates on every node/edge/boundary change (drags, etc.)
  const diagramStateValue = useMemo<DiagramStateContextValue>(() => ({
    nodes: state.nodes,
    edges: state.edges,
    boundaries: state.boundaries,
    onNodesChange,
    onEdgesChange,
    onBoundariesChange,
    onConnect,
  }), [state.nodes, state.edges, state.boundaries, onNodesChange, onEdgesChange, onBoundariesChange, onConnect]);

  // 2. Selection - updates on selection changes (clicks)
  const selectionValue = useMemo<SelectionContextValue>(() => ({
    selectedNodeId: state.selectedNodeId,
    selectedEdgeId: state.selectedEdgeId,
    selectedBoundaryId: state.selectedBoundaryId,
    selectedNodes: state.selectedNodes,
    setSelectedNode,
    setSelectedEdge,
    setSelectedBoundary,
    setSelectedNodes,
    selectAll,
    deselectAll,
  }), [state.selectedNodeId, state.selectedEdgeId, state.selectedBoundaryId, state.selectedNodes, setSelectedNode, setSelectedEdge, setSelectedBoundary, setSelectedNodes, selectAll, deselectAll]);

  // 3. Threats - updates only when threat-relevant data changes (smart caching)
  const threatsValue = useMemo<ThreatsContextValue>(() => ({
    activeThreats,
    severityOverrides: state.severityOverrides,
    implementedControls: state.implementedControls,
  }), [activeThreats, state.severityOverrides, state.implementedControls]);

  // 4. Actions - stable, never updates (all callbacks have empty or minimal deps)
  const actionsValue = useMemo<ActionsContextValue>(() => ({
    addNode,
    removeNode,
    removeEdge,
    updateEdgeLabel,
    updateNodeSensitivity,
    updateSelectedNodesSensitivity,
    updateNodeCustomName,
    updateNodeThreatsDisabled,
    getNodeById,
    getBoundaryById,
    removeSelectedNodes,
    nudgeNodes,
    addBoundary,
    removeBoundary,
    updateBoundaryType,
    updateBoundaryDimensions,
    updateBoundaryName,
    updateBoundaryRiskSettings,
    updateBoundaryNetworkType,
    assignNodeToBoundary,
    setCenterCallback,
    centerOnPosition,
    setGetViewportCenterCallback,
    getViewportCenter,
    setFitViewCallback,
    setSeverityOverride,
    setSeverityOverridesBatch,
    setControlImplemented,
    saveHistory,
  }), [
    addNode, removeNode, removeEdge, updateEdgeLabel,
    updateNodeSensitivity, updateSelectedNodesSensitivity, updateNodeCustomName, updateNodeThreatsDisabled,
    getNodeById, getBoundaryById, removeSelectedNodes, nudgeNodes,
    addBoundary, removeBoundary, updateBoundaryType, updateBoundaryDimensions,
    updateBoundaryName, updateBoundaryRiskSettings, updateBoundaryNetworkType,
    assignNodeToBoundary, setCenterCallback, centerOnPosition,
    setGetViewportCenterCallback, getViewportCenter, setFitViewCallback,
    setSeverityOverride, setSeverityOverridesBatch, setControlImplemented,
    saveHistory,
  ]);

  // 5. History - updates after undo/redo actions
  const historyValue = useMemo<HistoryContextValue>(() => ({
    canUndo,
    canRedo,
    undo,
    redo,
  }), [canUndo, canRedo, undo, redo]);

  // 6. Drawing - updates when drawing mode changes
  const drawingValue = useMemo<DrawingContextValue>(() => ({
    drawingZoneType: state.drawingZoneType,
    isDrawing,
    startDrawingPublicZone,
    startDrawingPrivateZone,
    cancelDrawingMode,
  }), [state.drawingZoneType, isDrawing, startDrawingPublicZone, startDrawingPrivateZone, cancelDrawingMode]);

  // 7. Model - updates on model name/import/export changes
  const modelValue = useMemo<ModelContextValue>(() => ({
    modelName: state.modelName,
    setModelName,
    exportModel,
    importModel,
    clearDiagram,
  }), [state.modelName, setModelName, exportModel, importModel, clearDiagram]);

  // 8. Clipboard - updates on clipboard changes
  const clipboardValue = useMemo<ClipboardContextValue>(() => ({
    hasClipboard: state.clipboard !== null && (state.clipboard.nodes.length > 0 || state.clipboard.zones.length > 0),
    copySelection,
    pasteClipboard,
    cutSelection,
    duplicateSelection,
  }), [state.clipboard, copySelection, pasteClipboard, cutSelection, duplicateSelection]);

  // 9. Settings - updates on pathway mitigation settings changes
  const settingsValue = useMemo<SettingsContextValue>(() => ({
    pathwayMitigationSettings: state.pathwayMitigationSettings,
    updatePathwayMitigationSettings,
  }), [state.pathwayMitigationSettings, updatePathwayMitigationSettings]);

  // 10. Custom Technologies - updates when custom technologies change
  const customTechValue = useMemo<CustomTechContextValue>(() => ({
    customTechnologies: state.customTechnologies,
    registerCustomTechnology,
    removeCustomTechnology,
    updateCustomTechnology,
  }), [state.customTechnologies, registerCustomTechnology, removeCustomTechnology, updateCustomTechnology]);

  // Combined value for backward compatibility
  const combinedValue = useMemo<ThreatModelContextValue>(() => ({
    ...diagramStateValue,
    ...selectionValue,
    ...threatsValue,
    ...actionsValue,
    ...historyValue,
    ...drawingValue,
    ...modelValue,
    ...clipboardValue,
    ...settingsValue,
    ...customTechValue,
  }), [diagramStateValue, selectionValue, threatsValue, actionsValue, historyValue, drawingValue, modelValue, clipboardValue, settingsValue, customTechValue]);

  return (
    <DiagramStateContext.Provider value={diagramStateValue}>
      <SelectionContext.Provider value={selectionValue}>
        <ThreatsContext.Provider value={threatsValue}>
          <ActionsContext.Provider value={actionsValue}>
            <HistoryContext.Provider value={historyValue}>
              <DrawingContext.Provider value={drawingValue}>
                <ModelContext.Provider value={modelValue}>
                  <ClipboardContext.Provider value={clipboardValue}>
                    <SettingsContext.Provider value={settingsValue}>
                      <CustomTechContext.Provider value={customTechValue}>
                        <ThreatModelContext.Provider value={combinedValue}>
                          {children}
                        </ThreatModelContext.Provider>
                      </CustomTechContext.Provider>
                    </SettingsContext.Provider>
                  </ClipboardContext.Provider>
                </ModelContext.Provider>
              </DrawingContext.Provider>
            </HistoryContext.Provider>
          </ActionsContext.Provider>
        </ThreatsContext.Provider>
      </SelectionContext.Provider>
    </DiagramStateContext.Provider>
  );
}

// ============================================================================
// HOOKS - Use specific hooks for better performance
// ============================================================================

// Legacy combined hook for backward compatibility
export function useThreatModel() {
  const context = useContext(ThreatModelContext);
  if (!context) {
    throw new Error('useThreatModel must be used within ThreatModelProvider');
  }
  return context;
}

// Specialized hooks - use these for better performance
export function useDiagramState() {
  const context = useContext(DiagramStateContext);
  if (!context) {
    throw new Error('useDiagramState must be used within ThreatModelProvider');
  }
  return context;
}

export function useSelection() {
  const context = useContext(SelectionContext);
  if (!context) {
    throw new Error('useSelection must be used within ThreatModelProvider');
  }
  return context;
}

export function useThreats() {
  const context = useContext(ThreatsContext);
  if (!context) {
    throw new Error('useThreats must be used within ThreatModelProvider');
  }
  return context;
}

export function useActions() {
  const context = useContext(ActionsContext);
  if (!context) {
    throw new Error('useActions must be used within ThreatModelProvider');
  }
  return context;
}

export function useHistory() {
  const context = useContext(HistoryContext);
  if (!context) {
    throw new Error('useHistory must be used within ThreatModelProvider');
  }
  return context;
}

export function useDrawing() {
  const context = useContext(DrawingContext);
  if (!context) {
    throw new Error('useDrawing must be used within ThreatModelProvider');
  }
  return context;
}

export function useModel() {
  const context = useContext(ModelContext);
  if (!context) {
    throw new Error('useModel must be used within ThreatModelProvider');
  }
  return context;
}

export function useClipboard() {
  const context = useContext(ClipboardContext);
  if (!context) {
    throw new Error('useClipboard must be used within ThreatModelProvider');
  }
  return context;
}

export function useSettings() {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error('useSettings must be used within ThreatModelProvider');
  }
  return context;
}

export function useCustomTechnologies() {
  const context = useContext(CustomTechContext);
  if (!context) {
    throw new Error('useCustomTechnologies must be used within ThreatModelProvider');
  }
  return context;
}
