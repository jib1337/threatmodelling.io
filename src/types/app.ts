// Types owned by the application rather than the technology & threat catalogue.

import type {
  CloudProvider,
  PathwayMitigationType,
  Threat,
  ThreatSeverity,
  Technology,
} from '../data/librarySchema';
import { PATHWAY_MITIGATION_DEFINITIONS } from '../data/librarySchema';

// Network zone types for trust zones
export type NetworkZone = 'public' | 'private';

export const NETWORK_ZONE_LABELS: Record<NetworkZone, string> = {
  'public': 'Public Network',
  'private': 'Private Network',
};

export const NETWORK_ZONE_RISK_MULTIPLIERS: Record<NetworkZone, number> = {
  'public': 1.0,
  'private': 0.8,
};

// Network type for zones (cloud provider VPC types)
export type ZoneNetworkType = 'aws-vpc' | 'gcp-vpc' | 'azure-vnet' | 'generic';

export const ZONE_NETWORK_TYPE_LABELS: Record<ZoneNetworkType, string> = {
  'generic': 'Generic Network',
  'aws-vpc': 'AWS VPC',
  'gcp-vpc': 'Google Cloud VPC',
  'azure-vnet': 'Azure VNet',
};

// Data sensitivity levels for risk scoring
export type DataSensitivity = 'public' | 'internal' | 'confidential' | 'restricted';

export const DATA_SENSITIVITY_LABELS: Record<DataSensitivity, string> = {
  'public': 'Public',
  'internal': 'Internal',
  'confidential': 'Confidential',
  'restricted': 'Restricted',
};

export const DATA_SENSITIVITY_VALUES: Record<DataSensitivity, number> = {
  'public': 1,
  'internal': 2,
  'confidential': 3,
  'restricted': 4,
};

// Risk levels (calculated from severity × sensitivity)
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  'low': 'Low',
  'medium': 'Medium',
  'high': 'High',
  'critical': 'Critical',
};

// Diagram node data - index signature required for React Flow compatibility
export interface TechNodeData extends Record<string, unknown> {
  technology: Technology;
  label: string;
  sensitivity: DataSensitivity;
  customName?: string;
  threatsDisabled?: boolean;  // When true, threats for this node are not shown or calculated
}

// Zone node data for network trust zones
export interface ZoneNodeData extends Record<string, unknown> {
  zoneType: NetworkZone;
  networkType?: ZoneNetworkType;  // Default: 'generic'
  label: string;
  customName?: string;
  // Callback to check and assign nodes when zone changes (move/resize)
  onZoneChange?: (zoneId: string) => void;
  // Risk reduction settings (only applies to private zones)
  riskReductionEnabled?: boolean;  // Default: true for private, false for public
  riskReductionPercent?: number;   // Default: 20 (1-100 range)
}

// Mitigation reasons for connection threats
export type ConnectionMitigation = 'encrypted' | 'internal';

export const CONNECTION_MITIGATION_LABELS: Record<ConnectionMitigation, string> = {
  'encrypted': 'TLS Encrypted',
  'internal': 'Internal Network',
};

// Active threat (threat associated with a specific node or connection)
export interface ActiveThreat {
  threat: Threat;
  sourceNodeId: string;
  sourceTechName: string;
  sourceProvider?: CloudProvider;
  // Technology-specific context/examples for this threat
  context?: string;
  // Technology-specific mitigations (replaces generic controls when present)
  techMitigations?: string[];
  isConnectionThreat?: boolean;
  connectionInfo?: {
    edgeId: string;
    sourceNodeName: string;
    targetNodeName: string;
    label?: string;
    sourceProvider?: CloudProvider;
    targetProvider?: CloudProvider;
  };
  isZoneThreat?: boolean;
  zoneInfo?: {
    boundaryId: string;
    zoneName: string;
    networkType?: ZoneNetworkType;
    riskReductionPercent?: number;
  };
  sensitivity: DataSensitivity;
  riskScore: number;
  riskLevel: RiskLevel;
  isEscalated?: boolean;
  effectiveSensitivity?: DataSensitivity;
  // Severity override: set when a user has overridden the default severity for this threat
  overriddenSeverity?: ThreatSeverity;
  // The technology ID that sourced this threat (for component threats, used to build override keys)
  sourceTechnologyId?: string;
  // For connection threats: indicates the threat is mitigated/reduced
  mitigatedBy?: ConnectionMitigation;
  // For network zone risk adjustment
  zoneMultiplier?: number;
  // For pathway mitigations: indicates upstream protection
  pathwayMitigatedBy?: {
    mitigationType: PathwayMitigationType;
    mitigatingTechId: string;
    mitigatingTechName: string;
    mode: 'remove' | 'reduce';
    reductionPercent?: number;
  };
}

// Model state for export/import
export interface ThreatModel {
  version: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  nodes: ExportedNode[];
  edges: ExportedEdge[];
  zones?: ExportedZone[];
  pathwayMitigationSettings?: PathwayMitigationSettings;
  customTechnologies?: Technology[];
  severityOverrides?: Record<string, ThreatSeverity>;
  implementedControls?: Record<string, true>;
}

export interface ExportedNode {
  id: string;
  technologyId: string;
  position: { x: number; y: number };
  sensitivity?: DataSensitivity;
  customName?: string;
  zoneId?: string;
  threatsDisabled?: boolean;
}

export interface ExportedEdge {
  id: string;
  source: string;
  target: string;
  sourceHandle?: string;
  targetHandle?: string;
  label?: string;
}

export interface ExportedZone {
  id: string;
  zoneType: NetworkZone;
  networkType?: ZoneNetworkType;
  position: { x: number; y: number };
  dimensions: { width: number; height: number };
  customName?: string;
  riskReductionEnabled?: boolean;
  riskReductionPercent?: number;
}

// Clipboard types for copy/paste operations
export interface ClipboardNode {
  originalId: string;
  technologyId: string;
  relativePosition: { x: number; y: number };
  sensitivity: DataSensitivity;
  customName?: string;
  customTechnology?: Technology;
}

export interface ClipboardEdge {
  originalSourceId: string;
  originalTargetId: string;
  label?: string;
}

export interface ClipboardZone {
  originalId: string;
  zoneType: NetworkZone;
  networkType?: ZoneNetworkType;
  relativePosition: { x: number; y: number };
  dimensions: { width: number; height: number };
  customName?: string;
  riskReductionEnabled?: boolean;
  riskReductionPercent?: number;
  // Track which nodes were inside this zone (by their original IDs)
  containedNodeIds: string[];
}

export interface ClipboardState {
  nodes: ClipboardNode[];
  edges: ClipboardEdge[];
  zones: ClipboardZone[];
  copyOrigin: { x: number; y: number };
}

// How the app applies a pathway mitigation — user-tunable.
export interface PathwayMitigationConfig {
  enabled: boolean;
  mode: 'remove' | 'reduce';
  reductionPercent: number;  // 0-100
}

export interface PathwayMitigationSettings {
  enabled: boolean;  // Master toggle
  mitigations: Record<PathwayMitigationType, PathwayMitigationConfig>;
}

// Starting position for each mitigation's risk adjustment.
const FALLBACK_MITIGATION_DEFAULT: Omit<PathwayMitigationConfig, 'enabled'> = {
  mode: 'reduce',
  reductionPercent: 50,
};

const MITIGATION_DEFAULTS: Partial<
  Record<PathwayMitigationType, Omit<PathwayMitigationConfig, 'enabled'>>
> = {
  'ddos-protection': { mode: 'reduce', reductionPercent: 50 },
  'waf-protection': { mode: 'remove', reductionPercent: 50 },
  'rate-limiting': { mode: 'reduce', reductionPercent: 30 },
  'network-firewall': { mode: 'reduce', reductionPercent: 40 },
};

export const DEFAULT_PATHWAY_MITIGATION_SETTINGS: PathwayMitigationSettings = {
  enabled: false,
  mitigations: Object.fromEntries(
    PATHWAY_MITIGATION_DEFINITIONS.map(m => [
      m.id,
      { enabled: false, ...(MITIGATION_DEFAULTS[m.id] ?? FALLBACK_MITIGATION_DEFAULT) },
    ])
  ) as Record<PathwayMitigationType, PathwayMitigationConfig>,
};
