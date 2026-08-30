import type { ThreatSeverity, DataSensitivity, RiskLevel, NetworkZone } from '../data/schema';
import { THREAT_SEVERITY_VALUES, DATA_SENSITIVITY_VALUES } from '../data/schema';

// Boundary data for risk calculation (subset of BoundaryNodeData)
export interface BoundaryRiskData {
  zoneType: NetworkZone;
  riskReductionEnabled?: boolean;
  riskReductionPercent?: number;
}

/**
 * Calculate risk score from threat severity and data sensitivity
 * Risk Score = Severity (1-4) × Sensitivity (1-4) = Range 1-16
 */
export function calculateRiskScore(
  severity: ThreatSeverity,
  sensitivity: DataSensitivity
): number {
  return THREAT_SEVERITY_VALUES[severity] * DATA_SENSITIVITY_VALUES[sensitivity];
}

/**
 * Convert numeric risk score to risk level
 * - Critical: 12-16
 * - High: 8-11
 * - Medium: 4-7
 * - Low: 1-3
 */
export function getRiskLevel(score: number): RiskLevel {
  if (score >= 12) return 'critical';
  if (score >= 8) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Get the higher of two sensitivity levels
 * Used for connection threats to inherit max sensitivity from connected nodes
 */
export function getHigherSensitivity(
  a: DataSensitivity,
  b: DataSensitivity
): DataSensitivity {
  return DATA_SENSITIVITY_VALUES[a] >= DATA_SENSITIVITY_VALUES[b] ? a : b;
}

/**
 * Get the maximum sensitivity of all directly connected downstream nodes
 * Used for pathway threats to consider downstream system sensitivity
 * @param nodeId - The source node ID
 * @param edges - All edges in the diagram
 * @param nodesSensitivityMap - Map of node IDs to their sensitivity levels
 * @returns The highest sensitivity of downstream nodes, or null if no downstream connections
 */
export function getMaxDownstreamSensitivity(
  nodeId: string,
  edges: { source: string; target: string }[],
  nodesSensitivityMap: Map<string, DataSensitivity>
): DataSensitivity | null {
  // Find all edges where this node is the source (downstream connections)
  const downstreamEdges = edges.filter(e => e.source === nodeId);

  if (downstreamEdges.length === 0) {
    return null;
  }

  let maxSensitivity: DataSensitivity | null = null;

  for (const edge of downstreamEdges) {
    const targetSensitivity = nodesSensitivityMap.get(edge.target);
    if (targetSensitivity) {
      if (maxSensitivity === null) {
        maxSensitivity = targetSensitivity;
      } else {
        maxSensitivity = getHigherSensitivity(maxSensitivity, targetSensitivity);
      }
    }
  }

  return maxSensitivity;
}

/**
 * Apply network boundary risk multiplier to a base score
 * Private boundaries reduce risk based on their custom reduction percentage
 * @param baseScore - The calculated risk score before boundary adjustment
 * @param boundaryData - The boundary data including type and custom risk settings
 * @returns The adjusted risk score rounded to nearest integer
 */
export function applyBoundaryMultiplier(
  baseScore: number,
  boundaryData: BoundaryRiskData | undefined
): number {
  const multiplier = getBoundaryMultiplier(boundaryData);
  return Math.round(baseScore * multiplier);
}

/**
 * Get the boundary risk multiplier from boundary data
 * Uses custom risk reduction settings if available
 * @param boundaryData - The boundary data including type and custom risk settings
 * @returns The multiplier value (0.0-1.0)
 */
export function getBoundaryMultiplier(
  boundaryData: BoundaryRiskData | undefined
): number {
  if (!boundaryData) return 1.0;
  if (boundaryData.zoneType === 'public') return 1.0;
  if (boundaryData.riskReductionEnabled === false) return 1.0;

  // Use custom reduction percentage if set, otherwise default to 20%
  const reductionPercent = boundaryData.riskReductionPercent ?? 20;
  return (100 - reductionPercent) / 100;
}

/**
 * Get the reduction percentage for display purposes
 * @param boundaryData - The boundary data
 * @returns The reduction percentage (0-100), or null if no reduction applies
 */
export function getBoundaryReductionPercent(
  boundaryData: BoundaryRiskData | undefined
): number | null {
  if (!boundaryData) return null;
  if (boundaryData.zoneType === 'public') return null;
  if (boundaryData.riskReductionEnabled === false) return null;
  return boundaryData.riskReductionPercent ?? 20;
}
