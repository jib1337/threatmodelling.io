import type { PathwayMitigationType, PathwayMitigationSettings } from '../data/schema';
import { getTechnologyMitigations, canMitigateThreat } from '../data/mitigationMappings';
import { getTechnologyById } from '../data';

/**
 * Information about an upstream node that provides mitigation.
 */
export interface UpstreamMitigation {
  mitigationType: PathwayMitigationType;
  techId: string;
  techName: string;
}

/**
 * Result of checking pathway mitigation for a threat.
 */
export interface PathwayMitigationResult {
  isMitigated: boolean;
  mitigationType?: PathwayMitigationType;
  mitigatingTechId?: string;
  mitigatingTechName?: string;
  mode?: 'remove' | 'reduce';
  reductionPercent?: number;
}

interface DiagramNode {
  id: string;
  technologyId: string;
}

interface DiagramEdge {
  id: string;
  source: string;
  target: string;
}

/**
 * Find all nodes that are upstream of a given node by traversing edges backwards.
 * Uses BFS to find all nodes that have a path leading to the target node.
 *
 * @param nodeId The target node to find upstream nodes for
 * @param edges All edges in the diagram
 * @returns Array of node IDs that are upstream of the target
 */
export function findUpstreamNodes(
  nodeId: string,
  edges: DiagramEdge[]
): string[] {
  const upstreamNodes: string[] = [];
  const visited = new Set<string>();
  const queue: string[] = [nodeId];

  // Build a map of target -> sources for quick lookup
  const targetToSources = new Map<string, string[]>();
  for (const edge of edges) {
    const sources = targetToSources.get(edge.target) || [];
    sources.push(edge.source);
    targetToSources.set(edge.target, sources);
  }

  visited.add(nodeId);

  while (queue.length > 0) {
    const current = queue.shift()!;
    const sources = targetToSources.get(current) || [];

    for (const source of sources) {
      if (!visited.has(source)) {
        visited.add(source);
        upstreamNodes.push(source);
        queue.push(source);
      }
    }
  }

  return upstreamNodes;
}

/**
 * Get all mitigation capabilities from upstream nodes.
 *
 * @param nodeId The target node to check
 * @param edges All edges in the diagram
 * @param nodeToTechId Map of node IDs to technology IDs
 * @returns Array of upstream mitigations with their source information
 */
export function getUpstreamMitigations(
  nodeId: string,
  edges: DiagramEdge[],
  nodeToTechId: Map<string, string>
): UpstreamMitigation[] {
  const upstreamNodeIds = findUpstreamNodes(nodeId, edges);
  const mitigations: UpstreamMitigation[] = [];

  for (const upstreamNodeId of upstreamNodeIds) {
    const techId = nodeToTechId.get(upstreamNodeId);
    if (!techId) continue;

    const techMitigations = getTechnologyMitigations(techId);
    if (techMitigations.length === 0) continue;

    const technology = getTechnologyById(techId);
    const techName = technology?.name || techId;

    for (const mitigationType of techMitigations) {
      mitigations.push({
        mitigationType,
        techId,
        techName,
      });
    }
  }

  return mitigations;
}

/**
 * Check if a threat should be mitigated based on upstream protections and settings.
 *
 * @param threatId The threat ID to check
 * @param upstreamMitigations Available upstream mitigations
 * @param settings Pathway mitigation settings
 * @returns Mitigation result including mode and reduction if applicable
 */
export function checkPathwayMitigation(
  threatId: string,
  upstreamMitigations: UpstreamMitigation[],
  settings: PathwayMitigationSettings
): PathwayMitigationResult {
  // If pathway mitigations are globally disabled, no mitigation
  if (!settings.enabled) {
    return { isMitigated: false };
  }

  // Check each upstream mitigation to see if it applies to this threat
  for (const mitigation of upstreamMitigations) {
    const config = settings.mitigations[mitigation.mitigationType];

    // Skip if this mitigation type is disabled
    if (!config?.enabled) continue;

    // Check if this mitigation type can mitigate the threat
    if (canMitigateThreat(threatId, mitigation.mitigationType)) {
      return {
        isMitigated: true,
        mitigationType: mitigation.mitigationType,
        mitigatingTechId: mitigation.techId,
        mitigatingTechName: mitigation.techName,
        mode: config.mode,
        reductionPercent: config.mode === 'reduce' ? config.reductionPercent : undefined,
      };
    }
  }

  return { isMitigated: false };
}

/**
 * Apply pathway mitigation to a risk score.
 *
 * @param baseRiskScore The original risk score
 * @param reductionPercent The percentage to reduce (0-100)
 * @returns The reduced risk score (floored to nearest integer, minimum 1)
 */
export function applyPathwayReduction(
  baseRiskScore: number,
  reductionPercent: number
): number {
  const reduction = baseRiskScore * (reductionPercent / 100);
  const reducedScore = Math.floor(baseRiskScore - reduction);
  // Minimum risk score of 1 (never fully eliminated by reduction)
  return Math.max(1, reducedScore);
}

/**
 * Pre-compute upstream mitigations for all nodes in the diagram.
 * This is more efficient than computing per-node during threat resolution.
 *
 * @param nodes All nodes in the diagram
 * @param edges All edges in the diagram
 * @returns Map of nodeId -> array of upstream mitigations
 */
export function precomputeUpstreamMitigations(
  nodes: DiagramNode[],
  edges: DiagramEdge[]
): Map<string, UpstreamMitigation[]> {
  const result = new Map<string, UpstreamMitigation[]>();

  // Build node to tech ID map
  const nodeToTechId = new Map<string, string>();
  for (const node of nodes) {
    nodeToTechId.set(node.id, node.technologyId);
  }

  // Compute upstream mitigations for each node
  for (const node of nodes) {
    const mitigations = getUpstreamMitigations(node.id, edges, nodeToTechId);
    result.set(node.id, mitigations);
  }

  return result;
}
