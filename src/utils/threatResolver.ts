import type { Threat, ActiveThreat, DataSensitivity, Technology, ConnectionMitigation, NetworkZone, ZoneNetworkType, PathwayMitigationSettings, ThreatSeverity } from '../data/schema';
import { NETWORK_ZONE_LABELS, ZONE_NETWORK_TYPE_LABELS, DEFAULT_PATHWAY_MITIGATION_SETTINGS } from '../data/schema';
import { getThreatsForTechnology, getTechnologyById, getConnectionThreats, getZoneThreats } from '../data';
import { calculateRiskScore, getRiskLevel, getHigherSensitivity, getMaxDownstreamSensitivity, applyBoundaryMultiplier, getBoundaryMultiplier, type BoundaryRiskData } from './riskCalculator';
import { precomputeUpstreamMitigations, checkPathwayMitigation, applyPathwayReduction, type UpstreamMitigation } from './pathwayMitigations';

export interface DiagramNode {
  id: string;
  parentId?: string;
  data: {
    technologyId: string;
    sensitivity: DataSensitivity;
    customName?: string;
    threatsDisabled?: boolean;
  };
}

export interface DiagramEdge {
  id: string;
  source: string;
  target: string;
  data?: {
    label?: string;
  };
}

export interface DiagramBoundary {
  id: string;
  zoneType: NetworkZone;
  networkType?: ZoneNetworkType;
  customName?: string;
  riskReductionEnabled?: boolean;
  riskReductionPercent?: number;
}

// Connection threats that are mitigated by TLS encryption
const ENCRYPTION_MITIGATED_THREATS = ['connection-mitm', 'connection-data-exposure'];

// Check if a connection is protected by encryption (either endpoint enforces TLS)
function isConnectionEncrypted(
  sourceTech: Technology | undefined,
  targetTech: Technology | undefined
): boolean {
  return !!(
    sourceTech?.connectionSecurity?.enforcesEncryption ||
    targetTech?.connectionSecurity?.enforcesEncryption
  );
}

// Determine if a threat should be mitigated and by what
function getConnectionMitigation(
  threat: Threat,
  sourceTech: Technology | undefined,
  targetTech: Technology | undefined
): ConnectionMitigation | undefined {
  // Check for encryption mitigation
  if (ENCRYPTION_MITIGATED_THREATS.includes(threat.id)) {
    if (isConnectionEncrypted(sourceTech, targetTech)) {
      return 'encrypted';
    }
  }

  // Future: Check for internal network mitigation
  // if (sourceTech?.connectionSecurity?.internalOnly && targetTech?.connectionSecurity?.internalOnly) {
  //   return 'internal';
  // }

  return undefined;
}

// Resolve all active threats based on nodes and edges in the diagram
export function resolveActiveThreats(
  nodes: DiagramNode[],
  edges: DiagramEdge[] = [],
  boundaries: DiagramBoundary[] = [],
  pathwayMitigationSettings: PathwayMitigationSettings = DEFAULT_PATHWAY_MITIGATION_SETTINGS,
  severityOverrides: Record<string, ThreatSeverity> = {}
): ActiveThreat[] {
  const activeThreats: ActiveThreat[] = [];
  const seenThreats = new Map<string, ActiveThreat>();

  // Build boundary lookup map with full risk data
  const boundaryDataMap = new Map<string, BoundaryRiskData>();
  boundaries.forEach(b => boundaryDataMap.set(b.id, {
    zoneType: b.zoneType,
    riskReductionEnabled: b.riskReductionEnabled,
    riskReductionPercent: b.riskReductionPercent,
  }));

  // Pre-compute upstream mitigations for pathway mitigation feature
  const nodeUpstreamMitigations = pathwayMitigationSettings.enabled
    ? precomputeUpstreamMitigations(
        nodes.map(n => ({ id: n.id, technologyId: n.data.technologyId })),
        edges.map(e => ({ id: e.id, source: e.source, target: e.target }))
      )
    : new Map<string, UpstreamMitigation[]>();

  // Build maps for quick lookup - cache technology lookups to avoid redundant calls
  const nodeToTechName = new Map<string, string>();
  const nodeToSensitivity = new Map<string, DataSensitivity>();
  const nodeToTechnology = new Map<string, ReturnType<typeof getTechnologyById>>();
  const nodeToBoundaryData = new Map<string, BoundaryRiskData | undefined>();
  const nodesWithThreatsDisabled = new Set<string>();

  nodes.forEach(node => {
    const technology = getTechnologyById(node.data.technologyId);
    if (technology) {
      nodeToTechnology.set(node.id, technology);
      nodeToTechName.set(node.id, node.data.customName || technology.name);
      nodeToSensitivity.set(node.id, node.data.sensitivity);
      // Map node to its boundary data (if in a boundary)
      const boundaryData = node.parentId ? boundaryDataMap.get(node.parentId) : undefined;
      nodeToBoundaryData.set(node.id, boundaryData);
      // Track nodes with threats disabled
      if (node.data.threatsDisabled) {
        nodesWithThreatsDisabled.add(node.id);
      }
    }
  });

  // Add component-based threats
  nodes.forEach(node => {
    const technology = nodeToTechnology.get(node.id);
    if (!technology) return;

    // Skip nodes with threats disabled
    if (node.data.threatsDisabled) return;

    const threats = getThreatsForTechnology(node.data.technologyId);
    const nodeSensitivity = node.data.sensitivity;
    const boundaryData = nodeToBoundaryData.get(node.id);

    // Get max downstream sensitivity for pathway threat escalation
    const maxDownstream = getMaxDownstreamSensitivity(node.id, edges, nodeToSensitivity);

    // Get upstream mitigations for this node
    const upstreamMitigations = nodeUpstreamMitigations.get(node.id) || [];

    threats.forEach(threat => {
      const key = `${threat.id}-${node.id}`;
      if (!seenThreats.has(key)) {
        // Check for pathway mitigation
        const pathwayMitigation = checkPathwayMitigation(
          threat.id,
          upstreamMitigations,
          pathwayMitigationSettings
        );

        // If mode is 'remove', skip this threat entirely
        if (pathwayMitigation.isMitigated && pathwayMitigation.mode === 'remove') {
          return; // Skip to next threat
        }

        // For pathway threats, consider downstream sensitivity
        let effectiveSensitivity = nodeSensitivity;
        let isEscalated = false;

        if (threat.isPathwayThreat && maxDownstream) {
          effectiveSensitivity = getHigherSensitivity(nodeSensitivity, maxDownstream);
          isEscalated = effectiveSensitivity !== nodeSensitivity;
        }

        // Check for severity override (component threat: technologyId::threatId)
        const overrideKey = `${technology.id}::${threat.id}`;
        const overriddenSeverity = severityOverrides[overrideKey];
        const effectiveSeverity = overriddenSeverity ?? threat.severity;

        let baseRiskScore = calculateRiskScore(effectiveSeverity, effectiveSensitivity);
        const boundaryMultiplier = getBoundaryMultiplier(boundaryData);
        let riskScore = applyBoundaryMultiplier(baseRiskScore, boundaryData);

        // Apply pathway reduction if applicable
        if (pathwayMitigation.isMitigated && pathwayMitigation.mode === 'reduce' && pathwayMitigation.reductionPercent) {
          riskScore = applyPathwayReduction(riskScore, pathwayMitigation.reductionPercent);
        }

        // Get technology-specific context for this threat if available
        const threatContext = technology.threatContext?.[threat.id];
        const techMitigations = technology.threatMitigations?.[threat.id];

        const activeThreat: ActiveThreat = {
          threat,
          sourceNodeId: node.id,
          sourceTechName: node.data.customName || technology.name,
          sourceProvider: technology.provider,
          sourceTechnologyId: technology.id,
          ...(threatContext && { context: threatContext }),
          ...(techMitigations && { techMitigations }),
          ...(overriddenSeverity && { overriddenSeverity }),
          sensitivity: nodeSensitivity,
          riskScore,
          riskLevel: getRiskLevel(riskScore),
          ...(isEscalated && { isEscalated, effectiveSensitivity }),
          ...(boundaryMultiplier !== 1.0 && { zoneMultiplier: boundaryMultiplier }),
          ...(pathwayMitigation.isMitigated && pathwayMitigation.mode === 'reduce' && {
            pathwayMitigatedBy: {
              mitigationType: pathwayMitigation.mitigationType!,
              mitigatingTechId: pathwayMitigation.mitigatingTechId!,
              mitigatingTechName: pathwayMitigation.mitigatingTechName!,
              mode: pathwayMitigation.mode,
              reductionPercent: pathwayMitigation.reductionPercent,
            },
          }),
        };
        seenThreats.set(key, activeThreat);
        activeThreats.push(activeThreat);
      }
    });
  });

  // Add connection-based threats for each edge
  if (edges.length > 0) {
    const connectionThreats = getConnectionThreats();

    edges.forEach(edge => {
      // Skip connections involving nodes with threats disabled
      if (nodesWithThreatsDisabled.has(edge.source) || nodesWithThreatsDisabled.has(edge.target)) {
        return;
      }

      const sourceNodeName = nodeToTechName.get(edge.source) || 'Unknown';
      const targetNodeName = nodeToTechName.get(edge.target) || 'Unknown';
      const sourceSensitivity = nodeToSensitivity.get(edge.source) || 'internal';
      const targetSensitivity = nodeToSensitivity.get(edge.target) || 'internal';
      const connectionSensitivity = getHigherSensitivity(sourceSensitivity, targetSensitivity);
      const label = edge.data?.label;

      // Get technologies for connection security check
      const sourceTech = nodeToTechnology.get(edge.source);
      const targetTech = nodeToTechnology.get(edge.target);

      // For connections, apply boundary multiplier only if BOTH endpoints are in private boundaries
      // Use the lower risk reduction if both are in private boundaries with different settings
      const sourceBoundaryData = nodeToBoundaryData.get(edge.source);
      const targetBoundaryData = nodeToBoundaryData.get(edge.target);
      let connectionBoundaryData: BoundaryRiskData | undefined;
      if (sourceBoundaryData?.zoneType === 'private' && targetBoundaryData?.zoneType === 'private') {
        // Use the lower risk reduction percentage between the two (more conservative)
        const sourceReduction = sourceBoundaryData.riskReductionEnabled !== false
          ? (sourceBoundaryData.riskReductionPercent ?? 20) : 0;
        const targetReduction = targetBoundaryData.riskReductionEnabled !== false
          ? (targetBoundaryData.riskReductionPercent ?? 20) : 0;
        const effectiveReduction = Math.min(sourceReduction, targetReduction);
        if (effectiveReduction > 0) {
          connectionBoundaryData = {
            zoneType: 'private',
            riskReductionEnabled: true,
            riskReductionPercent: effectiveReduction,
          };
        }
      }

      // For connection threats, use the source node's upstream mitigations
      // (the source node is the one sending data through the connection)
      const sourceUpstreamMitigations = nodeUpstreamMitigations.get(edge.source) || [];

      connectionThreats.forEach(threat => {
        const key = `${threat.id}-${edge.id}`;
        if (!seenThreats.has(key)) {
          // Check for pathway mitigation on connection threats
          const pathwayMitigation = checkPathwayMitigation(
            threat.id,
            sourceUpstreamMitigations,
            pathwayMitigationSettings
          );

          // If mode is 'remove', skip this threat entirely
          if (pathwayMitigation.isMitigated && pathwayMitigation.mode === 'remove') {
            return; // Skip to next threat
          }

          // Check if this threat is mitigated by connection security
          const mitigatedBy = getConnectionMitigation(threat, sourceTech, targetTech);

          // Check for severity override (connection threat: connection::threatId)
          const connOverrideKey = `connection::${threat.id}`;
          const connOverriddenSeverity = severityOverrides[connOverrideKey];
          const connEffectiveSeverity = connOverriddenSeverity ?? threat.severity;

          const baseRiskScore = calculateRiskScore(connEffectiveSeverity, connectionSensitivity);
          const boundaryMultiplier = getBoundaryMultiplier(connectionBoundaryData);
          let riskScore = applyBoundaryMultiplier(baseRiskScore, connectionBoundaryData);

          // Apply pathway reduction if applicable
          if (pathwayMitigation.isMitigated && pathwayMitigation.mode === 'reduce' && pathwayMitigation.reductionPercent) {
            riskScore = applyPathwayReduction(riskScore, pathwayMitigation.reductionPercent);
          }

          const activeThreat: ActiveThreat = {
            threat,
            sourceNodeId: edge.id,
            sourceTechName: `${sourceNodeName} → ${targetNodeName}`,
            isConnectionThreat: true,
            connectionInfo: {
              edgeId: edge.id,
              sourceNodeName,
              targetNodeName,
              label,
              sourceProvider: sourceTech?.provider,
              targetProvider: targetTech?.provider,
            },
            ...(connOverriddenSeverity && { overriddenSeverity: connOverriddenSeverity }),
            sensitivity: connectionSensitivity,
            riskScore,
            riskLevel: getRiskLevel(riskScore),
            ...(mitigatedBy && { mitigatedBy }),
            ...(boundaryMultiplier !== 1.0 && { zoneMultiplier: boundaryMultiplier }),
            ...(pathwayMitigation.isMitigated && pathwayMitigation.mode === 'reduce' && {
              pathwayMitigatedBy: {
                mitigationType: pathwayMitigation.mitigationType!,
                mitigatingTechId: pathwayMitigation.mitigatingTechId!,
                mitigatingTechName: pathwayMitigation.mitigatingTechName!,
                mode: pathwayMitigation.mode,
                reductionPercent: pathwayMitigation.reductionPercent,
              },
            }),
          };
          seenThreats.set(key, activeThreat);
          activeThreats.push(activeThreat);
        }
      });
    });
  }

  // Add zone-based threats for private boundaries
  const privateZones = boundaries.filter(b => b.zoneType === 'private');
  if (privateZones.length > 0) {
    const zoneThreats = getZoneThreats();

    privateZones.forEach(boundary => {
      const boundaryData: BoundaryRiskData = {
        zoneType: boundary.zoneType,
        riskReductionEnabled: boundary.riskReductionEnabled,
        riskReductionPercent: boundary.riskReductionPercent,
      };

      // Zone name for display (custom name or default based on network type)
      const zoneName = getZoneName(boundary);

      zoneThreats.forEach(threat => {
        const key = `${threat.id}-zone-${boundary.id}`;
        if (!seenThreats.has(key)) {
          // Use 'internal' as base sensitivity for zone threats
          const baseSensitivity: DataSensitivity = 'internal';

          // Check for severity override (zone threat: zone::threatId)
          const zoneOverrideKey = `zone::${threat.id}`;
          const zoneOverriddenSeverity = severityOverrides[zoneOverrideKey];
          const zoneEffectiveSeverity = zoneOverriddenSeverity ?? threat.severity;

          const baseRiskScore = calculateRiskScore(zoneEffectiveSeverity, baseSensitivity);
          const boundaryMultiplier = getBoundaryMultiplier(boundaryData);
          const riskScore = applyBoundaryMultiplier(baseRiskScore, boundaryData);

          const activeThreat: ActiveThreat = {
            threat,
            sourceNodeId: boundary.id,
            sourceTechName: zoneName,
            isZoneThreat: true,
            zoneInfo: {
              boundaryId: boundary.id,
              zoneName,
              networkType: boundary.networkType,
              riskReductionPercent: boundaryData.riskReductionEnabled !== false
                ? boundaryData.riskReductionPercent
                : undefined,
            },
            ...(zoneOverriddenSeverity && { overriddenSeverity: zoneOverriddenSeverity }),
            sensitivity: baseSensitivity,
            riskScore,
            riskLevel: getRiskLevel(riskScore),
            ...(boundaryMultiplier !== 1.0 && { zoneMultiplier: boundaryMultiplier }),
          };
          seenThreats.set(key, activeThreat);
          activeThreats.push(activeThreat);
        }
      });
    });
  }

  // Filter out threats with zero risk score
  return activeThreats.filter(threat => threat.riskScore > 0);
}

// Helper to get display name for a zone
function getZoneName(boundary: DiagramBoundary): string {
  if (boundary.customName) {
    return boundary.customName;
  }
  if (boundary.networkType && boundary.networkType !== 'generic') {
    return ZONE_NETWORK_TYPE_LABELS[boundary.networkType];
  }
  return NETWORK_ZONE_LABELS[boundary.zoneType];
}

// Group active threats by source (technology or connection)
export function groupThreatsByTechnology(
  activeThreats: ActiveThreat[]
): Map<string, { techName: string; threats: Threat[]; isConnection?: boolean }> {
  const result = new Map<string, { techName: string; threats: Threat[]; isConnection?: boolean }>();

  activeThreats.forEach(({ threat, sourceNodeId, sourceTechName, isConnectionThreat }) => {
    const existing = result.get(sourceNodeId);
    if (existing) {
      // Avoid duplicate threats for same node
      if (!existing.threats.some(t => t.id === threat.id)) {
        existing.threats.push(threat);
      }
    } else {
      result.set(sourceNodeId, {
        techName: sourceTechName,
        threats: [threat],
        isConnection: isConnectionThreat,
      });
    }
  });

  return result;
}

// Get unique threat count
export function getUniqueThreatCount(activeThreats: ActiveThreat[]): number {
  const uniqueIds = new Set(activeThreats.map(at => at.threat.id));
  return uniqueIds.size;
}
