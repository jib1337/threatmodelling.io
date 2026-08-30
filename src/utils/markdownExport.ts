import type { ActiveThreat, TechNodeData, RiskLevel, ZoneNetworkType } from '../data/schema';
import { STRIDE_LABELS, RISK_LEVEL_LABELS, DATA_SENSITIVITY_LABELS, PROVIDER_LABELS, ZONE_NETWORK_TYPE_LABELS } from '../data/schema';
import type { Node, Edge } from '@xyflow/react';
import { buildControlKey } from './controlFingerprint';

// Unicode ballot boxes render cleanly inside Markdown table cells where GFM
// task-list syntax is inert.
function renderControlLine(
  description: string,
  implemented: boolean,
  escape: (s: string) => string,
): string {
  const checkbox = implemented ? '☑' : '☐';
  const body = implemented ? `~~${escape(description)}~~` : escape(description);
  return `${checkbox} ${body}`;
}

interface ComponentSummary {
  name: string;
  provider: string;
  sensitivity: string;
  threatCount: number;
  maxRiskScore: number;
  maxRiskLevel: RiskLevel;
  threats: ActiveThreat[];
}

// Unicode emoji for risk levels (renders consistently across platforms)
const RISK_EMOJI: Record<RiskLevel, string> = {
  critical: '\u{1F534}', // Red circle
  high: '\u{1F7E0}',     // Orange circle
  medium: '\u{1F7E1}',   // Yellow circle
  low: '\u{1F535}',      // Blue circle
};

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function escapeMarkdown(text: string): string {
  return text.replace(/([|])/g, '\\$1');
}

function groupThreatsByComponent(
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[]
): Map<string, ComponentSummary> {
  const componentMap = new Map<string, ComponentSummary>();

  // Initialize components from nodes
  nodes.forEach(node => {
    const displayName = node.data.customName || node.data.technology.name;
    componentMap.set(node.id, {
      name: displayName,
      provider: PROVIDER_LABELS[node.data.technology.provider],
      sensitivity: DATA_SENSITIVITY_LABELS[node.data.sensitivity],
      threatCount: 0,
      maxRiskScore: 0,
      maxRiskLevel: 'low',
      threats: [],
    });
  });

  // Group threats by source component (skip zone threats - they're handled separately)
  threats.forEach(threat => {
    // Skip zone threats - they don't belong to components
    if (threat.isZoneThreat) {
      return;
    }

    let componentId = threat.sourceNodeId;

    // For connection threats, find the source node from the edge
    if (threat.isConnectionThreat && threat.connectionInfo) {
      const edge = edges.find(e => e.id === threat.connectionInfo!.edgeId);
      if (edge) {
        componentId = edge.source;
      }
    }

    const component = componentMap.get(componentId);
    if (component) {
      component.threats.push(threat);
      component.threatCount++;
      if (threat.riskScore > component.maxRiskScore) {
        component.maxRiskScore = threat.riskScore;
        component.maxRiskLevel = threat.riskLevel;
      }
    }
  });

  return componentMap;
}

function getRiskDistribution(threats: ActiveThreat[]): Record<RiskLevel, number> {
  const distribution: Record<RiskLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  threats.forEach(threat => {
    distribution[threat.riskLevel]++;
  });

  return distribution;
}

function filterMitigatedThreats(threats: ActiveThreat[]): ActiveThreat[] {
  return threats.filter(t => !t.mitigatedBy);
}

function generateHeader(modelName: string): string {
  return `# Threat Model Report: ${modelName}

`;
}

function generateOverview(
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[]
): string {
  const uniqueThreats = new Set(threats.map(t => t.threat.id)).size;

  return `## Overview

| Metric | Count |
|--------|-------|
| Components | ${nodes.length} |
| Data Flows | ${edges.length} |
| Total Threats | ${threats.length} |
| Unique Threats | ${uniqueThreats} |

`;
}

function generateRiskDistribution(threats: ActiveThreat[]): string {
  const distribution = getRiskDistribution(threats);

  return `## Risk Distribution

| Level | Count |
|-------|-------|
| ${RISK_EMOJI.critical} Critical | ${distribution.critical} |
| ${RISK_EMOJI.high} High | ${distribution.high} |
| ${RISK_EMOJI.medium} Medium | ${distribution.medium} |
| ${RISK_EMOJI.low} Low | ${distribution.low} |

`;
}

function generateTopThreats(threats: ActiveThreat[]): string {
  const sortedThreats = [...threats]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);

  let md = `## Top Threats by Risk Score

| Threat | Component | Score | Level |
|--------|-----------|-------|-------|
`;

  sortedThreats.forEach(t => {
    const emoji = RISK_EMOJI[t.riskLevel];
    md += `| ${escapeMarkdown(t.threat.name)} | ${escapeMarkdown(t.sourceTechName)} | ${t.riskScore} | ${emoji} ${RISK_LEVEL_LABELS[t.riskLevel]} |\n`;
  });

  return md + '\n';
}

function generateComponentsSummary(
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[]
): string {
  const componentMap = groupThreatsByComponent(nodes, edges, threats);
  const componentData = Array.from(componentMap.values())
    .filter(c => c.threatCount > 0)
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore);

  let md = `## Components Summary

| Component | Provider | Sensitivity | Threats | Max Risk |
|-----------|----------|-------------|---------|----------|
`;

  componentData.forEach(c => {
    const emoji = RISK_EMOJI[c.maxRiskLevel];
    md += `| ${escapeMarkdown(c.name)} | ${c.provider} | ${c.sensitivity} | ${c.threatCount} | ${c.maxRiskScore} (${emoji} ${RISK_LEVEL_LABELS[c.maxRiskLevel]}) |\n`;
  });

  return md + '\n';
}

function generateComponentDetails(
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  implementedControls: Record<string, true>,
): string {
  const componentMap = groupThreatsByComponent(nodes, edges, threats);
  const components = Array.from(componentMap.entries())
    .filter(([, c]) => c.threatCount > 0)
    .sort((a, b) => b[1].maxRiskScore - a[1].maxRiskScore);

  let md = `## Component Details

`;

  for (const [, component] of components) {
    md += `### ${component.name}

**Provider:** ${component.provider} | **Sensitivity:** ${component.sensitivity} | **Threats:** ${component.threatCount}

---

`;

    const sortedThreats = [...component.threats].sort((a, b) => b.riskScore - a.riskScore);

    for (const activeThreat of sortedThreats) {
      const threat = activeThreat.threat;
      const emoji = RISK_EMOJI[activeThreat.riskLevel];
      const threatTitle = activeThreat.isConnectionThreat
        ? `${threat.name} (Connection)`
        : threat.name;

      // STRIDE categories
      const strideLabels = threat.stride.map(s => STRIDE_LABELS[s]).join(', ');

      // MITRE ATT&CK techniques
      const mitreInfo = threat.mitreTechniques
        .map(t => `${t.id} (${t.name})`)
        .join(', ');

      // Mitigating Controls with <br> separators (tech-specific if available, otherwise generic).
      // Connection threats use a consolidated key scope; component threats are per-node.
      const keyScope = activeThreat.isConnectionThreat
        ? { kind: 'connection' as const, threatId: threat.id }
        : null;
      const controlsList = activeThreat.techMitigations && activeThreat.techMitigations.length > 0
        ? activeThreat.techMitigations.map(m => {
            const key = keyScope
              ? buildControlKey(keyScope, m)
              : buildControlKey({ kind: 'node-tech', nodeId: activeThreat.sourceNodeId, threatId: threat.id }, m);
            return renderControlLine(m, !!implementedControls[key], escapeMarkdown);
          }).join('<br>')
        : threat.controls.map(control => {
            const key = keyScope
              ? buildControlKey(keyScope, control.description)
              : buildControlKey({ kind: 'node-generic', nodeId: activeThreat.sourceNodeId, threatId: threat.id }, control.description);
            return renderControlLine(control.description, !!implementedControls[key], escapeMarkdown);
          }).join('<br>');

      md += `#### ${threatTitle}

| Field | Details |
|---|---|
| Risk Score | ${activeThreat.riskScore}/16 ${emoji} ${RISK_LEVEL_LABELS[activeThreat.riskLevel]} |
| Severity | ${threat.severity.toUpperCase()} |
| Sensitivity | ${DATA_SENSITIVITY_LABELS[activeThreat.sensitivity]} |`;

      // Connection info if applicable
      if (activeThreat.isConnectionThreat && activeThreat.connectionInfo) {
        const label = activeThreat.connectionInfo.label
          ? ` (${activeThreat.connectionInfo.label})`
          : '';
        md += `
| Data Flow | ${escapeMarkdown(activeThreat.connectionInfo.sourceNodeName)} -> ${escapeMarkdown(activeThreat.connectionInfo.targetNodeName)}${label} |`;
      }

      md += `
| STRIDE | ${strideLabels} |
| MITRE ATT&CK | ${mitreInfo} |
| Description | ${escapeMarkdown(threat.description)} |
| Mitigating Controls | ${controlsList} |

`;
    }
  }

  return md;
}

interface GroupedZoneThreat {
  threat: ActiveThreat['threat'];
  zones: Array<{
    boundaryId: string;
    zoneName: string;
    networkType?: ZoneNetworkType;
    riskScore: number;
    riskLevel: RiskLevel;
    riskReductionPercent?: number;
  }>;
  maxRiskScore: number;
  maxRiskLevel: RiskLevel;
}

function groupZoneThreats(threats: ActiveThreat[]): GroupedZoneThreat[] {
  const zoneMap = new Map<string, GroupedZoneThreat>();

  threats.forEach(threat => {
    if (!threat.isZoneThreat || !threat.zoneInfo) {
      return;
    }

    const existing = zoneMap.get(threat.threat.id);
    const zoneData = {
      boundaryId: threat.zoneInfo.boundaryId,
      zoneName: threat.zoneInfo.zoneName,
      networkType: threat.zoneInfo.networkType,
      riskScore: threat.riskScore,
      riskLevel: threat.riskLevel,
      riskReductionPercent: threat.zoneInfo.riskReductionPercent,
    };

    if (existing) {
      existing.zones.push(zoneData);
      if (threat.riskScore > existing.maxRiskScore) {
        existing.maxRiskScore = threat.riskScore;
        existing.maxRiskLevel = threat.riskLevel;
      }
    } else {
      zoneMap.set(threat.threat.id, {
        threat: threat.threat,
        zones: [zoneData],
        maxRiskScore: threat.riskScore,
        maxRiskLevel: threat.riskLevel,
      });
    }
  });

  return Array.from(zoneMap.values())
    .filter(g => g.zones.length > 0)
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore);
}

function generateOutOfScopeSection(nodes: Node<TechNodeData>[]): string {
  const excludedNodes = nodes.filter(node => node.data.threatsDisabled);

  if (excludedNodes.length === 0) {
    return '';
  }

  let md = `## Out of Scope

The following components have been excluded from threat analysis:

| Component | Provider | Sensitivity | Reason |
|-----------|----------|-------------|--------|
`;

  excludedNodes.forEach(node => {
    const displayName = node.data.customName || node.data.technology.name;
    const provider = PROVIDER_LABELS[node.data.technology.provider];
    const sensitivity = DATA_SENSITIVITY_LABELS[node.data.sensitivity];
    md += `| ${escapeMarkdown(displayName)} | ${provider} | ${sensitivity} | Excluded by user |\n`;
  });

  return md + '\n';
}

function generateZoneThreatDetails(
  threats: ActiveThreat[],
  implementedControls: Record<string, true>,
): string {
  const groupedZoneThreats = groupZoneThreats(threats);

  if (groupedZoneThreats.length === 0) {
    return '';
  }

  let md = `## Network Zone Threats

The following threats apply to private network zones in the architecture.

`;

  for (const groupedThreat of groupedZoneThreats) {
    const threat = groupedThreat.threat;
    const emoji = RISK_EMOJI[groupedThreat.maxRiskLevel];

    // STRIDE categories
    const strideLabels = threat.stride.map(s => STRIDE_LABELS[s]).join(', ');

    // MITRE ATT&CK techniques
    const mitreInfo = threat.mitreTechniques
      .map(t => `${t.id} (${t.name})`)
      .join(', ');

    // Mitigating Controls (zone scope — consolidated per threat id)
    const controlsList = threat.controls
      .map(control => {
        const key = buildControlKey({ kind: 'zone', threatId: threat.id }, control.description);
        return renderControlLine(control.description, !!implementedControls[key], escapeMarkdown);
      })
      .join('<br>');

    // Affected zones list
    const zonesList = groupedThreat.zones
      .map(zone => {
        const networkTypeLabel = zone.networkType && zone.networkType !== 'generic'
          ? ` (${ZONE_NETWORK_TYPE_LABELS[zone.networkType]})`
          : '';
        const zoneEmoji = RISK_EMOJI[zone.riskLevel];
        return `${zone.zoneName}${networkTypeLabel}: ${zone.riskScore} ${zoneEmoji}`;
      })
      .join('<br>');

    md += `### ${threat.name}

| Field | Details |
|---|---|
| Risk Score | ${groupedThreat.maxRiskScore}/16 ${emoji} ${RISK_LEVEL_LABELS[groupedThreat.maxRiskLevel]} |
| Severity | ${threat.severity.toUpperCase()} |
| Affected Zones | ${zonesList} |
| STRIDE | ${strideLabels} |
| MITRE ATT&CK | ${mitreInfo} |
| Description | ${escapeMarkdown(threat.description)} |
| Mitigating Controls | ${controlsList} |

`;
  }

  return md;
}

function generateFooter(generatedAt: string): string {
  return `---

*Generated by [ThreatModelling.io](https://threatmodelling.io) on ${generatedAt}*
`;
}

function downloadMarkdown(content: string, modelName: string): void {
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${modelName.toLowerCase().replace(/\s+/g, '-')}-full-report.md`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export async function generateMarkdownReport(
  modelName: string,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  implementedControls: Record<string, true> = {},
): Promise<void> {
  // Filter out mitigated threats (consistent with PDF export)
  const filteredThreats = filterMitigatedThreats(threats);

  const generatedAt = formatDate(new Date());

  // Build the markdown document
  const markdown = [
    generateHeader(modelName),
    generateOverview(nodes, edges, filteredThreats),
    generateRiskDistribution(filteredThreats),
    generateTopThreats(filteredThreats),
    generateComponentsSummary(nodes, edges, filteredThreats),
    generateComponentDetails(nodes, edges, filteredThreats, implementedControls),
    generateZoneThreatDetails(filteredThreats, implementedControls),
    generateOutOfScopeSection(nodes),
    generateFooter(generatedAt),
  ].join('');

  // Trigger download
  downloadMarkdown(markdown, modelName);
}
