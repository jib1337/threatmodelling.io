import type { Node, Edge } from '@xyflow/react';
import type {
  ActiveThreat,
  TechNodeData,
  ZoneNodeData,
  DataSensitivity,
  StrideCategory,
  ThreatSeverity,
} from '../data/schema';
import {
  DATA_SENSITIVITY_LABELS,
  PROVIDER_LABELS,
  THREAT_SEVERITY_VALUES,
} from '../data/schema';
import { buildControlKey } from './controlFingerprint';

// threatcl spec version targeted by this exporter
const SPEC_VERSION = '0.2.3';

// Canonical STRIDE strings accepted by the threatcl parser
// (see github.com/threatcl/spec config.go).
const STRIDE_TO_THREATCL: Record<StrideCategory, string> = {
  'spoofing': 'Spoofing',
  'tampering': 'Tampering',
  'repudiation': 'Repudiation',
  'information-disclosure': 'Info Disclosure',
  'denial-of-service': 'Denial Of Service',
  'elevation-of-privilege': 'Elevation Of Privilege',
};

// threatcl impacts are Confidentiality / Integrity / Availability.
const STRIDE_TO_IMPACT: Record<StrideCategory, Array<'Confidentiality' | 'Integrity' | 'Availability'>> = {
  'spoofing': ['Integrity'],
  'tampering': ['Integrity'],
  'repudiation': ['Integrity'],
  'information-disclosure': ['Confidentiality'],
  'denial-of-service': ['Availability'],
  'elevation-of-privilege': ['Confidentiality', 'Integrity'],
};

// threatcl information_classification only accepts Restricted/Confidential/Public.
// Our "internal" sensitivity has no direct equivalent — it collapses to Public.
const CLASSIFICATION_BY_SENSITIVITY: Record<DataSensitivity, string> = {
  'public': 'Public',
  'internal': 'Public',
  'confidential': 'Confidential',
  'restricted': 'Restricted',
};

// Map severity to a 0-100 risk_reduction heuristic applied to controls.
const SEVERITY_TO_RISK_REDUCTION: Record<ThreatSeverity, number> = {
  'low': 25,
  'medium': 50,
  'high': 65,
  'critical': 75,
};

function hclEscape(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r?\n/g, '\\n')
    .replace(/\t/g, '\\t');
}

function hclString(value: string): string {
  return `"${hclEscape(value)}"`;
}

// HCL indent-stripping heredoc (<<-EOT) for multi-line values. The leading
// whitespace on each line is stripped up to the indent of the closing marker,
// so the parsed value is flush-left regardless of surrounding indentation.
function hclHeredoc(value: string, indent: string): string {
  const lines = value.split(/\r?\n/);
  return `<<-EOT\n${lines.map(l => `${indent}${l}`).join('\n')}\n${indent}EOT`;
}

function hclList(values: string[]): string {
  return `[${values.map(v => hclString(v)).join(', ')}]`;
}

// threatcl block labels are strings, but we keep them alphanumeric to avoid
// ambiguity with DFD element names referenced by from/to.
function sanitizeLabel(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9_\- ]/g, '').trim();
  return cleaned || 'unnamed';
}

function nodeDisplayName(node: Node<TechNodeData>): string {
  return node.data.customName || node.data.technology.name;
}

function zoneDisplayName(zone: Node<ZoneNodeData>): string {
  return zone.data.customName || `${zone.data.zoneType} zone`;
}

// Ensure a label is unique within a given set (threatcl requires unique
// information_asset and DFD element names).
function uniquify(base: string, used: Set<string>): string {
  let candidate = base;
  let i = 2;
  while (used.has(candidate)) {
    candidate = `${base} ${i++}`;
  }
  used.add(candidate);
  return candidate;
}

interface ThreatGroup {
  threat: ActiveThreat['threat'];
  // Display label for the threat block (unique within the threatmodel)
  displayName: string;
  // Set of information_asset names this threat references
  assetRefs: Set<string>;
  // Affected component names (for description context)
  affectedComponents: Set<string>;
  // Affected connections (for description context)
  affectedConnections: Set<string>;
  // Affected zones (for description context)
  affectedZones: Set<string>;
  maxSeverity: ThreatSeverity;
  // Collected technology-specific context strings
  contexts: Set<string>;
  // Map of tech-mitigation description -> contributing nodeIds (for per-node
  // control-implementation lookup). Presence of any entry here causes the
  // generic threat.controls to be skipped (matches prior behavior).
  techMitigations: Map<string, Set<string>>;
  // Node IDs that contributed a component-level instance of this threat. Used
  // to resolve generic-control implementation status across all affected nodes.
  componentNodeIds: Set<string>;
  // Kind of threat grouping — controls which key scope to use when looking up
  // implementation status.
  kind: 'component' | 'connection' | 'zone';
}

function severityRank(s: ThreatSeverity): number {
  return THREAT_SEVERITY_VALUES[s];
}

function groupThreats(
  threats: ActiveThreat[],
  assetNameByNodeId: Map<string, string>,
): ThreatGroup[] {
  const map = new Map<string, ThreatGroup>();

  for (const at of threats) {
    const key = at.threat.id;
    let group = map.get(key);
    if (!group) {
      const kind: ThreatGroup['kind'] = at.isZoneThreat
        ? 'zone'
        : at.isConnectionThreat
          ? 'connection'
          : 'component';
      group = {
        threat: at.threat,
        displayName: at.threat.name,
        assetRefs: new Set(),
        affectedComponents: new Set(),
        affectedConnections: new Set(),
        affectedZones: new Set(),
        maxSeverity: at.threat.severity,
        contexts: new Set(),
        techMitigations: new Map(),
        componentNodeIds: new Set(),
        kind,
      };
      map.set(key, group);
    }

    if (at.isZoneThreat && at.zoneInfo) {
      group.affectedZones.add(at.zoneInfo.zoneName);
    } else if (at.isConnectionThreat && at.connectionInfo) {
      const label = at.connectionInfo.label ? ` (${at.connectionInfo.label})` : '';
      group.affectedConnections.add(
        `${at.connectionInfo.sourceNodeName} -> ${at.connectionInfo.targetNodeName}${label}`,
      );
      // Link both endpoints if they map to information_assets
      const srcAsset = assetNameByNodeId.get(at.sourceNodeId);
      if (srcAsset) group.assetRefs.add(srcAsset);
    } else {
      group.affectedComponents.add(at.sourceTechName);
      group.componentNodeIds.add(at.sourceNodeId);
      const assetName = assetNameByNodeId.get(at.sourceNodeId);
      if (assetName) group.assetRefs.add(assetName);
    }

    const effective = at.overriddenSeverity ?? at.threat.severity;
    if (severityRank(effective) > severityRank(group.maxSeverity)) {
      group.maxSeverity = effective;
    }

    if (at.context) group.contexts.add(at.context);
    if (at.techMitigations) {
      for (const m of at.techMitigations) {
        let contributors = group.techMitigations.get(m);
        if (!contributors) {
          contributors = new Set();
          group.techMitigations.set(m, contributors);
        }
        contributors.add(at.sourceNodeId);
      }
    }
  }

  // Uniquify threat display names — threatcl requires unique threat labels.
  const usedThreatNames = new Set<string>();
  for (const group of map.values()) {
    group.displayName = uniquify(group.threat.name, usedThreatNames);
  }

  return Array.from(map.values());
}

function renderHeader(modelName: string): string {
  return [
    `spec_version = ${hclString(SPEC_VERSION)}`,
    '',
    `threatmodel ${hclString(modelName)} {`,
    `  author = "ThreatModelling.io"`,
    `  description = ${hclString(`Exported from ThreatModelling.io on ${new Date().toISOString()}`)}`,
  ].join('\n');
}

function renderAttributes(nodeCount: number, edgeCount: number): string {
  // initiative_size accepts Undefined/Small/Medium/Large only.
  const size = nodeCount > 10 ? 'Large' : nodeCount > 5 ? 'Medium' : nodeCount > 0 ? 'Small' : 'Undefined';
  return [
    '  attributes {',
    `    new_initiative = "true"`,
    `    internet_facing = "${nodeCount > 0 ? 'true' : 'false'}"`,
    `    initiative_size = ${hclString(size)}`,
    '  }',
    '',
    `  additional_attribute "source_tool" {`,
    `    value = "ThreatModelling.io"`,
    `  }`,
    '',
    `  additional_attribute "component_count" {`,
    `    value = ${hclString(String(nodeCount))}`,
    `  }`,
    '',
    `  additional_attribute "data_flow_count" {`,
    `    value = ${hclString(String(edgeCount))}`,
    `  }`,
  ].join('\n');
}

// Assign a unique information_asset name to every relevant node, returning
// the render text and a lookup map (nodeId -> asset name).
function renderInformationAssets(nodes: Node<TechNodeData>[]): {
  text: string;
  assetNameByNodeId: Map<string, string>;
} {
  const assetNameByNodeId = new Map<string, string>();
  const used = new Set<string>();

  // Every node becomes an information asset — this is what lets threats
  // reference them via information_asset_refs.
  const blocks: string[] = [];
  for (const node of nodes) {
    if (node.data.threatsDisabled) continue;
    const base = sanitizeLabel(nodeDisplayName(node));
    const assetName = uniquify(base, used);
    assetNameByNodeId.set(node.id, assetName);

    const tech = node.data.technology;
    const classification = CLASSIFICATION_BY_SENSITIVITY[node.data.sensitivity];
    const desc = `${tech.name} (${PROVIDER_LABELS[tech.provider]}) — ${DATA_SENSITIVITY_LABELS[node.data.sensitivity]} data`;
    blocks.push(
      [
        `  information_asset ${hclString(assetName)} {`,
        `    description = ${hclString(desc)}`,
        `    information_classification = ${hclString(classification)}`,
        `  }`,
      ].join('\n'),
    );
  }

  return { text: blocks.join('\n\n'), assetNameByNodeId };
}

function renderThirdPartyDependencies(nodes: Node<TechNodeData>[]): string {
  const thirdParty = nodes.filter(
    n => n.data.technology.provider === 'saas' || n.data.technology.provider === 'actor',
  );
  if (thirdParty.length === 0) return '';

  const used = new Set<string>();
  return thirdParty
    .map(node => {
      const name = uniquify(sanitizeLabel(nodeDisplayName(node)), used);
      const tech = node.data.technology;
      const isSaas = tech.provider === 'saas';
      return [
        `  third_party_dependency ${hclString(name)} {`,
        `    description = ${hclString(tech.description || `${tech.name} third-party dependency`)}`,
        `    uptime_dependency = "degraded"`,
        isSaas ? `    saas = "true"` : `    saas = "false"`,
      ]
        .concat(['  }'])
        .join('\n');
    })
    .join('\n\n');
}

function renderUsecases(nodes: Node<TechNodeData>[], edges: Edge[]): string {
  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const labelled = edges
    .map(e => {
      const src = nodeById.get(e.source);
      const dst = nodeById.get(e.target);
      if (!src || !dst) return null;
      const label = (e.data as { label?: string } | undefined)?.label;
      if (!label) return null;
      return `${nodeDisplayName(src)} ${label} ${nodeDisplayName(dst)}`;
    })
    .filter((v): v is string => v !== null);

  if (labelled.length === 0) {
    return [
      `  usecase {`,
      `    description = "System components exchange data as modelled in the data flow diagram."`,
      `  }`,
    ].join('\n');
  }

  return labelled
    .map(desc =>
      [`  usecase {`, `    description = ${hclString(desc)}`, `  }`].join('\n'),
    )
    .join('\n\n');
}

function renderExclusions(nodes: Node<TechNodeData>[]): string {
  const excluded = nodes.filter(n => n.data.threatsDisabled);
  if (excluded.length === 0) return '';
  return excluded
    .map(node => {
      const name = nodeDisplayName(node);
      return [
        `  exclusion {`,
        `    description = ${hclString(`${name} is explicitly out of scope for this threat model.`)}`,
        `  }`,
      ].join('\n');
    })
    .join('\n\n');
}

// Determine whether a control should be emitted as implemented. A group may
// aggregate several nodes worth of the same threat, and per-node control state
// is tracked independently — we report `implemented = true` only when every
// contributing scope has actioned the control, so the HCL reflects the
// stricter reality.
function resolveControlImplemented(
  group: ThreatGroup,
  description: string,
  fromTech: boolean,
  implementedControls: Record<string, true>,
): boolean {
  if (group.kind === 'connection') {
    const k = buildControlKey({ kind: 'connection', threatId: group.threat.id }, description);
    return !!implementedControls[k];
  }
  if (group.kind === 'zone') {
    const k = buildControlKey({ kind: 'zone', threatId: group.threat.id }, description);
    return !!implementedControls[k];
  }
  // Component threats — per-node AND across contributors.
  if (fromTech) {
    const contributors = group.techMitigations.get(description);
    if (!contributors || contributors.size === 0) return false;
    for (const nodeId of contributors) {
      const k = buildControlKey({ kind: 'node-tech', nodeId, threatId: group.threat.id }, description);
      if (!implementedControls[k]) return false;
    }
    return true;
  }
  if (group.componentNodeIds.size === 0) return false;
  for (const nodeId of group.componentNodeIds) {
    const k = buildControlKey({ kind: 'node-generic', nodeId, threatId: group.threat.id }, description);
    if (!implementedControls[k]) return false;
  }
  return true;
}

function renderThreats(
  groups: ThreatGroup[],
  implementedControls: Record<string, true>,
): string {
  if (groups.length === 0) return '';

  return groups
    .map(group => {
      const { threat, displayName } = group;

      // Build a narrative description that preserves the affected-components
      // context (threatcl threats are model-level, so we summarize here).
      const contextParts: string[] = [threat.description];
      if (group.affectedComponents.size > 0) {
        contextParts.push(`\nAffects components: ${Array.from(group.affectedComponents).join(', ')}`);
      }
      if (group.affectedConnections.size > 0) {
        contextParts.push(`\nAffects data flows: ${Array.from(group.affectedConnections).join('; ')}`);
      }
      if (group.affectedZones.size > 0) {
        contextParts.push(`\nAffects trust zones: ${Array.from(group.affectedZones).join(', ')}`);
      }
      if (group.contexts.size > 0) {
        contextParts.push(`\nContext: ${Array.from(group.contexts).join(' | ')}`);
      }
      const fullDesc = contextParts.join('\n');

      const impactSet = new Set<'Confidentiality' | 'Integrity' | 'Availability'>();
      threat.stride.forEach(s => STRIDE_TO_IMPACT[s].forEach(i => impactSet.add(i)));
      const impacts = Array.from(impactSet);

      const strideValues = threat.stride.map(s => STRIDE_TO_THREATCL[s]);

      const reduction = SEVERITY_TO_RISK_REDUCTION[group.maxSeverity];
      const fromTech = group.techMitigations.size > 0;
      const controlSources = fromTech
        ? Array.from(group.techMitigations.keys()).map((d, i) => ({
            name: `tech-mitigation-${i + 1}`,
            description: d,
          }))
        : threat.controls.map((c, i) => ({
            name: c.id || `control-${i + 1}`,
            description: c.description,
          }));

      // MITRE techniques are packed into each control as attribute blocks —
      // threatcl has no first-class place for them on threats, but control
      // attributes are the idiomatic escape hatch.
      const mitreAttributes = threat.mitreTechniques
        .map(t => {
          const name = `MITRE ${t.id}`;
          const value = `${t.name} (${t.tactic})`;
          return [
            `      attribute ${hclString(name)} {`,
            `        value = ${hclString(value)}`,
            `      }`,
          ].join('\n');
        })
        .join('\n');

      const controlBlocks = controlSources
        .map((c, idx) => {
          const implemented = resolveControlImplemented(group, c.description, fromTech, implementedControls);
          const lines = [
            `    control ${hclString(sanitizeLabel(c.name) || `control-${idx + 1}`)} {`,
            `      description = ${hclString(c.description)}`,
            `      implemented = ${implemented ? 'true' : 'false'}`,
            `      risk_reduction = ${reduction}`,
          ];
          // Put MITRE attributes on the first control only so we don't repeat
          // them per-control.
          if (idx === 0 && mitreAttributes) {
            lines.push('');
            lines.push(mitreAttributes);
          }
          lines.push(`    }`);
          return lines.join('\n');
        })
        .join('\n\n');

      const parts: string[] = [];
      parts.push(`  threat ${hclString(displayName)} {`);
      parts.push(`    description = ${hclHeredoc(fullDesc, '      ')}`);
      if (impacts.length > 0) {
        parts.push(`    impacts = ${hclList(impacts)}`);
      }
      if (strideValues.length > 0) {
        parts.push(`    stride = ${hclList(strideValues)}`);
      }
      if (group.assetRefs.size > 0) {
        parts.push(`    information_asset_refs = ${hclList(Array.from(group.assetRefs))}`);
      }
      if (controlBlocks) {
        parts.push('');
        parts.push(controlBlocks);
      }
      parts.push(`  }`);
      return parts.join('\n');
    })
    .join('\n\n');
}

function renderDfd(
  modelName: string,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  boundaries: Node<ZoneNodeData>[],
  assetNameByNodeId: Map<string, string>,
): string {
  if (nodes.length === 0) return '';

  // Classify each node into a DFD element kind.
  const dataStoreCategories = new Set(['database', 'storage', 'secrets']);
  type Kind = 'process' | 'data_store' | 'external_element';
  const kindOf = (n: Node<TechNodeData>): Kind => {
    const prov = n.data.technology.provider;
    const cat = n.data.technology.category;
    if (cat === 'actor' || prov === 'actor' || prov === 'saas') return 'external_element';
    if (dataStoreCategories.has(cat)) return 'data_store';
    return 'process';
  };

  // threatcl requires DFD element names to be unique across all kinds within
  // a single DFD. We reuse the information_asset names when available so that
  // data_store's information_asset attribute lines up; otherwise we mint a
  // unique sanitized label.
  const dfdNameByNodeId = new Map<string, string>();
  const used = new Set<string>();
  nodes.forEach(n => {
    const base = assetNameByNodeId.get(n.id) ?? sanitizeLabel(nodeDisplayName(n));
    dfdNameByNodeId.set(n.id, uniquify(base, used));
  });

  // Group nodes by their containing boundary (or top-level).
  const topLevel: Node<TechNodeData>[] = [];
  const byBoundary = new Map<string, Node<TechNodeData>[]>();
  nodes.forEach(n => {
    if (n.parentId) {
      const arr = byBoundary.get(n.parentId) ?? [];
      arr.push(n);
      byBoundary.set(n.parentId, arr);
    } else {
      topLevel.push(n);
    }
  });

  const renderElement = (n: Node<TechNodeData>, indent: string): string => {
    const label = dfdNameByNodeId.get(n.id)!;
    const kind = kindOf(n);
    const lines = [`${indent}${kind} ${hclString(label)} {`];
    if (kind === 'data_store') {
      const asset = assetNameByNodeId.get(n.id);
      if (asset) {
        lines.push(`${indent}  information_asset = ${hclString(asset)}`);
      }
    }
    lines.push(`${indent}}`);
    return lines.join('\n');
  };

  const parts: string[] = [];
  const dfdLabel = sanitizeLabel(modelName) || 'primary';
  parts.push(`  data_flow_diagram_v2 ${hclString(dfdLabel)} {`);

  // Top-level elements (not in a boundary)
  topLevel.forEach(n => parts.push(renderElement(n, '    ')));

  // Trust zones for each boundary that has contents
  const usedZoneNames = new Set<string>();
  boundaries.forEach(zone => {
    const contained = byBoundary.get(zone.id);
    if (!contained || contained.length === 0) return;
    const zoneLabel = uniquify(sanitizeLabel(zoneDisplayName(zone)), usedZoneNames);
    const inner = contained.map(n => renderElement(n, '        ')).join('\n\n');
    parts.push(
      [
        `    trust_zone ${hclString(zoneLabel)} {`,
        inner,
        `    }`,
      ].join('\n'),
    );
  });

  // Flows — name does not need to be unique, but from/to for a given name must be.
  edges.forEach((edge, idx) => {
    const srcLabel = dfdNameByNodeId.get(edge.source);
    const dstLabel = dfdNameByNodeId.get(edge.target);
    if (!srcLabel || !dstLabel) return;
    const rawLabel = (edge.data as { label?: string } | undefined)?.label || `flow-${idx + 1}`;
    parts.push(
      [
        `    flow ${hclString(sanitizeLabel(rawLabel) || `flow-${idx + 1}`)} {`,
        `      from = ${hclString(srcLabel)}`,
        `      to = ${hclString(dstLabel)}`,
        `    }`,
      ].join('\n'),
    );
  });

  parts.push(`  }`);
  return parts.join('\n\n');
}

export function generateThreatclDocument(
  modelName: string,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  boundaries: Node<ZoneNodeData>[],
  implementedControls: Record<string, true> = {},
): string {
  const liveThreats = threats.filter(t => !t.mitigatedBy);

  const sections: string[] = [];
  sections.push(renderHeader(modelName));
  sections.push('');
  sections.push(renderAttributes(nodes.length, edges.length));

  const { text: assetText, assetNameByNodeId } = renderInformationAssets(nodes);
  if (assetText) {
    sections.push('');
    sections.push(assetText);
  }

  const thirdParty = renderThirdPartyDependencies(nodes);
  if (thirdParty) {
    sections.push('');
    sections.push(thirdParty);
  }

  const usecases = renderUsecases(nodes, edges);
  if (usecases) {
    sections.push('');
    sections.push(usecases);
  }

  const exclusions = renderExclusions(nodes);
  if (exclusions) {
    sections.push('');
    sections.push(exclusions);
  }

  const groups = groupThreats(liveThreats, assetNameByNodeId);
  const threatBlocks = renderThreats(groups, implementedControls);
  if (threatBlocks) {
    sections.push('');
    sections.push(threatBlocks);
  }

  const dfd = renderDfd(modelName, nodes, edges, boundaries, assetNameByNodeId);
  if (dfd) {
    sections.push('');
    sections.push(dfd);
  }

  sections.push('}');
  return sections.join('\n') + '\n';
}

export function exportThreatcl(
  modelName: string,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  boundaries: Node<ZoneNodeData>[],
  implementedControls: Record<string, true> = {},
): void {
  const hcl = generateThreatclDocument(modelName, nodes, edges, threats, boundaries, implementedControls);
  const blob = new Blob([hcl], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${modelName.toLowerCase().replace(/\s+/g, '-')}.hcl`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
