import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Node, Edge } from '@xyflow/react';
import type {
  ActiveThreat,
  TechNodeData,
  ZoneNodeData,
  Technology,
  Threat,
  DataSensitivity,
  CloudProvider,
  ServiceCategory,
  StrideCategory,
} from '../data/schema';
import { generateThreatclDocument } from './threatclExport';
import { buildControlKey } from './controlFingerprint';

// --- fixture helpers ---------------------------------------------------------

function makeTech(overrides: Partial<Technology> = {}): Technology {
  return {
    id: 'x',
    name: 'Tech',
    provider: 'aws',
    category: 'compute',
    description: 'desc',
    threatIds: [],
    ...overrides,
  };
}

function makeNode(
  id: string,
  name: string,
  opts: {
    provider?: CloudProvider;
    category?: ServiceCategory;
    sensitivity?: DataSensitivity;
    parentId?: string;
    threatsDisabled?: boolean;
    customName?: string;
  } = {},
): Node<TechNodeData> {
  const {
    provider = 'aws',
    category = 'compute',
    sensitivity = 'internal',
    parentId,
    threatsDisabled,
    customName,
  } = opts;
  return {
    id,
    type: 'tech',
    position: { x: 0, y: 0 },
    parentId,
    data: {
      technology: makeTech({ id: `${provider}-${name}`, name, provider, category }),
      label: name,
      sensitivity,
      customName,
      threatsDisabled,
    },
  };
}

function makeEdge(id: string, source: string, target: string, label?: string): Edge {
  return {
    id,
    source,
    target,
    data: label ? { label } : undefined,
  };
}

function makeZone(id: string, name: string): Node<ZoneNodeData> {
  return {
    id,
    type: 'zone',
    position: { x: 0, y: 0 },
    data: {
      zoneType: 'private',
      label: name,
      customName: name,
    },
  };
}

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    id: 't-default',
    name: 'Default threat',
    description: 'A default threat',
    severity: 'medium',
    stride: ['tampering'],
    mitreTechniques: [],
    controls: [{ id: 'ctrl-default-1', description: 'Apply best practices' }],
    ...overrides,
  };
}

function makeActiveThreat(
  threat: Threat,
  overrides: Partial<ActiveThreat> = {},
): ActiveThreat {
  return {
    threat,
    sourceNodeId: 'n1',
    sourceTechName: 'Tech',
    sensitivity: 'internal',
    riskScore: 4,
    riskLevel: 'medium',
    ...overrides,
  };
}

// A reusable "representative" model touching every code path in the exporter.
function buildRepresentativeModel() {
  const nodes: Node<TechNodeData>[] = [
    makeNode('n-ec2', 'EC2 Instance', {
      provider: 'aws',
      category: 'compute',
      sensitivity: 'confidential',
    }),
    makeNode('n-rds', 'RDS Postgres', {
      provider: 'aws',
      category: 'database',
      sensitivity: 'restricted',
      parentId: 'z-vpc',
    }),
    makeNode('n-s3', 'S3 Bucket', {
      provider: 'aws',
      category: 'storage',
      sensitivity: 'confidential',
      parentId: 'z-vpc',
    }),
    makeNode('n-github', 'GitHub', {
      provider: 'saas',
      category: 'saas',
      sensitivity: 'internal',
    }),
    makeNode('n-user', 'End User', {
      provider: 'actor',
      category: 'actor',
      sensitivity: 'public',
    }),
    makeNode('n-legacy', 'Legacy Box', {
      provider: 'self-hosted',
      category: 'compute',
      sensitivity: 'internal',
      threatsDisabled: true,
    }),
  ];

  const edges: Edge[] = [
    makeEdge('e1', 'n-user', 'n-ec2', 'HTTPS'),
    makeEdge('e2', 'n-ec2', 'n-rds', 'SQL'),
    makeEdge('e3', 'n-ec2', 'n-s3'),
    makeEdge('e4', 'n-ec2', 'n-github', 'webhook'),
  ];

  const boundaries: Node<ZoneNodeData>[] = [makeZone('z-vpc', 'Private VPC')];

  const sqlInjection = makeThreat({
    id: 't-sqli',
    name: 'SQL Injection',
    description: 'Attacker injects SQL through unsanitized input',
    severity: 'critical',
    stride: ['tampering', 'information-disclosure'],
    mitreTechniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    ],
    controls: [{ id: 'ctrl-sqli-1', description: 'Use parameterized queries' }],
  });

  const mitm = makeThreat({
    id: 't-mitm',
    name: 'Man-in-the-Middle',
    description: 'Traffic intercepted in transit',
    severity: 'high',
    stride: ['information-disclosure'],
    isConnectionThreat: true,
    mitreTechniques: [
      { id: 'T1040', name: 'Network Sniffing', tactic: 'Credential Access' },
    ],
    controls: [{ id: 'ctrl-mitm-1', description: 'Enforce TLS 1.2+' }],
  });

  const dos = makeThreat({
    id: 't-dos',
    name: 'Denial of Service',
    description: 'Resource exhaustion',
    severity: 'high',
    stride: ['denial-of-service'],
    mitreTechniques: [],
    controls: [{ id: 'ctrl-dos-1', description: 'Rate limiting' }],
  });

  const activeThreats: ActiveThreat[] = [
    makeActiveThreat(sqlInjection, {
      sourceNodeId: 'n-rds',
      sourceTechName: 'RDS Postgres',
      sourceTechnologyId: 'aws-RDS Postgres',
      sensitivity: 'restricted',
      riskScore: 16,
      riskLevel: 'critical',
      techMitigations: ['Parameterized queries', 'Prepared statements'],
    }),
    makeActiveThreat(mitm, {
      sourceNodeId: 'n-ec2',
      sourceTechName: 'EC2 Instance',
      sensitivity: 'confidential',
      riskScore: 9,
      riskLevel: 'high',
      isConnectionThreat: true,
      connectionInfo: {
        edgeId: 'e1',
        sourceNodeName: 'End User',
        targetNodeName: 'EC2 Instance',
        label: 'HTTPS',
      },
    }),
    // A threat that should be filtered out because it is marked mitigated
    makeActiveThreat(dos, {
      sourceNodeId: 'n-ec2',
      sourceTechName: 'EC2 Instance',
      mitigatedBy: 'internal',
    }),
  ];

  return { nodes, edges, boundaries, activeThreats };
}

// --- unit tests on document structure ---------------------------------------

describe('generateThreatclDocument', () => {
  it('emits a spec_version and a single threatmodel block with the given name', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('Payments API', nodes, edges, activeThreats, boundaries);

    expect(hcl.startsWith('spec_version = "0.2.3"')).toBe(true);
    expect(hcl).toMatch(/^threatmodel "Payments API" \{/m);
    // Single threatmodel block: exactly one opening and one closing at col 0.
    expect(hcl.match(/^threatmodel /gm)?.length).toBe(1);
    expect(hcl.match(/^\}$/gm)?.length).toBe(1);
  });

  it('buckets initiative_size by component count', () => {
    const build = (count: number) => {
      const nodes = Array.from({ length: count }, (_, i) => makeNode(`n${i}`, `N${i}`));
      return generateThreatclDocument('M', nodes, [], [], []);
    };
    expect(build(0)).toMatch(/initiative_size = "Undefined"/);
    expect(build(3)).toMatch(/initiative_size = "Small"/);
    expect(build(8)).toMatch(/initiative_size = "Medium"/);
    expect(build(20)).toMatch(/initiative_size = "Large"/);
  });

  it('renders every non-excluded node as an information_asset with a valid classification', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);

    expect(hcl).toMatch(/information_asset "EC2 Instance" \{/);
    expect(hcl).toMatch(/information_asset "RDS Postgres" \{/);
    expect(hcl).toMatch(/information_asset "S3 Bucket" \{/);
    expect(hcl).toMatch(/information_asset "GitHub" \{/);
    expect(hcl).toMatch(/information_asset "End User" \{/);
    // Excluded (threatsDisabled) nodes do not become assets
    expect(hcl).not.toMatch(/information_asset "Legacy Box"/);

    // Only the three threatcl-legal classifications should appear
    const classifications = Array.from(hcl.matchAll(/information_classification = "([^"]+)"/g)).map(
      m => m[1],
    );
    expect(classifications.length).toBeGreaterThan(0);
    for (const c of classifications) {
      expect(['Public', 'Confidential', 'Restricted']).toContain(c);
    }
  });

  it('maps internal sensitivity to Public and preserves Confidential/Restricted', () => {
    const nodes = [
      makeNode('a', 'A', { sensitivity: 'public' }),
      makeNode('b', 'B', { sensitivity: 'internal' }),
      makeNode('c', 'C', { sensitivity: 'confidential' }),
      makeNode('d', 'D', { sensitivity: 'restricted' }),
    ];
    const hcl = generateThreatclDocument('M', nodes, [], [], []);
    expect(hcl).toMatch(/information_asset "A"[\s\S]+?information_classification = "Public"/);
    expect(hcl).toMatch(/information_asset "B"[\s\S]+?information_classification = "Public"/);
    expect(hcl).toMatch(/information_asset "C"[\s\S]+?information_classification = "Confidential"/);
    expect(hcl).toMatch(/information_asset "D"[\s\S]+?information_classification = "Restricted"/);
  });

  it('uniquifies duplicate asset names so threatcl label uniqueness holds', () => {
    const nodes = [
      makeNode('a', 'API'),
      makeNode('b', 'API'),
      makeNode('c', 'API'),
    ];
    const hcl = generateThreatclDocument('M', nodes, [], [], []);
    expect(hcl).toMatch(/information_asset "API" \{/);
    expect(hcl).toMatch(/information_asset "API 2" \{/);
    expect(hcl).toMatch(/information_asset "API 3" \{/);
  });

  it('renders saas/actor nodes as third_party_dependency and omits others', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);

    expect(hcl).toMatch(/third_party_dependency "GitHub" \{[\s\S]+?saas = "true"/);
    expect(hcl).toMatch(/third_party_dependency "End User" \{[\s\S]+?saas = "false"/);
    expect(hcl).not.toMatch(/third_party_dependency "EC2 Instance"/);
    // uptime_dependency is required on the third_party_dependency block
    expect(hcl).toMatch(/third_party_dependency "GitHub" \{[\s\S]+?uptime_dependency = "degraded"/);
  });

  it('derives usecase blocks from labelled edges and falls back when none have labels', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
    expect(hcl).toMatch(/usecase \{\s+description = "End User HTTPS EC2 Instance"/);
    expect(hcl).toMatch(/usecase \{\s+description = "EC2 Instance SQL RDS Postgres"/);
    // The unlabeled edge (e3) should NOT produce a usecase
    expect(hcl).not.toMatch(/usecase \{\s+description = "EC2 Instance  S3 Bucket"/);

    // Fallback when no labelled edges at all
    const fallbackNodes = [makeNode('a', 'A'), makeNode('b', 'B')];
    const fallbackEdges = [makeEdge('e', 'a', 'b')];
    const fallback = generateThreatclDocument('M', fallbackNodes, fallbackEdges, [], []);
    expect(fallback).toMatch(/usecase \{[\s\S]+?data flow diagram/);
  });

  it('produces an exclusion block for every threatsDisabled node', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
    expect(hcl).toMatch(/exclusion \{[\s\S]+?Legacy Box is explicitly out of scope/);
  });

  it('canonicalizes STRIDE values to threatcl form', () => {
    const t = makeThreat({
      stride: [
        'spoofing',
        'tampering',
        'repudiation',
        'information-disclosure',
        'denial-of-service',
        'elevation-of-privilege',
      ] as StrideCategory[],
    });
    const at = makeActiveThreat(t, { sourceNodeId: 'n1' });
    const hcl = generateThreatclDocument(
      'M',
      [makeNode('n1', 'Host', { sensitivity: 'confidential' })],
      [],
      [at],
      [],
    );
    const strideMatch = hcl.match(/stride = \[([^\]]+)\]/);
    expect(strideMatch).not.toBeNull();
    const values = strideMatch![1].split(',').map(s => s.trim().replace(/"/g, ''));
    expect(values).toEqual([
      'Spoofing',
      'Tampering',
      'Repudiation',
      'Info Disclosure',
      'Denial Of Service',
      'Elevation Of Privilege',
    ]);
  });

  it('derives impacts from STRIDE categories and dedupes across multiple strides', () => {
    const t = makeThreat({
      stride: ['tampering', 'elevation-of-privilege'] as StrideCategory[],
    });
    const hcl = generateThreatclDocument(
      'M',
      [makeNode('n1', 'Host', { sensitivity: 'confidential' })],
      [],
      [makeActiveThreat(t)],
      [],
    );
    const match = hcl.match(/impacts = \[([^\]]+)\]/);
    expect(match).not.toBeNull();
    const impacts = match![1].split(',').map(s => s.trim().replace(/"/g, ''));
    // tampering->Integrity, elevation-of-privilege->Confidentiality,Integrity
    expect(new Set(impacts)).toEqual(new Set(['Integrity', 'Confidentiality']));
  });

  it('dedupes threats by id and links threats to their source asset via information_asset_refs', () => {
    const shared = makeThreat({ id: 't-shared', name: 'Shared', severity: 'high' });
    const nodes = [
      makeNode('n1', 'Host A', { sensitivity: 'confidential' }),
      makeNode('n2', 'Host B', { sensitivity: 'confidential' }),
    ];
    const threats = [
      makeActiveThreat(shared, { sourceNodeId: 'n1', sourceTechName: 'Host A' }),
      makeActiveThreat(shared, { sourceNodeId: 'n2', sourceTechName: 'Host B' }),
    ];
    const hcl = generateThreatclDocument('M', nodes, [], threats, []);

    // Single "Shared" threat block, even though there are two instances
    const threatBlocks = hcl.match(/^  threat "Shared"/gm) ?? [];
    expect(threatBlocks.length).toBe(1);

    // Both assets appear in information_asset_refs
    const refMatch = hcl.match(/information_asset_refs = \[([^\]]+)\]/);
    expect(refMatch).not.toBeNull();
    expect(refMatch![1]).toContain('"Host A"');
    expect(refMatch![1]).toContain('"Host B"');
  });

  it('filters out threats flagged as mitigated before rendering', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
    // The DoS threat in the fixture is mitigatedBy: 'internal'
    expect(hcl).not.toMatch(/threat "Denial of Service"/);
    expect(hcl).toMatch(/threat "SQL Injection"/);
  });

  it('prefers tech-specific mitigations over generic controls when present', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
    // SQL Injection in the fixture provides techMitigations
    expect(hcl).toMatch(
      /threat "SQL Injection"[\s\S]+?control "tech-mitigation-1"[\s\S]+?description = "Parameterized queries"/,
    );
    expect(hcl).toMatch(
      /threat "SQL Injection"[\s\S]+?control "tech-mitigation-2"[\s\S]+?description = "Prepared statements"/,
    );
    // The generic control should NOT be rendered when tech mitigations exist
    expect(hcl).not.toMatch(/threat "SQL Injection"[\s\S]+?Use parameterized queries/);
  });

  it('embeds MITRE techniques as control attribute blocks', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
    expect(hcl).toMatch(
      /attribute "MITRE T1190" \{\s+value = "Exploit Public-Facing Application \(Initial Access\)"\s+\}/,
    );
    expect(hcl).toMatch(
      /attribute "MITRE T1040" \{\s+value = "Network Sniffing \(Credential Access\)"\s+\}/,
    );
  });

  it('uses indent-stripping heredocs (<<-EOT) for descriptions', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
    expect(hcl).toMatch(/description = <<-EOT/);
    expect(hcl).not.toMatch(/description = <<EOT\b/);
  });

  describe('data_flow_diagram_v2', () => {
    it('classifies nodes into process / data_store / external_element by category', () => {
      const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
      const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);

      // EC2 (compute) -> process
      expect(hcl).toMatch(/process "EC2 Instance" \{/);
      // RDS (database) -> data_store, inside the trust_zone
      expect(hcl).toMatch(/trust_zone "Private VPC" \{[\s\S]+?data_store "RDS Postgres"/);
      // S3 (storage) -> data_store
      expect(hcl).toMatch(/data_store "S3 Bucket"/);
      // GitHub (saas) -> external_element
      expect(hcl).toMatch(/external_element "GitHub" \{/);
      // End User (actor) -> external_element
      expect(hcl).toMatch(/external_element "End User" \{/);
    });

    it('nests nodes with parentId inside their trust_zone block', () => {
      const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
      const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
      const zoneMatch = hcl.match(/trust_zone "Private VPC" \{([\s\S]+?)\n    \}/);
      expect(zoneMatch).not.toBeNull();
      const zoneBody = zoneMatch![1];
      expect(zoneBody).toContain('data_store "RDS Postgres"');
      expect(zoneBody).toContain('data_store "S3 Bucket"');
      expect(zoneBody).not.toContain('"EC2 Instance"');
    });

    it('links data_store elements back to their information_asset', () => {
      const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
      const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
      expect(hcl).toMatch(
        /data_store "RDS Postgres" \{\s+information_asset = "RDS Postgres"\s+\}/,
      );
    });

    it('emits flow blocks for every edge, preserving labels and node references', () => {
      const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
      const hcl = generateThreatclDocument('M', nodes, edges, activeThreats, boundaries);
      expect(hcl).toMatch(/flow "HTTPS" \{\s+from = "End User"\s+to = "EC2 Instance"\s+\}/);
      expect(hcl).toMatch(/flow "SQL" \{\s+from = "EC2 Instance"\s+to = "RDS Postgres"\s+\}/);
      // Unlabelled edge (e3) falls back to a synthetic name
      expect(hcl).toMatch(/flow "flow-3" \{\s+from = "EC2 Instance"\s+to = "S3 Bucket"\s+\}/);
    });

    it('skips empty DFDs when there are no nodes', () => {
      const hcl = generateThreatclDocument('Empty', [], [], [], []);
      expect(hcl).not.toMatch(/data_flow_diagram_v2/);
    });
  });

  it('HCL-escapes quotes and backslashes in user-provided strings', () => {
    const nodes = [makeNode('n1', 'Weird "quoted" \\ name')];
    const hcl = generateThreatclDocument('Model "X"', nodes, [], [], []);
    expect(hcl).toContain('threatmodel "Model \\"X\\""');
    expect(hcl).toContain('"Weird quoted  name"'); // sanitized label drops quotes/backslashes
  });

  describe('implementedControls', () => {
    // Pulls every `implemented = ...` value found inside a named threat block.
    function implementedFlagsFor(hcl: string, threatName: string): boolean[] {
      const block = hcl.match(new RegExp(`threat "${threatName}" \\{[\\s\\S]+?\\n  \\}`));
      if (!block) throw new Error(`threat block "${threatName}" not found`);
      return Array.from(block[0].matchAll(/implemented = (true|false)/g)).map(
        m => m[1] === 'true',
      );
    }

    it('defaults every control to implemented = false when no map is supplied', () => {
      const t = makeThreat({
        id: 't-x',
        name: 'X',
        controls: [
          { id: 'ctrl-x-1', description: 'Step one' },
          { id: 'ctrl-x-2', description: 'Step two' },
        ],
      });
      const at = makeActiveThreat(t, { sourceNodeId: 'n1' });
      const hcl = generateThreatclDocument(
        'M',
        [makeNode('n1', 'Host', { sensitivity: 'confidential' })],
        [],
        [at],
        [],
      );
      expect(implementedFlagsFor(hcl, 'X')).toEqual([false, false]);
    });

    it('marks a node-generic control implemented when the matching key is set', () => {
      const t = makeThreat({
        id: 't-x',
        name: 'X',
        controls: [
          { id: 'ctrl-x-1', description: 'Step one' },
          { id: 'ctrl-x-2', description: 'Step two' },
        ],
      });
      const at = makeActiveThreat(t, { sourceNodeId: 'n1' });
      const key = buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't-x' }, 'Step one');
      const hcl = generateThreatclDocument(
        'M',
        [makeNode('n1', 'Host', { sensitivity: 'confidential' })],
        [],
        [at],
        [],
        { [key]: true },
      );
      expect(implementedFlagsFor(hcl, 'X')).toEqual([true, false]);
    });

    it('AND-resolves a node-generic control across multiple contributors', () => {
      const shared = makeThreat({
        id: 't-shared',
        name: 'Shared',
        controls: [{ id: 'ctrl-shared-1', description: 'Mitigate it' }],
      });
      const nodes = [
        makeNode('n1', 'Host A', { sensitivity: 'confidential' }),
        makeNode('n2', 'Host B', { sensitivity: 'confidential' }),
      ];
      const threats = [
        makeActiveThreat(shared, { sourceNodeId: 'n1', sourceTechName: 'Host A' }),
        makeActiveThreat(shared, { sourceNodeId: 'n2', sourceTechName: 'Host B' }),
      ];

      // Only n1 is ticked — overall result must be false (one contributor unticked).
      const oneTicked = {
        [buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't-shared' }, 'Mitigate it')]: true as const,
      };
      const hclPartial = generateThreatclDocument('M', nodes, [], threats, [], oneTicked);
      expect(implementedFlagsFor(hclPartial, 'Shared')).toEqual([false]);

      // Both ticked — overall result must be true.
      const bothTicked = {
        ...oneTicked,
        [buildControlKey({ kind: 'node-generic', nodeId: 'n2', threatId: 't-shared' }, 'Mitigate it')]: true as const,
      };
      const hclFull = generateThreatclDocument('M', nodes, [], threats, [], bothTicked);
      expect(implementedFlagsFor(hclFull, 'Shared')).toEqual([true]);
    });

    it('AND-resolves a node-tech control across contributors that supply the same mitigation', () => {
      const t = makeThreat({
        id: 't-tech',
        name: 'TechThreat',
        controls: [{ id: 'ctrl-tech-1', description: 'Generic fallback' }],
      });
      const nodes = [
        makeNode('n1', 'Host A', { sensitivity: 'confidential' }),
        makeNode('n2', 'Host B', { sensitivity: 'confidential' }),
      ];
      const threats = [
        makeActiveThreat(t, {
          sourceNodeId: 'n1',
          sourceTechName: 'Host A',
          techMitigations: ['Enable IMDSv2'],
        }),
        makeActiveThreat(t, {
          sourceNodeId: 'n2',
          sourceTechName: 'Host B',
          techMitigations: ['Enable IMDSv2'],
        }),
      ];

      const onlyOne = {
        [buildControlKey({ kind: 'node-tech', nodeId: 'n1', threatId: 't-tech' }, 'Enable IMDSv2')]: true as const,
      };
      const hclPartial = generateThreatclDocument('M', nodes, [], threats, [], onlyOne);
      expect(implementedFlagsFor(hclPartial, 'TechThreat')).toEqual([false]);

      const both = {
        ...onlyOne,
        [buildControlKey({ kind: 'node-tech', nodeId: 'n2', threatId: 't-tech' }, 'Enable IMDSv2')]: true as const,
      };
      const hclFull = generateThreatclDocument('M', nodes, [], threats, [], both);
      expect(implementedFlagsFor(hclFull, 'TechThreat')).toEqual([true]);
    });

    it('marks a connection control implemented from a single connection-scoped key', () => {
      const mitm = makeThreat({
        id: 't-mitm',
        name: 'MitM',
        isConnectionThreat: true,
        controls: [{ id: 'ctrl-mitm-1', description: 'Enforce TLS' }],
      });
      const at = makeActiveThreat(mitm, {
        sourceNodeId: 'n1',
        isConnectionThreat: true,
        connectionInfo: {
          edgeId: 'e1',
          sourceNodeName: 'A',
          targetNodeName: 'B',
          label: 'HTTPS',
        },
      });
      const nodes = [
        makeNode('n1', 'A', { sensitivity: 'confidential' }),
        makeNode('n2', 'B', { sensitivity: 'confidential' }),
      ];
      const edges = [makeEdge('e1', 'n1', 'n2', 'HTTPS')];
      const key = buildControlKey({ kind: 'connection', threatId: 't-mitm' }, 'Enforce TLS');

      const hcl = generateThreatclDocument('M', nodes, edges, [at], [], { [key]: true });
      expect(implementedFlagsFor(hcl, 'MitM')).toEqual([true]);
    });

    it('ignores stale keys whose description hash no longer matches any control', () => {
      const t = makeThreat({
        id: 't-x',
        name: 'X',
        controls: [{ id: 'ctrl-x-1', description: 'Current control text' }],
      });
      const at = makeActiveThreat(t, { sourceNodeId: 'n1' });
      const staleKey = buildControlKey(
        { kind: 'node-generic', nodeId: 'n1', threatId: 't-x' },
        'A different, no-longer-present control text',
      );
      const hcl = generateThreatclDocument(
        'M',
        [makeNode('n1', 'Host', { sensitivity: 'confidential' })],
        [],
        [at],
        [],
        { [staleKey]: true },
      );
      // The current control should remain unimplemented; the stale tick is dropped on the floor.
      expect(implementedFlagsFor(hcl, 'X')).toEqual([false]);
    });
  });
});

// --- optional integration test against the real threatcl binary --------------

// Runs only when THREATCL_BIN points at an executable threatcl CLI. This lets
// CI (and the developer locally) spot-check that our output is accepted by the
// authoritative parser without making the test suite itself depend on Go.
const threatclBin = process.env.THREATCL_BIN;
const describeIfBin = threatclBin && existsSync(threatclBin) ? describe : describe.skip;

describeIfBin('threatcl binary validation', () => {
  it('validates the representative model', () => {
    const { nodes, edges, boundaries, activeThreats } = buildRepresentativeModel();
    const hcl = generateThreatclDocument(
      'Integration Model',
      nodes,
      edges,
      activeThreats,
      boundaries,
    );

    const dir = mkdtempSync(join(tmpdir(), 'threatcl-test-'));
    const file = join(dir, 'model.hcl');
    writeFileSync(file, hcl);

    const output = execFileSync(threatclBin!, ['validate', file], { encoding: 'utf8' });
    expect(output).toMatch(/Validated 1 threatmodels/);
  });

  it('validates a minimal empty-ish model', () => {
    const hcl = generateThreatclDocument('Minimal', [makeNode('a', 'A')], [], [], []);
    const dir = mkdtempSync(join(tmpdir(), 'threatcl-test-'));
    const file = join(dir, 'model.hcl');
    writeFileSync(file, hcl);
    const output = execFileSync(threatclBin!, ['validate', file], { encoding: 'utf8' });
    expect(output).toMatch(/Validated 1 threatmodels/);
  });
});
