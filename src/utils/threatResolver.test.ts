import { describe, it, expect, vi, beforeEach } from 'vitest';
import type {
  ActiveThreat,
  Technology,
  Threat,
  PathwayMitigationSettings,
  DataSensitivity,
} from '../data/schema';
import { DEFAULT_PATHWAY_MITIGATION_SETTINGS } from '../data/schema';

// Mock the data layer so we can fully control which threats/technologies
// the resolver sees, without depending on real JSON fixtures.
vi.mock('../data', () => ({
  getTechnologyById: vi.fn(),
  getThreatsForTechnology: vi.fn(),
  getConnectionThreats: vi.fn(),
  getZoneThreats: vi.fn(),
}));

import {
  getTechnologyById,
  getThreatsForTechnology,
  getConnectionThreats,
  getZoneThreats,
} from '../data';
import {
  resolveActiveThreats,
  groupThreatsByTechnology,
  getUniqueThreatCount,
  type DiagramNode,
  type DiagramEdge,
  type DiagramBoundary,
} from './threatResolver';

// --- fixture helpers --------------------------------------------------------

const makeTech = (overrides: Partial<Technology> = {}): Technology => ({
  id: 'aws-ec2',
  name: 'EC2',
  provider: 'aws',
  category: 'compute',
  description: '',
  threatIds: [],
  ...overrides,
});

const makeThreat = (overrides: Partial<Threat> = {}): Threat => ({
  id: 't-generic',
  name: 'Generic Threat',
  description: 'A generic threat',
  severity: 'medium',
  stride: ['tampering'],
  mitreTechniques: [],
  controls: [{ id: 'ctrl-1', description: 'Do the thing' }],
  ...overrides,
});

const makeNode = (
  id: string,
  technologyId: string,
  sensitivity: DataSensitivity = 'internal',
  opts: { customName?: string; threatsDisabled?: boolean; parentId?: string } = {},
): DiagramNode => ({
  id,
  parentId: opts.parentId,
  data: {
    technologyId,
    sensitivity,
    customName: opts.customName,
    threatsDisabled: opts.threatsDisabled,
  },
});

const makeEdge = (id: string, source: string, target: string, label?: string): DiagramEdge => ({
  id,
  source,
  target,
  data: label ? { label } : undefined,
});

// --- test setup ------------------------------------------------------------

beforeEach(() => {
  vi.mocked(getTechnologyById).mockReset();
  vi.mocked(getThreatsForTechnology).mockReset();
  vi.mocked(getConnectionThreats).mockReset().mockReturnValue([]);
  vi.mocked(getZoneThreats).mockReset().mockReturnValue([]);
});

// --- tests -----------------------------------------------------------------

describe('resolveActiveThreats', () => {
  it('returns no threats for an empty diagram', () => {
    expect(resolveActiveThreats([], [], [])).toEqual([]);
  });

  it('resolves a single component threat from a single tech node', () => {
    const tech = makeTech();
    const threat = makeThreat({ id: 't-1', severity: 'high' });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([threat]);

    const result = resolveActiveThreats([makeNode('n1', 'aws-ec2', 'confidential')]);
    expect(result).toHaveLength(1);
    expect(result[0].threat.id).toBe('t-1');
    expect(result[0].sourceNodeId).toBe('n1');
    expect(result[0].sourceTechName).toBe('EC2');
    expect(result[0].sensitivity).toBe('confidential');
    // high (3) × confidential (3) = 9 → high
    expect(result[0].riskScore).toBe(9);
    expect(result[0].riskLevel).toBe('high');
  });

  it('skips nodes whose technology cannot be resolved', () => {
    vi.mocked(getTechnologyById).mockReturnValue(undefined);
    vi.mocked(getThreatsForTechnology).mockReturnValue([makeThreat()]);

    expect(resolveActiveThreats([makeNode('n1', 'missing')])).toEqual([]);
  });

  it('skips nodes with threatsDisabled flag set', () => {
    vi.mocked(getTechnologyById).mockReturnValue(makeTech());
    vi.mocked(getThreatsForTechnology).mockReturnValue([makeThreat()]);

    const result = resolveActiveThreats([
      makeNode('n1', 'aws-ec2', 'internal', { threatsDisabled: true }),
    ]);
    expect(result).toEqual([]);
  });

  it('uses a custom name in sourceTechName when provided', () => {
    vi.mocked(getTechnologyById).mockReturnValue(makeTech());
    vi.mocked(getThreatsForTechnology).mockReturnValue([makeThreat()]);

    const result = resolveActiveThreats([
      makeNode('n1', 'aws-ec2', 'internal', { customName: 'Prod DB' }),
    ]);
    expect(result[0].sourceTechName).toBe('Prod DB');
  });

  it('resolves connection threats for every edge', () => {
    const tech = makeTech();
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([]); // No component threats
    vi.mocked(getConnectionThreats).mockReturnValue([
      makeThreat({ id: 'connection-mitm', isConnectionThreat: true, severity: 'high' }),
    ]);

    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-ec2', 'public'), makeNode('n2', 'aws-ec2', 'confidential')],
      [makeEdge('e1', 'n1', 'n2', 'HTTPS')],
    );
    expect(result).toHaveLength(1);
    expect(result[0].isConnectionThreat).toBe(true);
    expect(result[0].connectionInfo?.edgeId).toBe('e1');
    expect(result[0].connectionInfo?.label).toBe('HTTPS');
    // Connection sensitivity is the higher of the two endpoints → confidential
    expect(result[0].sensitivity).toBe('confidential');
  });

  it('skips connection threats when either endpoint has threats disabled', () => {
    vi.mocked(getTechnologyById).mockReturnValue(makeTech());
    vi.mocked(getThreatsForTechnology).mockReturnValue([]);
    vi.mocked(getConnectionThreats).mockReturnValue([
      makeThreat({ id: 'connection-mitm', isConnectionThreat: true }),
    ]);

    const result = resolveActiveThreats(
      [
        makeNode('n1', 'aws-ec2'),
        makeNode('n2', 'aws-ec2', 'internal', { threatsDisabled: true }),
      ],
      [makeEdge('e1', 'n1', 'n2')],
    );
    expect(result).toEqual([]);
  });

  it('marks connection threats mitigated by TLS-enforcing endpoints', () => {
    const plain = makeTech({ id: 'aws-ec2' });
    const tlsEnforcing = makeTech({
      id: 'aws-api-gateway',
      name: 'API Gateway',
      connectionSecurity: { enforcesEncryption: true },
    });
    vi.mocked(getTechnologyById).mockImplementation(id =>
      id === 'aws-api-gateway' ? tlsEnforcing : plain,
    );
    vi.mocked(getThreatsForTechnology).mockReturnValue([]);
    vi.mocked(getConnectionThreats).mockReturnValue([
      makeThreat({ id: 'connection-mitm', isConnectionThreat: true, severity: 'high' }),
      makeThreat({ id: 'connection-data-exposure', isConnectionThreat: true, severity: 'high' }),
      makeThreat({ id: 'connection-other', isConnectionThreat: true, severity: 'high' }),
    ]);

    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-api-gateway'), makeNode('n2', 'aws-ec2')],
      [makeEdge('e1', 'n1', 'n2')],
    );
    const mitm = result.find(r => r.threat.id === 'connection-mitm');
    const expose = result.find(r => r.threat.id === 'connection-data-exposure');
    const other = result.find(r => r.threat.id === 'connection-other');
    expect(mitm?.mitigatedBy).toBe('encrypted');
    expect(expose?.mitigatedBy).toBe('encrypted');
    expect(other?.mitigatedBy).toBeUndefined();
  });

  it('escalates pathway-threat risk based on max downstream sensitivity', () => {
    const tech = makeTech();
    const pathway = makeThreat({
      id: 't-pathway',
      severity: 'medium',
      isPathwayThreat: true,
    });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([pathway]);

    // Source node is 'public'; downstream is 'restricted'
    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-ec2', 'public'), makeNode('n2', 'aws-ec2', 'restricted')],
      [makeEdge('e1', 'n1', 'n2')],
    );
    const pathwayThreat = result.find(r => r.sourceNodeId === 'n1' && r.threat.id === 't-pathway');
    // Source sensitivity still public, but effectiveSensitivity bumped to restricted
    expect(pathwayThreat?.isEscalated).toBe(true);
    expect(pathwayThreat?.effectiveSensitivity).toBe('restricted');
    // Score uses the escalated sensitivity: medium (2) × restricted (4) = 8
    expect(pathwayThreat?.riskScore).toBe(8);
  });

  it('does NOT escalate non-pathway threats based on downstream sensitivity', () => {
    const tech = makeTech();
    const nonPathway = makeThreat({ id: 't-normal', severity: 'medium' });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([nonPathway]);

    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-ec2', 'public'), makeNode('n2', 'aws-ec2', 'restricted')],
      [makeEdge('e1', 'n1', 'n2')],
    );
    const threat = result.find(r => r.sourceNodeId === 'n1');
    expect(threat?.isEscalated).toBeFalsy();
    // medium (2) × public (1) = 2
    expect(threat?.riskScore).toBe(2);
  });

  it('applies private zone boundary multiplier to component threats', () => {
    const tech = makeTech();
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([
      makeThreat({ id: 't-1', severity: 'critical' }),
    ]);

    const boundaries: DiagramBoundary[] = [
      { id: 'z1', zoneType: 'private', riskReductionPercent: 50 },
    ];
    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-ec2', 'restricted', { parentId: 'z1' })],
      [],
      boundaries,
    );
    // critical (4) × restricted (4) = 16, then 50% reduction = 8
    expect(result[0].riskScore).toBe(8);
    expect(result[0].zoneMultiplier).toBeCloseTo(0.5);
  });

  it('applies boundary reduction to connection threats only when both endpoints are in private zones', () => {
    const tech = makeTech();
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([]);
    vi.mocked(getConnectionThreats).mockReturnValue([
      makeThreat({ id: 'connection-other', isConnectionThreat: true, severity: 'critical' }),
    ]);

    const boundaries: DiagramBoundary[] = [
      { id: 'z1', zoneType: 'private', riskReductionPercent: 30 },
      { id: 'z2', zoneType: 'private', riskReductionPercent: 50 },
    ];
    // Both endpoints inside private zones with different percents — use lower (30%)
    const result = resolveActiveThreats(
      [
        makeNode('n1', 'aws-ec2', 'restricted', { parentId: 'z1' }),
        makeNode('n2', 'aws-ec2', 'restricted', { parentId: 'z2' }),
      ],
      [makeEdge('e1', 'n1', 'n2')],
      boundaries,
    );
    // critical (4) × restricted (4) = 16, then 30% reduction = 11
    expect(result[0].riskScore).toBe(11);
    expect(result[0].zoneMultiplier).toBeCloseTo(0.7);
  });

  it('does NOT apply boundary reduction when only one connection endpoint is in a private zone', () => {
    const tech = makeTech();
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([]);
    vi.mocked(getConnectionThreats).mockReturnValue([
      makeThreat({ id: 'connection-other', isConnectionThreat: true, severity: 'critical' }),
    ]);

    const boundaries: DiagramBoundary[] = [
      { id: 'z1', zoneType: 'private', riskReductionPercent: 30 },
    ];
    const result = resolveActiveThreats(
      [
        makeNode('n1', 'aws-ec2', 'restricted', { parentId: 'z1' }),
        makeNode('n2', 'aws-ec2', 'restricted'), // outside any zone
      ],
      [makeEdge('e1', 'n1', 'n2')],
      boundaries,
    );
    // Full 16 (no reduction applied)
    expect(result[0].riskScore).toBe(16);
    expect(result[0].zoneMultiplier).toBeUndefined();
  });

  it('emits a zone threat per private boundary with default 20% reduction', () => {
    vi.mocked(getTechnologyById).mockReturnValue(undefined);
    vi.mocked(getThreatsForTechnology).mockReturnValue([]);
    vi.mocked(getZoneThreats).mockReturnValue([
      makeThreat({ id: 'zone-1', severity: 'medium', isZoneThreat: true }),
    ]);

    const boundaries: DiagramBoundary[] = [
      { id: 'z1', zoneType: 'private', customName: 'Prod VPC' },
      { id: 'z2', zoneType: 'public' }, // should NOT emit a zone threat
    ];
    const result = resolveActiveThreats([], [], boundaries);
    expect(result).toHaveLength(1);
    expect(result[0].isZoneThreat).toBe(true);
    expect(result[0].zoneInfo?.boundaryId).toBe('z1');
    expect(result[0].zoneInfo?.zoneName).toBe('Prod VPC');
    // medium (2) × internal (2) = 4, then 20% reduction = 3.2 → round → 3
    expect(result[0].riskScore).toBe(3);
  });

  it('deduplicates: a threat seen twice on the same node is emitted only once', () => {
    const tech = makeTech();
    const threat = makeThreat({ id: 't-dup' });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    // Return the same threat twice — resolver keys by threatId+nodeId and should dedupe
    vi.mocked(getThreatsForTechnology).mockReturnValue([threat, threat]);

    const result = resolveActiveThreats([makeNode('n1', 'aws-ec2')]);
    expect(result).toHaveLength(1);
  });

  it('filters out threats whose final risk score drops to zero', () => {
    const tech = makeTech();
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([
      makeThreat({ id: 't-low', severity: 'low' }),
    ]);
    const boundaries: DiagramBoundary[] = [
      { id: 'z1', zoneType: 'private', riskReductionPercent: 100 },
    ];
    // low (1) × public (1) = 1, then 100% reduction = 0 → filtered
    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-ec2', 'public', { parentId: 'z1' })],
      [],
      boundaries,
    );
    expect(result).toEqual([]);
  });

  it('attaches technology-specific threatContext when available', () => {
    const tech = makeTech({
      threatContext: { 't-1': 'Instance metadata service credential theft' },
    });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([makeThreat({ id: 't-1' })]);

    const result = resolveActiveThreats([makeNode('n1', 'aws-ec2', 'confidential')]);
    expect(result[0].context).toBe('Instance metadata service credential theft');
  });

  it('attaches technology-specific threatMitigations when available', () => {
    const tech = makeTech({
      threatMitigations: { 't-1': ['Enforce IMDSv2', 'Use IAM roles'] },
    });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([makeThreat({ id: 't-1' })]);

    const result = resolveActiveThreats([makeNode('n1', 'aws-ec2', 'confidential')]);
    expect(result[0].techMitigations).toEqual(['Enforce IMDSv2', 'Use IAM roles']);
  });

  it('applies a severity override via the component override key', () => {
    const tech = makeTech({ id: 'aws-ec2' });
    vi.mocked(getTechnologyById).mockReturnValue(tech);
    vi.mocked(getThreatsForTechnology).mockReturnValue([
      makeThreat({ id: 't-1', severity: 'low' }),
    ]);

    const result = resolveActiveThreats(
      [makeNode('n1', 'aws-ec2', 'restricted')],
      [],
      [],
      DEFAULT_PATHWAY_MITIGATION_SETTINGS,
      { 'aws-ec2::t-1': 'critical' }, // override low → critical
    );
    expect(result[0].overriddenSeverity).toBe('critical');
    // critical (4) × restricted (4) = 16
    expect(result[0].riskScore).toBe(16);
  });

  it('removes a threat entirely when pathway mitigation mode is "remove"', () => {
    const tech = makeTech({ id: 'aws-ec2' });
    const wafTech = makeTech({ id: 'aws-waf', name: 'AWS WAF' });
    vi.mocked(getTechnologyById).mockImplementation(id => (id === 'aws-waf' ? wafTech : tech));
    vi.mocked(getThreatsForTechnology).mockImplementation(id =>
      id === 'aws-ec2'
        ? [makeThreat({ id: 'injection-attack', severity: 'high' })]
        : [],
    );

    const settings: PathwayMitigationSettings = {
      enabled: true,
      mitigations: {
        'ddos-protection': { enabled: false, mode: 'reduce', reductionPercent: 50 },
        'waf-protection': { enabled: true, mode: 'remove', reductionPercent: 50 },
        'rate-limiting': { enabled: false, mode: 'reduce', reductionPercent: 30 },
        'network-firewall': { enabled: false, mode: 'reduce', reductionPercent: 40 },
      },
    };
    const result = resolveActiveThreats(
      [makeNode('n-waf', 'aws-waf'), makeNode('n-app', 'aws-ec2', 'restricted')],
      [makeEdge('e1', 'n-waf', 'n-app')],
      [],
      settings,
    );
    // The WAF is upstream of the app; injection-attack mitigated in "remove" mode
    expect(result.find(r => r.threat.id === 'injection-attack')).toBeUndefined();
  });

  it('reduces (but does not remove) risk when pathway mitigation mode is "reduce"', () => {
    const tech = makeTech({ id: 'aws-ec2' });
    const cdnTech = makeTech({ id: 'aws-cloudfront', name: 'CloudFront' });
    vi.mocked(getTechnologyById).mockImplementation(id =>
      id === 'aws-cloudfront' ? cdnTech : tech,
    );
    vi.mocked(getThreatsForTechnology).mockImplementation(id =>
      id === 'aws-ec2' ? [makeThreat({ id: 'dos-attack', severity: 'critical' })] : [],
    );

    const settings: PathwayMitigationSettings = {
      enabled: true,
      mitigations: {
        'ddos-protection': { enabled: true, mode: 'reduce', reductionPercent: 50 },
        'waf-protection': { enabled: false, mode: 'remove', reductionPercent: 50 },
        'rate-limiting': { enabled: false, mode: 'reduce', reductionPercent: 30 },
        'network-firewall': { enabled: false, mode: 'reduce', reductionPercent: 40 },
      },
    };
    const result = resolveActiveThreats(
      [makeNode('n-cdn', 'aws-cloudfront'), makeNode('n-app', 'aws-ec2', 'restricted')],
      [makeEdge('e1', 'n-cdn', 'n-app')],
      [],
      settings,
    );
    const threat = result.find(r => r.threat.id === 'dos-attack');
    // critical (4) × restricted (4) = 16, reduce by 50% → 8
    expect(threat?.riskScore).toBe(8);
    expect(threat?.pathwayMitigatedBy?.mode).toBe('reduce');
    expect(threat?.pathwayMitigatedBy?.mitigatingTechId).toBe('aws-cloudfront');
  });
});

describe('groupThreatsByTechnology', () => {
  it('groups by sourceNodeId and includes the tech name', () => {
    const threat1 = makeThreat({ id: 't-1', name: 'T1' });
    const threat2 = makeThreat({ id: 't-2', name: 'T2' });
    const active: ActiveThreat[] = [
      { threat: threat1, sourceNodeId: 'n1', sourceTechName: 'EC2', sensitivity: 'internal', riskScore: 4, riskLevel: 'medium' },
      { threat: threat2, sourceNodeId: 'n1', sourceTechName: 'EC2', sensitivity: 'internal', riskScore: 4, riskLevel: 'medium' },
    ];
    const grouped = groupThreatsByTechnology(active);
    expect(grouped.size).toBe(1);
    expect(grouped.get('n1')?.techName).toBe('EC2');
    expect(grouped.get('n1')?.threats.map(t => t.id)).toEqual(['t-1', 't-2']);
  });

  it('does not double-count the same threat on the same node', () => {
    const threat = makeThreat({ id: 't-dup' });
    const active: ActiveThreat[] = [
      { threat, sourceNodeId: 'n1', sourceTechName: 'EC2', sensitivity: 'internal', riskScore: 4, riskLevel: 'medium' },
      { threat, sourceNodeId: 'n1', sourceTechName: 'EC2', sensitivity: 'internal', riskScore: 4, riskLevel: 'medium' },
    ];
    const grouped = groupThreatsByTechnology(active);
    expect(grouped.get('n1')?.threats.length).toBe(1);
  });

  it('flags connection groups with isConnection', () => {
    const threat = makeThreat({ id: 'connection-mitm', isConnectionThreat: true });
    const active: ActiveThreat[] = [
      {
        threat,
        sourceNodeId: 'e1',
        sourceTechName: 'A → B',
        sensitivity: 'internal',
        riskScore: 4,
        riskLevel: 'medium',
        isConnectionThreat: true,
      },
    ];
    expect(groupThreatsByTechnology(active).get('e1')?.isConnection).toBe(true);
  });
});

describe('getUniqueThreatCount', () => {
  it('returns the number of distinct threat IDs', () => {
    const active: ActiveThreat[] = [
      { threat: makeThreat({ id: 'a' }), sourceNodeId: 'n1', sourceTechName: 'X', sensitivity: 'internal', riskScore: 1, riskLevel: 'low' },
      { threat: makeThreat({ id: 'a' }), sourceNodeId: 'n2', sourceTechName: 'Y', sensitivity: 'internal', riskScore: 1, riskLevel: 'low' },
      { threat: makeThreat({ id: 'b' }), sourceNodeId: 'n1', sourceTechName: 'X', sensitivity: 'internal', riskScore: 1, riskLevel: 'low' },
    ];
    expect(getUniqueThreatCount(active)).toBe(2);
  });

  it('returns 0 for an empty list', () => {
    expect(getUniqueThreatCount([])).toBe(0);
  });
});
