import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PathwayMitigationSettings, Technology } from '../data/schema';

// Mock getTechnologyById so getUpstreamMitigations can resolve display names
// without loading any real provider data files.
vi.mock('../data', () => ({
  getTechnologyById: vi.fn(),
}));

import { getTechnologyById } from '../data';
import {
  findUpstreamNodes,
  getUpstreamMitigations,
  checkPathwayMitigation,
  applyPathwayReduction,
  precomputeUpstreamMitigations,
  type UpstreamMitigation,
} from './pathwayMitigations';

const stubTech = (id: string, name: string): Technology => ({
  id,
  name,
  provider: 'aws',
  category: 'networking',
  description: '',
  threatIds: [],
});

// Build a PathwayMitigationSettings with a specific mitigation enabled in the
// mode requested. Anything not named stays disabled.
function buildSettings(
  enabledMitigations: Partial<Record<
    'ddos-protection' | 'waf-protection' | 'rate-limiting' | 'network-firewall',
    { mode: 'remove' | 'reduce'; reductionPercent?: number }
  >>,
  masterEnabled = true,
): PathwayMitigationSettings {
  return {
    enabled: masterEnabled,
    mitigations: {
      'ddos-protection': {
        enabled: !!enabledMitigations['ddos-protection'],
        mode: enabledMitigations['ddos-protection']?.mode ?? 'reduce',
        reductionPercent: enabledMitigations['ddos-protection']?.reductionPercent ?? 50,
      },
      'waf-protection': {
        enabled: !!enabledMitigations['waf-protection'],
        mode: enabledMitigations['waf-protection']?.mode ?? 'remove',
        reductionPercent: enabledMitigations['waf-protection']?.reductionPercent ?? 50,
      },
      'rate-limiting': {
        enabled: !!enabledMitigations['rate-limiting'],
        mode: enabledMitigations['rate-limiting']?.mode ?? 'reduce',
        reductionPercent: enabledMitigations['rate-limiting']?.reductionPercent ?? 30,
      },
      'network-firewall': {
        enabled: !!enabledMitigations['network-firewall'],
        mode: enabledMitigations['network-firewall']?.mode ?? 'reduce',
        reductionPercent: enabledMitigations['network-firewall']?.reductionPercent ?? 40,
      },
    },
  };
}

beforeEach(() => {
  vi.mocked(getTechnologyById).mockReset();
});

describe('findUpstreamNodes', () => {
  it('returns an empty array when the node has no inbound edges', () => {
    expect(findUpstreamNodes('a', [])).toEqual([]);
  });

  it('finds a single direct predecessor', () => {
    // a → b: b's upstream is [a]
    expect(findUpstreamNodes('b', [{ id: 'e1', source: 'a', target: 'b' }])).toEqual(['a']);
  });

  it('traverses multi-hop chains (a → b → c → d)', () => {
    const edges = [
      { id: 'e1', source: 'a', target: 'b' },
      { id: 'e2', source: 'b', target: 'c' },
      { id: 'e3', source: 'c', target: 'd' },
    ];
    const upstream = findUpstreamNodes('d', edges);
    expect(new Set(upstream)).toEqual(new Set(['a', 'b', 'c']));
  });

  it('handles diamond/converging patterns without visiting nodes twice', () => {
    // a → b, a → c, b → d, c → d
    const edges = [
      { id: 'e1', source: 'a', target: 'b' },
      { id: 'e2', source: 'a', target: 'c' },
      { id: 'e3', source: 'b', target: 'd' },
      { id: 'e4', source: 'c', target: 'd' },
    ];
    const upstream = findUpstreamNodes('d', edges);
    // 'a' should appear exactly once despite two paths reaching d
    expect(upstream.filter(n => n === 'a').length).toBe(1);
    expect(new Set(upstream)).toEqual(new Set(['a', 'b', 'c']));
  });

  it('terminates on cycles without infinite looping', () => {
    // a → b → c → a
    const edges = [
      { id: 'e1', source: 'a', target: 'b' },
      { id: 'e2', source: 'b', target: 'c' },
      { id: 'e3', source: 'c', target: 'a' },
    ];
    const upstream = findUpstreamNodes('c', edges);
    expect(new Set(upstream)).toEqual(new Set(['a', 'b']));
  });

  it('does not include the start node itself', () => {
    const edges = [
      { id: 'e1', source: 'a', target: 'b' },
      { id: 'e2', source: 'b', target: 'a' }, // cycle back
    ];
    expect(findUpstreamNodes('a', edges)).not.toContain('a');
  });

  it('ignores downstream-only edges', () => {
    // a → b, a → c: a has no upstream
    const edges = [
      { id: 'e1', source: 'a', target: 'b' },
      { id: 'e2', source: 'a', target: 'c' },
    ];
    expect(findUpstreamNodes('a', edges)).toEqual([]);
  });
});

describe('getUpstreamMitigations', () => {
  it('returns an empty array when no upstream nodes provide mitigations', () => {
    vi.mocked(getTechnologyById).mockReturnValue(stubTech('custom-x', 'Custom'));
    const nodeToTechId = new Map([
      ['upstream', 'custom-x'], // not in TECHNOLOGY_MITIGATION_CAPABILITIES
      ['target', 'custom-y'],
    ]);
    const edges = [{ id: 'e1', source: 'upstream', target: 'target' }];
    expect(getUpstreamMitigations('target', edges, nodeToTechId)).toEqual([]);
  });

  it('returns a single mitigation for a single capable upstream node', () => {
    vi.mocked(getTechnologyById).mockImplementation(id =>
      id === 'aws-waf' ? stubTech('aws-waf', 'AWS WAF') : undefined,
    );
    const nodeToTechId = new Map([
      ['n-waf', 'aws-waf'],
      ['n-app', 'aws-ec2'],
    ]);
    const edges = [{ id: 'e1', source: 'n-waf', target: 'n-app' }];
    const mitigations = getUpstreamMitigations('n-app', edges, nodeToTechId);
    expect(mitigations).toEqual([
      { mitigationType: 'waf-protection', techId: 'aws-waf', techName: 'AWS WAF' },
    ]);
  });

  it('returns multiple mitigations when a single upstream tech has multiple capabilities', () => {
    // saas-cloudflare provides BOTH ddos-protection AND waf-protection
    vi.mocked(getTechnologyById).mockImplementation(id =>
      id === 'saas-cloudflare' ? stubTech('saas-cloudflare', 'CloudFlare') : undefined,
    );
    const nodeToTechId = new Map([
      ['n-cf', 'saas-cloudflare'],
      ['n-app', 'aws-ec2'],
    ]);
    const edges = [{ id: 'e1', source: 'n-cf', target: 'n-app' }];
    const mitigations = getUpstreamMitigations('n-app', edges, nodeToTechId);
    expect(mitigations.map(m => m.mitigationType).sort()).toEqual([
      'ddos-protection',
      'waf-protection',
    ]);
    expect(mitigations.every(m => m.techId === 'saas-cloudflare')).toBe(true);
  });

  it('collects mitigations across multiple upstream nodes in a chain', () => {
    vi.mocked(getTechnologyById).mockImplementation(id => stubTech(id, id));
    // n-cf → n-waf → n-app. Both upstreams provide mitigations.
    const nodeToTechId = new Map([
      ['n-cf', 'saas-cloudflare'], // ddos + waf
      ['n-waf', 'aws-waf'],        // waf
      ['n-app', 'aws-ec2'],
    ]);
    const edges = [
      { id: 'e1', source: 'n-cf', target: 'n-waf' },
      { id: 'e2', source: 'n-waf', target: 'n-app' },
    ];
    const mitigations = getUpstreamMitigations('n-app', edges, nodeToTechId);
    // 3 total: ddos+waf from cloudflare, waf from aws-waf
    expect(mitigations.length).toBe(3);
    expect(mitigations.map(m => m.techId).sort()).toEqual(['aws-waf', 'saas-cloudflare', 'saas-cloudflare']);
  });
});

describe('checkPathwayMitigation', () => {
  it('returns not mitigated when the master toggle is off', () => {
    const settings = buildSettings({ 'waf-protection': { mode: 'remove' } }, false);
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'waf-protection', techId: 'aws-waf', techName: 'AWS WAF' },
    ];
    expect(checkPathwayMitigation('injection-attack', upstream, settings).isMitigated).toBe(false);
  });

  it('returns not mitigated when the matching mitigation type is disabled', () => {
    const settings = buildSettings({});
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'waf-protection', techId: 'aws-waf', techName: 'AWS WAF' },
    ];
    expect(checkPathwayMitigation('injection-attack', upstream, settings).isMitigated).toBe(false);
  });

  it('returns mitigated with mode=remove when a matching mitigation is configured to remove', () => {
    const settings = buildSettings({ 'waf-protection': { mode: 'remove' } });
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'waf-protection', techId: 'aws-waf', techName: 'AWS WAF' },
    ];
    const result = checkPathwayMitigation('injection-attack', upstream, settings);
    expect(result.isMitigated).toBe(true);
    expect(result.mode).toBe('remove');
    expect(result.mitigationType).toBe('waf-protection');
    expect(result.mitigatingTechId).toBe('aws-waf');
    expect(result.mitigatingTechName).toBe('AWS WAF');
  });

  it('returns mitigated with mode=reduce and surfaces the reductionPercent', () => {
    const settings = buildSettings({
      'ddos-protection': { mode: 'reduce', reductionPercent: 60 },
    });
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'ddos-protection', techId: 'aws-cloudfront', techName: 'CloudFront' },
    ];
    const result = checkPathwayMitigation('dos-attack', upstream, settings);
    expect(result.isMitigated).toBe(true);
    expect(result.mode).toBe('reduce');
    expect(result.reductionPercent).toBe(60);
  });

  it('leaves reductionPercent undefined when mode is remove', () => {
    const settings = buildSettings({ 'waf-protection': { mode: 'remove' } });
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'waf-protection', techId: 'aws-waf', techName: 'AWS WAF' },
    ];
    const result = checkPathwayMitigation('injection-attack', upstream, settings);
    expect(result.reductionPercent).toBeUndefined();
  });

  it('returns not mitigated when upstream mitigations do not target the threat', () => {
    const settings = buildSettings({ 'network-firewall': { mode: 'reduce' } });
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'network-firewall', techId: 'aws-network-firewall', techName: 'Network Firewall' },
    ];
    // network-firewall mitigates lateral-movement / unauthorized-access, NOT injection-attack
    expect(checkPathwayMitigation('injection-attack', upstream, settings).isMitigated).toBe(false);
  });

  it('uses the first matching mitigation when multiple upstream mitigations could apply', () => {
    const settings = buildSettings({
      'ddos-protection': { mode: 'reduce', reductionPercent: 50 },
      'rate-limiting': { mode: 'reduce', reductionPercent: 30 },
    });
    // Both mitigate dos-attack. The implementation walks the upstream list in
    // order and returns on the first hit — here, ddos-protection wins.
    const upstream: UpstreamMitigation[] = [
      { mitigationType: 'ddos-protection', techId: 'aws-cloudfront', techName: 'CloudFront' },
      { mitigationType: 'rate-limiting', techId: 'aws-api-gateway', techName: 'API Gateway' },
    ];
    const result = checkPathwayMitigation('dos-attack', upstream, settings);
    expect(result.mitigationType).toBe('ddos-protection');
  });
});

describe('applyPathwayReduction', () => {
  it('returns a reduced, floored score', () => {
    // 10 × (1 - 0.5) = 5
    expect(applyPathwayReduction(10, 50)).toBe(5);
  });

  it('floors fractional results rather than rounding', () => {
    // 10 - (10 * 0.3) = 7.0 → floor → 7
    // 11 - (11 * 0.3) = 7.7 → floor → 7
    expect(applyPathwayReduction(11, 30)).toBe(7);
  });

  it('returns the base score unchanged when reduction is zero', () => {
    expect(applyPathwayReduction(9, 0)).toBe(9);
  });

  it('clamps to a minimum of 1 even under a 100% reduction', () => {
    expect(applyPathwayReduction(16, 100)).toBe(1);
  });

  it('clamps to a minimum of 1 when the reduction would produce 0', () => {
    // Edge case: base score 1 × 50% reduction = 0.5 → floor = 0 → clamped to 1
    expect(applyPathwayReduction(1, 50)).toBe(1);
  });
});

describe('precomputeUpstreamMitigations', () => {
  it('returns an entry for every node, even when it has no upstream mitigations', () => {
    vi.mocked(getTechnologyById).mockReturnValue(undefined);
    const nodes = [
      { id: 'a', technologyId: 'aws-ec2' },
      { id: 'b', technologyId: 'aws-s3' },
    ];
    const result = precomputeUpstreamMitigations(nodes, []);
    expect(result.size).toBe(2);
    expect(result.get('a')).toEqual([]);
    expect(result.get('b')).toEqual([]);
  });

  it('populates the upstream mitigations for each node', () => {
    vi.mocked(getTechnologyById).mockImplementation(id => stubTech(id, id));
    const nodes = [
      { id: 'n-waf', technologyId: 'aws-waf' },
      { id: 'n-app', technologyId: 'aws-ec2' },
    ];
    const edges = [{ id: 'e1', source: 'n-waf', target: 'n-app' }];
    const result = precomputeUpstreamMitigations(nodes, edges);
    expect(result.get('n-waf')).toEqual([]);
    expect(result.get('n-app')).toEqual([
      { mitigationType: 'waf-protection', techId: 'aws-waf', techName: 'aws-waf' },
    ]);
  });

  it('handles a graph where no node has any mitigation capability', () => {
    vi.mocked(getTechnologyById).mockReturnValue(undefined);
    const nodes = [
      { id: 'a', technologyId: 'aws-ec2' },
      { id: 'b', technologyId: 'aws-rds' },
    ];
    const edges = [{ id: 'e1', source: 'a', target: 'b' }];
    const result = precomputeUpstreamMitigations(nodes, edges);
    expect(result.get('a')).toEqual([]);
    expect(result.get('b')).toEqual([]);
  });

  it('deduplicates by traversal — each mitigation appears once per distinct upstream contributor', () => {
    vi.mocked(getTechnologyById).mockImplementation(id => stubTech(id, id));
    // Diamond: cf → waf, cf → app, waf → app
    const nodes = [
      { id: 'n-cf', technologyId: 'saas-cloudflare' },
      { id: 'n-waf', technologyId: 'aws-waf' },
      { id: 'n-app', technologyId: 'aws-ec2' },
    ];
    const edges = [
      { id: 'e1', source: 'n-cf', target: 'n-waf' },
      { id: 'e2', source: 'n-cf', target: 'n-app' },
      { id: 'e3', source: 'n-waf', target: 'n-app' },
    ];
    const result = precomputeUpstreamMitigations(nodes, edges);
    const appMitigations = result.get('n-app')!;
    // Cloudflare appears once (BFS visited-set dedupe), contributing ddos+waf;
    // aws-waf appears once, contributing waf. Total: 3.
    expect(appMitigations.length).toBe(3);
    const cfCount = appMitigations.filter(m => m.techId === 'saas-cloudflare').length;
    expect(cfCount).toBe(2); // ddos + waf from the same tech
  });
});
