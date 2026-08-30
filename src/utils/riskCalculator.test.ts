import { describe, it, expect } from 'vitest';
import {
  calculateRiskScore,
  getRiskLevel,
  getHigherSensitivity,
  getMaxDownstreamSensitivity,
  applyBoundaryMultiplier,
  getBoundaryMultiplier,
  getBoundaryReductionPercent,
  type BoundaryRiskData,
} from './riskCalculator';
import type { DataSensitivity } from '../data/schema';

describe('calculateRiskScore', () => {
  it('returns severity × sensitivity for all combinations', () => {
    // Lowest: low × public = 1
    expect(calculateRiskScore('low', 'public')).toBe(1);
    // Highest: critical × restricted = 16
    expect(calculateRiskScore('critical', 'restricted')).toBe(16);
  });

  it('produces the full 1–16 range across every pair', () => {
    const severities = ['low', 'medium', 'high', 'critical'] as const;
    const sensitivities: DataSensitivity[] = ['public', 'internal', 'confidential', 'restricted'];
    const scores = severities.flatMap(sev => sensitivities.map(sen => calculateRiskScore(sev, sen)));
    expect(Math.min(...scores)).toBe(1);
    expect(Math.max(...scores)).toBe(16);
  });

  it('multiplies the severity and sensitivity indices (medium × confidential = 6)', () => {
    // medium (2) × confidential (3) = 6
    expect(calculateRiskScore('medium', 'confidential')).toBe(6);
    // high (3) × internal (2) = 6
    expect(calculateRiskScore('high', 'internal')).toBe(6);
  });

  it('is commutative when the indices match (high × public == low × restricted... each is their own product)', () => {
    // high × public = 3; low × restricted = 4 — not commutative, just verifying the math holds
    expect(calculateRiskScore('high', 'public')).toBe(3);
    expect(calculateRiskScore('low', 'restricted')).toBe(4);
  });
});

describe('getRiskLevel', () => {
  it('maps scores 1–3 to low', () => {
    expect(getRiskLevel(1)).toBe('low');
    expect(getRiskLevel(3)).toBe('low');
  });

  it('maps scores 4–7 to medium (boundary 3→4)', () => {
    expect(getRiskLevel(4)).toBe('medium');
    expect(getRiskLevel(7)).toBe('medium');
  });

  it('maps scores 8–11 to high (boundary 7→8)', () => {
    expect(getRiskLevel(8)).toBe('high');
    expect(getRiskLevel(11)).toBe('high');
  });

  it('maps scores 12–16 to critical (boundary 11→12)', () => {
    expect(getRiskLevel(12)).toBe('critical');
    expect(getRiskLevel(16)).toBe('critical');
  });

  it('handles scores outside the canonical 1–16 range by extending the top and bottom bands', () => {
    expect(getRiskLevel(0)).toBe('low');
    expect(getRiskLevel(100)).toBe('critical');
  });
});

describe('getHigherSensitivity', () => {
  it('returns the higher-valued sensitivity', () => {
    expect(getHigherSensitivity('public', 'restricted')).toBe('restricted');
    expect(getHigherSensitivity('confidential', 'internal')).toBe('confidential');
  });

  it('returns either side when sensitivities are equal', () => {
    expect(getHigherSensitivity('confidential', 'confidential')).toBe('confidential');
  });

  it('is order-independent for distinct sensitivities', () => {
    expect(getHigherSensitivity('public', 'confidential')).toBe(
      getHigherSensitivity('confidential', 'public'),
    );
  });
});

describe('getMaxDownstreamSensitivity', () => {
  it('returns null when the node has no outgoing edges', () => {
    const sensitivityMap = new Map<string, DataSensitivity>([['a', 'public']]);
    expect(getMaxDownstreamSensitivity('a', [], sensitivityMap)).toBeNull();
  });

  it('returns null when outgoing edges point to nodes missing from the sensitivity map', () => {
    const sensitivityMap = new Map<string, DataSensitivity>([['a', 'public']]);
    const edges = [{ source: 'a', target: 'b' }];
    expect(getMaxDownstreamSensitivity('a', edges, sensitivityMap)).toBeNull();
  });

  it('returns the sensitivity of the single downstream node', () => {
    const sensitivityMap = new Map<string, DataSensitivity>([
      ['a', 'public'],
      ['b', 'confidential'],
    ]);
    const edges = [{ source: 'a', target: 'b' }];
    expect(getMaxDownstreamSensitivity('a', edges, sensitivityMap)).toBe('confidential');
  });

  it('returns the maximum across multiple downstream nodes', () => {
    const sensitivityMap = new Map<string, DataSensitivity>([
      ['a', 'public'],
      ['b', 'internal'],
      ['c', 'restricted'],
      ['d', 'confidential'],
    ]);
    const edges = [
      { source: 'a', target: 'b' },
      { source: 'a', target: 'c' },
      { source: 'a', target: 'd' },
    ];
    expect(getMaxDownstreamSensitivity('a', edges, sensitivityMap)).toBe('restricted');
  });

  it('ignores edges where the node is the target (inbound), not the source', () => {
    const sensitivityMap = new Map<string, DataSensitivity>([
      ['a', 'public'],
      ['b', 'restricted'],
    ]);
    // b → a: a has no outbound connection
    const edges = [{ source: 'b', target: 'a' }];
    expect(getMaxDownstreamSensitivity('a', edges, sensitivityMap)).toBeNull();
  });

  it('only inspects direct (one-hop) downstream neighbours', () => {
    // a → b → c: max downstream of a should be b's sensitivity, not c's
    const sensitivityMap = new Map<string, DataSensitivity>([
      ['a', 'public'],
      ['b', 'internal'],
      ['c', 'restricted'],
    ]);
    const edges = [
      { source: 'a', target: 'b' },
      { source: 'b', target: 'c' },
    ];
    expect(getMaxDownstreamSensitivity('a', edges, sensitivityMap)).toBe('internal');
  });
});

describe('getBoundaryMultiplier', () => {
  it('returns 1.0 when no boundary data is supplied', () => {
    expect(getBoundaryMultiplier(undefined)).toBe(1.0);
  });

  it('returns 1.0 for public zones regardless of reduction settings', () => {
    const boundary: BoundaryRiskData = {
      zoneType: 'public',
      riskReductionEnabled: true,
      riskReductionPercent: 50,
    };
    expect(getBoundaryMultiplier(boundary)).toBe(1.0);
  });

  it('returns 1.0 for private zones when reduction is explicitly disabled', () => {
    const boundary: BoundaryRiskData = {
      zoneType: 'private',
      riskReductionEnabled: false,
      riskReductionPercent: 50,
    };
    expect(getBoundaryMultiplier(boundary)).toBe(1.0);
  });

  it('defaults to a 20% reduction (multiplier 0.8) for private zones with no percent set', () => {
    const boundary: BoundaryRiskData = { zoneType: 'private' };
    expect(getBoundaryMultiplier(boundary)).toBeCloseTo(0.8);
  });

  it('honours custom riskReductionPercent', () => {
    const boundary: BoundaryRiskData = {
      zoneType: 'private',
      riskReductionPercent: 40,
    };
    expect(getBoundaryMultiplier(boundary)).toBeCloseTo(0.6);
  });

  it('treats riskReductionEnabled undefined as enabled for private zones', () => {
    const boundary: BoundaryRiskData = {
      zoneType: 'private',
      riskReductionPercent: 25,
    };
    expect(getBoundaryMultiplier(boundary)).toBeCloseTo(0.75);
  });
});

describe('applyBoundaryMultiplier', () => {
  it('returns the base score unchanged when no boundary data is supplied', () => {
    expect(applyBoundaryMultiplier(12, undefined)).toBe(12);
  });

  it('applies the default 20% reduction for private zones (12 → 10)', () => {
    expect(applyBoundaryMultiplier(12, { zoneType: 'private' })).toBe(10);
  });

  it('applies a custom reduction percentage', () => {
    // 16 × 0.5 = 8
    expect(applyBoundaryMultiplier(16, { zoneType: 'private', riskReductionPercent: 50 })).toBe(8);
  });

  it('does not reduce public zones', () => {
    expect(applyBoundaryMultiplier(16, { zoneType: 'public', riskReductionPercent: 90 })).toBe(16);
  });

  it('rounds fractional results to the nearest integer', () => {
    // 10 × 0.75 = 7.5 → rounds to 8
    expect(applyBoundaryMultiplier(10, { zoneType: 'private', riskReductionPercent: 25 })).toBe(8);
  });

  it('returns zero when a 100% reduction is applied', () => {
    expect(applyBoundaryMultiplier(12, { zoneType: 'private', riskReductionPercent: 100 })).toBe(0);
  });
});

describe('getBoundaryReductionPercent', () => {
  it('returns null when no boundary data is supplied', () => {
    expect(getBoundaryReductionPercent(undefined)).toBeNull();
  });

  it('returns null for public zones', () => {
    expect(getBoundaryReductionPercent({ zoneType: 'public' })).toBeNull();
  });

  it('returns null for private zones with reduction explicitly disabled', () => {
    expect(
      getBoundaryReductionPercent({ zoneType: 'private', riskReductionEnabled: false }),
    ).toBeNull();
  });

  it('returns the default 20 when private and no percent is set', () => {
    expect(getBoundaryReductionPercent({ zoneType: 'private' })).toBe(20);
  });

  it('returns the configured custom percent when set', () => {
    expect(
      getBoundaryReductionPercent({ zoneType: 'private', riskReductionPercent: 65 }),
    ).toBe(65);
  });
});
