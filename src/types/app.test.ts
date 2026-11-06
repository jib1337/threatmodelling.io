import { describe, it, expect } from 'vitest';
import type { ActiveThreat, Threat } from '../data/schema';
import { isThreatMitigated, partitionMitigatedThreats, describeThreatMitigation } from './app';

const threat: Threat = {
  id: 't-1',
  name: 'Threat',
  description: '',
  severity: 'high',
  stride: ['tampering'],
  mitreTechniques: [],
  controls: [],
};

const make = (overrides: Partial<ActiveThreat> = {}): ActiveThreat => ({
  threat,
  sourceNodeId: 'n1',
  sourceTechName: 'EC2',
  sensitivity: 'internal',
  riskScore: 6,
  riskLevel: 'medium',
  ...overrides,
});

const pathway = (mode: 'remove' | 'reduce'): ActiveThreat['pathwayMitigatedBy'] => ({
  mitigationType: 'waf-protection',
  mitigatingTechId: 'aws-waf',
  mitigatingTechName: 'AWS WAF',
  mode,
  ...(mode === 'reduce' && { reductionPercent: 50 }),
});

describe('isThreatMitigated', () => {
  it('is false for an unmitigated threat', () => {
    expect(isThreatMitigated(make())).toBe(false);
  });

  it('is true for a pathway removal', () => {
    expect(isThreatMitigated(make({ pathwayMitigatedBy: pathway('remove') }))).toBe(true);
  });

  it('is false for a pathway reduction, which leaves the threat active', () => {
    expect(isThreatMitigated(make({ pathwayMitigatedBy: pathway('reduce') }))).toBe(false);
  });

  it('is true for an encrypted connection threat', () => {
    expect(isThreatMitigated(make({ isConnectionThreat: true, mitigatedBy: 'encrypted' }))).toBe(true);
  });
});

describe('describeThreatMitigation', () => {
  it('names the mitigating technology and mitigation type for a pathway removal', () => {
    expect(describeThreatMitigation(make({ pathwayMitigatedBy: pathway('remove') })))
      .toBe('AWS WAF (WAF Protection)');
  });

  it('uses the connection mitigation label for encrypted connections', () => {
    expect(describeThreatMitigation(make({ mitigatedBy: 'encrypted' }))).toBe('TLS Encrypted');
  });

  it('is undefined for threats that are not mitigated', () => {
    expect(describeThreatMitigation(make())).toBeUndefined();
    expect(describeThreatMitigation(make({ pathwayMitigatedBy: pathway('reduce') }))).toBeUndefined();
  });
});

describe('partitionMitigatedThreats', () => {
  const active = make();
  const reduced = make({ pathwayMitigatedBy: pathway('reduce') });
  const removed = make({ pathwayMitigatedBy: pathway('remove') });
  const encrypted = make({ mitigatedBy: 'encrypted' });

  it('splits active from mitigated threats, preserving order', () => {
    expect(partitionMitigatedThreats([active, removed, reduced, encrypted], false)).toEqual({
      active: [active, reduced],
      mitigated: [removed, encrypted],
    });
  });

  it('drops mitigated threats when hidden', () => {
    expect(partitionMitigatedThreats([active, removed, reduced, encrypted], true)).toEqual({
      active: [active, reduced],
      mitigated: [],
    });
  });
});
