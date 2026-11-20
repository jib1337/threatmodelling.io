import { describe, it, expect } from 'vitest';
import type { ActiveThreat, Threat } from '../data/schema';
import type { MitigatedVisibility } from './app';
import {
  isThreatMitigated,
  getMitigationKind,
  partitionMitigatedThreats,
  describeThreatMitigation,
  normalizePathwayMitigationSettings,
  SHOW_ALL_MITIGATED,
  HIDE_ALL_MITIGATED,
} from './app';

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

  it('is true when every control is implemented', () => {
    expect(isThreatMitigated(make({ controlsImplemented: true }))).toBe(true);
  });
});

describe('describeThreatMitigation', () => {
  it('names the mitigating technology and mitigation type for a pathway removal', () => {
    expect(describeThreatMitigation(make({ pathwayMitigatedBy: pathway('remove') })))
      .toBe('AWS WAF (WAF Protection)');
  });

  it('uses the connection mitigation label for encrypted connections', () => {
    expect(describeThreatMitigation(make({ mitigatedBy: 'encrypted' }))).toBe('TLS Encrypted');
    expect(describeThreatMitigation(make({ controlsImplemented: true }))).toBe('All controls implemented');
  });

  it('is undefined for threats that are not mitigated', () => {
    expect(describeThreatMitigation(make())).toBeUndefined();
    expect(describeThreatMitigation(make({ pathwayMitigatedBy: pathway('reduce') }))).toBeUndefined();
  });
});

describe('getMitigationKind', () => {
  it('classifies each kind of mitigation', () => {
    expect(getMitigationKind(make())).toBeUndefined();
    expect(getMitigationKind(make({ pathwayMitigatedBy: pathway('reduce') }))).toBeUndefined();
    expect(getMitigationKind(make({ pathwayMitigatedBy: pathway('remove') }))).toBe('upstream');
    expect(getMitigationKind(make({ mitigatedBy: 'encrypted' }))).toBe('connection');
    expect(getMitigationKind(make({ controlsImplemented: true }))).toBe('controls');
  });

  it('prefers upstream, then connection, then controls', () => {
    expect(getMitigationKind(make({
      pathwayMitigatedBy: pathway('remove'), mitigatedBy: 'encrypted', controlsImplemented: true,
    }))).toBe('upstream');
    expect(getMitigationKind(make({ mitigatedBy: 'encrypted', controlsImplemented: true }))).toBe('connection');
  });
});

describe('partitionMitigatedThreats', () => {
  const active = make();
  const reduced = make({ pathwayMitigatedBy: pathway('reduce') });
  const removed = make({ pathwayMitigatedBy: pathway('remove') });
  const encrypted = make({ mitigatedBy: 'encrypted' });
  const ticked = make({ controlsImplemented: true });
  const all = [active, removed, reduced, encrypted, ticked];

  it('splits active from mitigated threats, preserving order', () => {
    expect(partitionMitigatedThreats(all, SHOW_ALL_MITIGATED)).toEqual({
      active: [active, reduced],
      mitigated: [removed, encrypted, ticked],
    });
  });

  it('drops every mitigated threat when all kinds are hidden', () => {
    expect(partitionMitigatedThreats(all, HIDE_ALL_MITIGATED)).toEqual({
      active: [active, reduced],
      mitigated: [],
    });
  });

  it('drops only the kinds that are hidden', () => {
    const only = (key: keyof MitigatedVisibility) => ({ ...SHOW_ALL_MITIGATED, [key]: true });
    expect(partitionMitigatedThreats(all, only('hideUpstream')).mitigated).toEqual([encrypted, ticked]);
    expect(partitionMitigatedThreats(all, only('hideConnection')).mitigated).toEqual([removed, ticked]);
    expect(partitionMitigatedThreats(all, only('hideControls')).mitigated).toEqual([removed, encrypted]);
  });
});

describe('normalizePathwayMitigationSettings: mitigatedVisibility', () => {
  it('shows everything when the setting is absent', () => {
    expect(normalizePathwayMitigationSettings({ enabled: true }).mitigatedVisibility)
      .toEqual(SHOW_ALL_MITIGATED);
  });

  it('maps a legacy hideMitigated boolean onto every kind', () => {
    expect(normalizePathwayMitigationSettings({ hideMitigated: true }).mitigatedVisibility)
      .toEqual(HIDE_ALL_MITIGATED);
    expect(normalizePathwayMitigationSettings({ hideMitigated: false }).mitigatedVisibility)
      .toEqual(SHOW_ALL_MITIGATED);
  });

  it('keeps per-kind values and fills in missing ones', () => {
    expect(normalizePathwayMitigationSettings({
      mitigatedVisibility: { hideConnection: true },
    }).mitigatedVisibility).toEqual({ hideUpstream: false, hideConnection: true, hideControls: false });
  });
});
