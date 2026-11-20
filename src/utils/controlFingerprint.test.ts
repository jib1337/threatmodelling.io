import { describe, it, expect } from 'vitest';
import type { ActiveThreat, Threat } from '../data/schema';
import {
  hashControl,
  buildControlKey,
  pruneNodeControlKeys,
  getThreatControlKeys,
  areAllControlsImplemented,
  markControlMitigatedThreats,
} from './controlFingerprint';

describe('hashControl', () => {
  it('returns the same hash for the same description', () => {
    expect(hashControl('Enable MFA')).toBe(hashControl('Enable MFA'));
  });

  it('returns an 8-character hex string', () => {
    expect(hashControl('anything')).toMatch(/^[0-9a-f]{8}$/);
  });

  it('ignores leading and trailing whitespace', () => {
    expect(hashControl('  Enable MFA  ')).toBe(hashControl('Enable MFA'));
  });

  it('collapses internal repeated whitespace', () => {
    expect(hashControl('Enable    MFA\tfor\nadmins')).toBe(hashControl('Enable MFA for admins'));
  });

  it('produces different hashes for different descriptions', () => {
    const a = hashControl('Enable MFA');
    const b = hashControl('Disable MFA');
    expect(a).not.toBe(b);
  });

  it('treats meaningful punctuation differences as different controls', () => {
    expect(hashControl('Enable MFA.')).not.toBe(hashControl('Enable MFA'));
  });
});

describe('buildControlKey', () => {
  const desc = 'Enable encryption at rest';

  it('emits a node-generic key with no tech segment', () => {
    const key = buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't1' }, desc);
    expect(key).toBe(`node:n1:t1::${hashControl(desc)}`);
  });

  it('emits a node-tech key with a :tech segment', () => {
    const key = buildControlKey({ kind: 'node-tech', nodeId: 'n1', threatId: 't1' }, desc);
    expect(key).toBe(`node:n1:t1:tech::${hashControl(desc)}`);
  });

  it('emits a connection key without a node id', () => {
    const key = buildControlKey({ kind: 'connection', threatId: 't1' }, desc);
    expect(key).toBe(`connection:t1::${hashControl(desc)}`);
  });

  it('emits a zone key without a node id', () => {
    const key = buildControlKey({ kind: 'zone', threatId: 't1' }, desc);
    expect(key).toBe(`zone:t1::${hashControl(desc)}`);
  });

  it('produces distinct keys for the same description across scopes', () => {
    const generic = buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't1' }, desc);
    const tech = buildControlKey({ kind: 'node-tech', nodeId: 'n1', threatId: 't1' }, desc);
    const connection = buildControlKey({ kind: 'connection', threatId: 't1' }, desc);
    const zone = buildControlKey({ kind: 'zone', threatId: 't1' }, desc);
    expect(new Set([generic, tech, connection, zone]).size).toBe(4);
  });

  it('produces distinct keys when only the nodeId differs', () => {
    const a = buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't1' }, desc);
    const b = buildControlKey({ kind: 'node-generic', nodeId: 'n2', threatId: 't1' }, desc);
    expect(a).not.toBe(b);
  });
});

describe('pruneNodeControlKeys', () => {
  it('removes only keys belonging to the given node', () => {
    const map = {
      'node:n1:t1::aaaaaaaa': true as const,
      'node:n1:t2:tech::bbbbbbbb': true as const,
      'node:n2:t1::cccccccc': true as const,
      'connection:t1::dddddddd': true as const,
      'zone:t1::eeeeeeee': true as const,
    };
    const pruned = pruneNodeControlKeys(map, 'n1');
    expect(pruned).toEqual({
      'node:n2:t1::cccccccc': true,
      'connection:t1::dddddddd': true,
      'zone:t1::eeeeeeee': true,
    });
  });

  it('returns the same reference when nothing matches (cheap no-op)', () => {
    const map = {
      'node:n2:t1::aaaaaaaa': true as const,
      'connection:t1::bbbbbbbb': true as const,
    };
    expect(pruneNodeControlKeys(map, 'n1')).toBe(map);
  });

  it('returns the same reference when the map is empty', () => {
    const map = {};
    expect(pruneNodeControlKeys(map, 'anything')).toBe(map);
  });

  it('does not match a different node id that is a prefix of another (n1 vs n10)', () => {
    const map = {
      'node:n1:t1::aaaaaaaa': true as const,
      'node:n10:t1::bbbbbbbb': true as const,
    };
    const pruned = pruneNodeControlKeys(map, 'n1');
    expect(pruned).toEqual({
      'node:n10:t1::bbbbbbbb': true,
    });
  });
});

describe('control-based mitigation', () => {
  const threat: Threat = {
    id: 't-1',
    name: 'Threat',
    description: '',
    severity: 'high',
    stride: ['tampering'],
    mitreTechniques: [],
    controls: [
      { id: 'c1', description: 'Enable MFA' },
      { id: 'c2', description: 'Rotate keys' },
    ],
  } as Threat;

  const make = (overrides: Partial<ActiveThreat> = {}): ActiveThreat => ({
    threat,
    sourceNodeId: 'n1',
    sourceTechName: 'EC2',
    sensitivity: 'internal',
    riskScore: 6,
    riskLevel: 'medium',
    ...overrides,
  });

  const tickAll = (at: ActiveThreat): Record<string, true> =>
    Object.fromEntries(getThreatControlKeys(at).map(k => [k, true as const]));

  it('uses node-generic keys for a component threat', () => {
    expect(getThreatControlKeys(make())).toEqual([
      buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't-1' }, 'Enable MFA'),
      buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't-1' }, 'Rotate keys'),
    ]);
  });

  it('uses tech-specific mitigations in place of generic controls', () => {
    expect(getThreatControlKeys(make({ techMitigations: ['Use IMDSv2'] }))).toEqual([
      buildControlKey({ kind: 'node-tech', nodeId: 'n1', threatId: 't-1' }, 'Use IMDSv2'),
    ]);
  });

  it('uses consolidated keys for connection and zone threats', () => {
    expect(getThreatControlKeys(make({ isConnectionThreat: true }))[0])
      .toBe(buildControlKey({ kind: 'connection', threatId: 't-1' }, 'Enable MFA'));
    expect(getThreatControlKeys(make({ isZoneThreat: true }))[0])
      .toBe(buildControlKey({ kind: 'zone', threatId: 't-1' }, 'Enable MFA'));
  });

  it('requires every control to be ticked', () => {
    const at = make();
    const [first] = getThreatControlKeys(at);
    expect(areAllControlsImplemented(at, { [first]: true })).toBe(false);
    expect(areAllControlsImplemented(at, tickAll(at))).toBe(true);
  });

  it('never treats a threat with no controls as fully implemented', () => {
    expect(areAllControlsImplemented(make({ threat: { ...threat, controls: [] } }), {})).toBe(false);
  });

  it('flags only fully-ticked threats and keeps other mitigations as they are', () => {
    const ticked = make();
    const unticked = make({ sourceNodeId: 'n2' });
    const encrypted = make({ isConnectionThreat: true, mitigatedBy: 'encrypted' });
    const result = markControlMitigatedThreats(
      [ticked, unticked, encrypted],
      { ...tickAll(ticked), ...tickAll(encrypted) },
    );
    expect(result[0].controlsImplemented).toBe(true);
    expect(result[1]).toBe(unticked);
    expect(result[2]).toBe(encrypted);
  });

  it('returns the same array when nothing qualifies', () => {
    const threats = [make()];
    expect(markControlMitigatedThreats(threats, {})).toBe(threats);
  });
});
