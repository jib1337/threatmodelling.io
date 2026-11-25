import { describe, it, expect } from 'vitest';
import type { ActiveThreat, CustomControlsMap, Threat } from '../data/schema';
import { MAX_CUSTOM_CONTROL_LENGTH } from '../data/schema';
import {
  hashControl,
  customControlScopeKey,
  buildCustomControlKey,
  getCustomControls,
  normalizeCustomControlDescription,
  pruneNodeCustomControls,
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

describe('custom controls', () => {
  const threat: Threat = {
    id: 't-1',
    name: 'Threat',
    description: '',
    severity: 'high',
    stride: ['tampering'],
    mitreTechniques: [],
    controls: [{ id: 'c1', description: 'Enable MFA' }],
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

  const custom: CustomControlsMap = {
    'node:n1:t-1': [{ id: 'cc1', description: 'Quarterly access review' }],
    'connection:t-1': [{ id: 'cc2', description: 'mTLS between services' }],
    'zone:t-1': [{ id: 'cc3', description: 'Egress allow-list' }],
  };

  const tick = (keys: string[]): Record<string, true> =>
    Object.fromEntries(keys.map(k => [k, true as const]));

  describe('customControlScopeKey', () => {
    it('is per node for component threats', () => {
      expect(customControlScopeKey(make())).toBe('node:n1:t-1');
      expect(customControlScopeKey(make({ techMitigations: ['Use IMDSv2'] }))).toBe('node:n1:t-1');
    });

    it('is consolidated per threat for connections and zones', () => {
      expect(customControlScopeKey(make({ isConnectionThreat: true }))).toBe('connection:t-1');
      expect(customControlScopeKey(make({ isZoneThreat: true }))).toBe('zone:t-1');
    });
  });

  describe('buildCustomControlKey', () => {
    it('appends a custom:<id> segment to the scope', () => {
      expect(buildCustomControlKey('node:n1:t-1', 'cc1')).toBe('node:n1:t-1::custom:cc1');
    });

    it('never collides with a catalogue key for the same scope', () => {
      const catalogue = buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't-1' }, 'cc1');
      expect(buildCustomControlKey('node:n1:t-1', 'cc1')).not.toBe(catalogue);
    });

    it('is cleared by pruneNodeControlKeys along with the node\'s other ticks', () => {
      const key = buildCustomControlKey('node:n1:t-1', 'cc1');
      expect(pruneNodeControlKeys({ [key]: true }, 'n1')).toEqual({});
    });
  });

  describe('getCustomControls', () => {
    it('returns the controls for the instance\'s scope', () => {
      expect(getCustomControls(make(), custom)).toEqual(custom['node:n1:t-1']);
      expect(getCustomControls(make({ isZoneThreat: true }), custom)).toEqual(custom['zone:t-1']);
    });

    it('returns an empty list for another node', () => {
      expect(getCustomControls(make({ sourceNodeId: 'n2' }), custom)).toEqual([]);
    });
  });

  describe('getThreatControlKeys with custom controls', () => {
    it('appends custom keys after the catalogue keys', () => {
      expect(getThreatControlKeys(make(), custom)).toEqual([
        buildControlKey({ kind: 'node-generic', nodeId: 'n1', threatId: 't-1' }, 'Enable MFA'),
        'node:n1:t-1::custom:cc1',
      ]);
    });

    it('appends custom keys after tech-specific mitigations too', () => {
      expect(getThreatControlKeys(make({ techMitigations: ['Use IMDSv2'] }), custom)).toEqual([
        buildControlKey({ kind: 'node-tech', nodeId: 'n1', threatId: 't-1' }, 'Use IMDSv2'),
        'node:n1:t-1::custom:cc1',
      ]);
    });

    it('uses consolidated scopes for connection and zone threats', () => {
      const connectionKeys = getThreatControlKeys(make({ isConnectionThreat: true }), custom);
      expect(connectionKeys[connectionKeys.length - 1]).toBe('connection:t-1::custom:cc2');
      const zoneKeys = getThreatControlKeys(make({ isZoneThreat: true }), custom);
      expect(zoneKeys[zoneKeys.length - 1]).toBe('zone:t-1::custom:cc3');
    });
  });

  describe('mitigation with custom controls', () => {
    it('requires custom controls to be ticked as well as catalogue ones', () => {
      const at = make();
      const [catalogueKey, customKey] = getThreatControlKeys(at, custom);
      expect(areAllControlsImplemented(at, tick([catalogueKey]), custom)).toBe(false);
      expect(areAllControlsImplemented(at, tick([catalogueKey, customKey]), custom)).toBe(true);
    });

    it('lets a threat with no catalogue controls be mitigated by its custom ones', () => {
      const at = make({ threat: { ...threat, controls: [] } });
      expect(areAllControlsImplemented(at, {}, custom)).toBe(false);
      expect(areAllControlsImplemented(at, tick(['node:n1:t-1::custom:cc1']), custom)).toBe(true);
    });

    it('un-mitigates a threat when an unticked custom control is added', () => {
      const at = make();
      const ticks = tick(getThreatControlKeys(at));
      expect(markControlMitigatedThreats([at], ticks)[0].controlsImplemented).toBe(true);
      expect(markControlMitigatedThreats([at], ticks, custom)[0].controlsImplemented).toBeUndefined();
    });
  });

  describe('normalizeCustomControlDescription', () => {
    it('trims and collapses whitespace, including newlines', () => {
      expect(normalizeCustomControlDescription('  Rotate\n\nkeys   quarterly ')).toBe('Rotate keys quarterly');
    });

    it('returns null for blank input', () => {
      expect(normalizeCustomControlDescription('')).toBeNull();
      expect(normalizeCustomControlDescription(' \t\n ')).toBeNull();
    });

    it('keeps a description of exactly the maximum length', () => {
      const text = 'a'.repeat(MAX_CUSTOM_CONTROL_LENGTH);
      expect(normalizeCustomControlDescription(text)).toBe(text);
    });

    it('clips an over-length description to the maximum', () => {
      expect(MAX_CUSTOM_CONTROL_LENGTH).toBe(200);
      const result = normalizeCustomControlDescription('a'.repeat(250));
      expect(result).toHaveLength(200);
    });

    it('does not split a surrogate pair at the boundary', () => {
      const result = normalizeCustomControlDescription('a'.repeat(199) + '🔒' + 'b')!;
      expect(result).toBe('a'.repeat(199));
    });
  });

  describe('pruneNodeCustomControls', () => {
    it('removes only the given node\'s scopes', () => {
      const map: CustomControlsMap = {
        ...custom,
        'node:n10:t-1': [{ id: 'x', description: 'Other node' }],
      };
      expect(pruneNodeCustomControls(map, 'n1')).toEqual({
        'connection:t-1': custom['connection:t-1'],
        'zone:t-1': custom['zone:t-1'],
        'node:n10:t-1': map['node:n10:t-1'],
      });
    });

    it('returns the same reference when nothing matches', () => {
      expect(pruneNodeCustomControls(custom, 'n2')).toBe(custom);
    });
  });
});
