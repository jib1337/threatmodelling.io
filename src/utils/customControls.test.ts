import { describe, it, expect } from 'vitest';
import type { CustomControlsMap } from '../data/schema';
import { MAX_CUSTOM_CONTROL_LENGTH, MAX_CUSTOM_CONTROLS_PER_SCOPE } from '../data/schema';
import { buildCustomControlKey } from './controlFingerprint';
import {
  isValidCustomControlScope,
  addCustomControl,
  updateCustomControl,
  removeCustomControl,
  sanitizeCustomControls,
  pruneOrphanCustomControlTicks,
  getCustomControlReportItems,
} from './customControls';

const SCOPE = 'node:n1:aws-ec2-imds';

describe('isValidCustomControlScope', () => {
  it.each(['node:n1:t-1', 'connection:t-1', 'zone:t-1'])('accepts %s', scope => {
    expect(isValidCustomControlScope(scope)).toBe(true);
  });

  it.each([
    '', 'node:n1', 'node::t-1', 'node:n1:', 'connection:', 'edge:t-1',
    'node:n1:t-1::custom:x', 'connection:t-1:extra', '__proto__',
  ])('rejects %j', scope => {
    expect(isValidCustomControlScope(scope)).toBe(false);
  });
});

describe('addCustomControl', () => {
  it('appends a normalised control to a new scope', () => {
    const next = addCustomControl({}, SCOPE, { id: 'a', description: '  Quarterly\naccess review ' });
    expect(next).toEqual({ [SCOPE]: [{ id: 'a', description: 'Quarterly access review' }] });
  });

  it('appends after existing controls in the scope', () => {
    const start: CustomControlsMap = { [SCOPE]: [{ id: 'a', description: 'First' }] };
    const next = addCustomControl(start, SCOPE, { id: 'b', description: 'Second' });
    expect(next[SCOPE].map(c => c.id)).toEqual(['a', 'b']);
    expect(start[SCOPE]).toHaveLength(1); // not mutated
  });

  it('stores an over-length description clipped to the maximum', () => {
    const next = addCustomControl({}, SCOPE, { id: 'a', description: 'x'.repeat(250) });
    expect(next[SCOPE][0].description).toHaveLength(MAX_CUSTOM_CONTROL_LENGTH);
  });

  it.each([
    ['a blank description', SCOPE, { id: 'a', description: '   ' }],
    ['a malformed scope', 'node:n1', { id: 'a', description: 'Valid' }],
    ['an unsafe id', SCOPE, { id: 'a::b', description: 'Valid' }],
  ])('ignores %s', (_label, scope, control) => {
    const start: CustomControlsMap = {};
    expect(addCustomControl(start, scope, control)).toBe(start);
  });

  it('ignores a duplicate id within the scope', () => {
    const start: CustomControlsMap = { [SCOPE]: [{ id: 'a', description: 'First' }] };
    expect(addCustomControl(start, SCOPE, { id: 'a', description: 'Again' })).toBe(start);
  });

  it('refuses to exceed the per-scope cap', () => {
    const full: CustomControlsMap = {
      [SCOPE]: Array.from({ length: MAX_CUSTOM_CONTROLS_PER_SCOPE }, (_, i) => ({ id: `c${i}`, description: `C${i}` })),
    };
    expect(addCustomControl(full, SCOPE, { id: 'extra', description: 'One more' })).toBe(full);
  });
});

describe('updateCustomControl', () => {
  const start: CustomControlsMap = {
    [SCOPE]: [{ id: 'a', description: 'First' }, { id: 'b', description: 'Second' }],
  };

  it('rewords the control in place, keeping its id and position', () => {
    const next = updateCustomControl(start, SCOPE, 'b', 'Second, reworded');
    expect(next[SCOPE]).toEqual([
      { id: 'a', description: 'First' },
      { id: 'b', description: 'Second, reworded' },
    ]);
  });

  it('clips an over-length rewording to the maximum', () => {
    const next = updateCustomControl(start, SCOPE, 'a', 'y'.repeat(250));
    expect(next[SCOPE][0].description).toHaveLength(MAX_CUSTOM_CONTROL_LENGTH);
  });

  it.each([
    ['a scope naming an Object.prototype member', 'constructor', 'a', 'New'],
    ['blank text', SCOPE, 'a', '  '],
    ['unchanged text', SCOPE, 'a', ' First '],
    ['an unknown id', SCOPE, 'zzz', 'New'],
    ['an unknown scope', 'zone:t-9', 'a', 'New'],
  ])('is a no-op for %s', (_label, scope, id, text) => {
    expect(updateCustomControl(start, scope, id, text)).toBe(start);
  });
});

describe('removeCustomControl', () => {
  const tick = buildCustomControlKey(SCOPE, 'a');
  const start: CustomControlsMap = {
    [SCOPE]: [{ id: 'a', description: 'First' }, { id: 'b', description: 'Second' }],
  };

  it('removes the control and its tick', () => {
    const next = removeCustomControl(start, { [tick]: true, other: true }, SCOPE, 'a');
    expect(next.customControls[SCOPE]).toEqual([{ id: 'b', description: 'Second' }]);
    expect(next.implementedControls).toEqual({ other: true });
  });

  it('drops the scope once it is empty', () => {
    const single: CustomControlsMap = { [SCOPE]: [{ id: 'a', description: 'Only' }], 'zone:t-1': [] };
    const next = removeCustomControl(single, {}, SCOPE, 'a');
    expect(next.customControls).toEqual({ 'zone:t-1': [] });
  });

  it('keeps the implementedControls reference when the control was unticked', () => {
    const implemented = { other: true as const };
    expect(removeCustomControl(start, implemented, SCOPE, 'a').implementedControls).toBe(implemented);
  });

  it('is a no-op for a scope naming an Object.prototype member', () => {
    const next = removeCustomControl(start, {}, 'constructor', 'a');
    expect(next.customControls).toBe(start);
  });

  it('is a no-op for an unknown id', () => {
    const implemented = { [tick]: true as const };
    const next = removeCustomControl(start, implemented, SCOPE, 'zzz');
    expect(next.customControls).toBe(start);
    expect(next.implementedControls).toBe(implemented);
  });
});

describe('sanitizeCustomControls', () => {
  const nodes = new Set(['n1']);

  it('keeps well-formed entries for every scope kind', () => {
    const raw = {
      'node:n1:t-1': [{ id: 'a', description: 'Node control' }],
      'connection:t-2': [{ id: 'b', description: 'Connection control' }],
      'zone:t-3': [{ id: 'c', description: 'Zone control' }],
    };
    expect(sanitizeCustomControls(raw, nodes)).toEqual(raw);
  });

  it.each([undefined, null, 'string', 42, ['array']])('returns {} for %j', raw => {
    expect(sanitizeCustomControls(raw, nodes)).toEqual({});
  });

  it('drops malformed scopes, non-array values and scopes for missing nodes', () => {
    const raw = {
      'bogus:t-1': [{ id: 'a', description: 'x' }],
      'zone:t-1': 'not an array',
      'node:n404:t-1': [{ id: 'a', description: 'Orphaned' }],
      'node:n1:t-1': [{ id: 'a', description: 'Kept' }],
    };
    expect(sanitizeCustomControls(raw, nodes)).toEqual({
      'node:n1:t-1': [{ id: 'a', description: 'Kept' }],
    });
  });

  it('drops malformed entries and keeps the rest', () => {
    const raw = {
      'zone:t-1': [
        null,
        'string',
        { id: 7, description: 'Numeric id' },
        { id: 'a::b', description: 'Unsafe id' },
        { id: 'c' },
        { id: 'd', description: '   ' },
        { id: 'e', description: 'Good', extra: 'stripped' },
      ],
    };
    expect(sanitizeCustomControls(raw, nodes)).toEqual({
      'zone:t-1': [{ id: 'e', description: 'Good' }],
    });
  });

  it('clips over-length descriptions instead of dropping them', () => {
    const raw = { 'zone:t-1': [{ id: 'a', description: 'z'.repeat(500) }] };
    const result = sanitizeCustomControls(raw, nodes);
    expect(result['zone:t-1'][0].description).toBe('z'.repeat(MAX_CUSTOM_CONTROL_LENGTH));
  });

  it('keeps the first of any repeated id within a scope', () => {
    const raw = { 'zone:t-1': [{ id: 'a', description: 'First' }, { id: 'a', description: 'Second' }] };
    expect(sanitizeCustomControls(raw, nodes)).toEqual({ 'zone:t-1': [{ id: 'a', description: 'First' }] });
  });

  it('caps the number of controls per scope', () => {
    const raw = {
      'zone:t-1': Array.from({ length: MAX_CUSTOM_CONTROLS_PER_SCOPE + 10 }, (_, i) => ({ id: `c${i}`, description: `C${i}` })),
    };
    expect(sanitizeCustomControls(raw, nodes)['zone:t-1']).toHaveLength(MAX_CUSTOM_CONTROLS_PER_SCOPE);
  });

  it('omits scopes left empty after cleaning', () => {
    expect(sanitizeCustomControls({ 'zone:t-1': [{ id: 'a', description: '' }] }, nodes)).toEqual({});
  });

  it('ignores an own __proto__ key from JSON.parse', () => {
    const raw = JSON.parse('{"__proto__": [{"id": "a", "description": "x"}], "zone:t-1": [{"id": "b", "description": "ok"}]}');
    const result = sanitizeCustomControls(raw, nodes);
    expect(result).toEqual({ 'zone:t-1': [{ id: 'b', description: 'ok' }] });
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
  });
});

describe('pruneOrphanCustomControlTicks', () => {
  const custom: CustomControlsMap = { 'zone:t-1': [{ id: 'a', description: 'Kept' }] };

  it('drops ticks for custom controls that no longer exist, keeping catalogue ticks', () => {
    const implemented = {
      'zone:t-1::custom:a': true as const,
      'zone:t-1::custom:gone': true as const,
      'node:n9:t-2::custom:x': true as const,
      'zone:t-1::0badf00d': true as const,
    };
    expect(pruneOrphanCustomControlTicks(implemented, custom)).toEqual({
      'zone:t-1::custom:a': true,
      'zone:t-1::0badf00d': true,
    });
  });

  it('does not throw on tick keys naming Object.prototype members', () => {
    const implemented = { 'constructor::custom:a': true as const, 'toString::custom:b': true as const };
    expect(pruneOrphanCustomControlTicks(implemented, custom)).toEqual({});
  });

  it('returns the same reference when nothing is orphaned', () => {
    const implemented = { 'zone:t-1::custom:a': true as const, 'zone:t-1::0badf00d': true as const };
    expect(pruneOrphanCustomControlTicks(implemented, custom)).toBe(implemented);
  });
});

describe('getCustomControlReportItems', () => {
  it('lists the scope\'s controls in order with their tick state', () => {
    const custom: CustomControlsMap = {
      'zone:t-1': [{ id: 'a', description: 'First' }, { id: 'b', description: 'Second' }],
    };
    expect(getCustomControlReportItems('zone:t-1', custom, { 'zone:t-1::custom:b': true })).toEqual([
      { text: 'First', implemented: false },
      { text: 'Second', implemented: true },
    ]);
  });

  it('returns an empty list for an unknown or prototype-named scope', () => {
    expect(getCustomControlReportItems('zone:t-9', {}, {})).toEqual([]);
    expect(getCustomControlReportItems('constructor', {}, {})).toEqual([]);
  });
});
