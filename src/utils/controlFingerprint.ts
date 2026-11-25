import type { ActiveThreat, CustomControl, CustomControlsMap } from '../data/schema';
import { MAX_CUSTOM_CONTROL_LENGTH } from '../data/schema';

// Identity for "this specific control" that survives ID renames and breaks
// when the description text changes meaningfully. djb2 is deterministic, has
// no runtime deps, and is cheap enough to run on every render.
//
// Trailing/leading whitespace is trimmed and repeated whitespace collapsed so
// incidental formatting tweaks don't orphan a user's actioned flag.
export function hashControl(description: string): string {
  const normalized = description.trim().replace(/\s+/g, ' ');
  let hash = 5381;
  for (let i = 0; i < normalized.length; i++) {
    hash = ((hash << 5) + hash + normalized.charCodeAt(i)) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

export type ControlScope =
  // A node's generic threat controls (the default threat.controls list)
  | { kind: 'node-generic'; nodeId: string; threatId: string }
  // A node's tech-specific mitigations (Technology.threatMitigations[threatId])
  | { kind: 'node-tech'; nodeId: string; threatId: string }
  // Connection threats are consolidated across all edges they apply to
  | { kind: 'connection'; threatId: string }
  // Zone threats are consolidated across all zones they apply to
  | { kind: 'zone'; threatId: string };

export function buildControlKey(scope: ControlScope, description: string): string {
  const fp = hashControl(description);
  switch (scope.kind) {
    case 'node-generic':
      return `node:${scope.nodeId}:${scope.threatId}::${fp}`;
    case 'node-tech':
      return `node:${scope.nodeId}:${scope.threatId}:tech::${fp}`;
    case 'connection':
      return `connection:${scope.threatId}::${fp}`;
    case 'zone':
      return `zone:${scope.threatId}::${fp}`;
  }
}

// Strips every `node:{nodeId}:*` entry from an implementedControls map. Used
// when a node is removed so its actioned flags don't linger as orphaned keys
// in exported JSON.
export function pruneNodeControlKeys(
  implementedControls: Record<string, true>,
  nodeId: string,
): Record<string, true> {
  const prefix = `node:${nodeId}:`;
  let changed = false;
  const next: Record<string, true> = {};
  for (const key of Object.keys(implementedControls)) {
    if (key.startsWith(prefix)) {
      changed = true;
      continue;
    }
    next[key] = true;
  }
  return changed ? next : implementedControls;
}

// Scope key a threat instance's custom controls are stored under in a
// CustomControlsMap. Same granularity as the catalogue control keys: per node
// for component threats, consolidated per threat id for connections and zones.
export type CustomControlScope =
  | { kind: 'node'; nodeId: string; threatId: string }
  | { kind: 'connection' | 'zone'; threatId: string };

export function buildCustomControlScope(scope: CustomControlScope): string {
  return scope.kind === 'node'
    ? `node:${scope.nodeId}:${scope.threatId}`
    : `${scope.kind}:${scope.threatId}`;
}

export function customControlScopeKey(at: ActiveThreat): string {
  const threatId = at.threat.id;
  if (at.isZoneThreat) return buildCustomControlScope({ kind: 'zone', threatId });
  if (at.isConnectionThreat) return buildCustomControlScope({ kind: 'connection', threatId });
  return buildCustomControlScope({ kind: 'node', nodeId: at.sourceNodeId, threatId });
}

// implementedControls key for a custom control. Keyed by the control's stable
// id rather than a description hash, so editing its text keeps the tick. The
// `custom:` segment can't collide with an 8-hex-digit catalogue hash, and the
// node:<id>: prefix means pruneNodeControlKeys clears these ticks too.
export function buildCustomControlKey(scopeKey: string, controlId: string): string {
  return `${scopeKey}::custom:${controlId}`;
}

// The custom controls the user has added to this threat instance.
export function getCustomControls(
  at: ActiveThreat,
  customControls: CustomControlsMap,
): CustomControl[] {
  const scopeKey = customControlScopeKey(at);
  return Object.prototype.hasOwnProperty.call(customControls, scopeKey)
    ? customControls[scopeKey]
    : [];
}

// Canonical form of a user-entered custom control description: trimmed,
// whitespace runs (including newlines, which would break Markdown tables)
// collapsed to single spaces, and clipped to MAX_CUSTOM_CONTROL_LENGTH
// without splitting a surrogate pair. Returns null when nothing remains.
export function normalizeCustomControlDescription(raw: string): string | null {
  let text = raw.replace(/\s+/g, ' ').trim();
  if (text.length > MAX_CUSTOM_CONTROL_LENGTH) {
    text = text.slice(0, MAX_CUSTOM_CONTROL_LENGTH);
    const last = text.charCodeAt(text.length - 1);
    if (last >= 0xd800 && last <= 0xdbff) text = text.slice(0, -1);
    text = text.trimEnd();
  }
  return text.length > 0 ? text : null;
}

// Removes every node:<nodeId>:* scope from a CustomControlsMap. The
// companion to pruneNodeControlKeys, run when a node is deleted.
export function pruneNodeCustomControls(
  customControls: CustomControlsMap,
  nodeId: string,
): CustomControlsMap {
  const prefix = `node:${nodeId}:`;
  let changed = false;
  const next: CustomControlsMap = {};
  for (const [scope, controls] of Object.entries(customControls)) {
    if (scope.startsWith(prefix)) {
      changed = true;
      continue;
    }
    next[scope] = controls;
  }
  return changed ? next : customControls;
}

// The implementedControls keys for every control the sidebar lists on this
// threat instance. Mirrors the key choice in ThreatCard, ConnectionThreatCard
// and ZoneThreatCard: tech-specific mitigations replace the generic controls
// when present. Custom controls follow the catalogue ones.
export function getThreatControlKeys(
  at: ActiveThreat,
  customControls: CustomControlsMap = {},
): string[] {
  const threatId = at.threat.id;
  let catalogueKeys: string[];
  if (at.isZoneThreat) {
    catalogueKeys = at.threat.controls.map(c => buildControlKey({ kind: 'zone', threatId }, c.description));
  } else if (at.isConnectionThreat) {
    catalogueKeys = at.threat.controls.map(c => buildControlKey({ kind: 'connection', threatId }, c.description));
  } else if (at.techMitigations && at.techMitigations.length > 0) {
    catalogueKeys = at.techMitigations.map(m =>
      buildControlKey({ kind: 'node-tech', nodeId: at.sourceNodeId, threatId }, m));
  } else {
    catalogueKeys = at.threat.controls.map(c =>
      buildControlKey({ kind: 'node-generic', nodeId: at.sourceNodeId, threatId }, c.description));
  }
  const custom = getCustomControls(at, customControls);
  if (custom.length === 0) return catalogueKeys;
  const scopeKey = customControlScopeKey(at);
  return [...catalogueKeys, ...custom.map(c => buildCustomControlKey(scopeKey, c.id))];
}

// True when the threat lists at least one control (catalogue or custom) and
// every one is ticked.
export function areAllControlsImplemented(
  at: ActiveThreat,
  implementedControls: Record<string, true>,
  customControls: CustomControlsMap = {},
): boolean {
  const keys = getThreatControlKeys(at, customControls);
  return keys.length > 0 && keys.every(key => implementedControls[key]);
}

// Flags threats whose controls are all ticked with controlsImplemented so
// isThreatMitigated treats them as mitigated. Threats already mitigated another
// way keep their original attribution. Returns the input array unchanged when
// nothing qualifies, so memoised consumers don't re-render needlessly.
export function markControlMitigatedThreats(
  threats: ActiveThreat[],
  implementedControls: Record<string, true>,
  customControls: CustomControlsMap = {},
): ActiveThreat[] {
  let changed = false;
  const result = threats.map(at => {
    if (at.mitigatedBy || at.pathwayMitigatedBy?.mode === 'remove') return at;
    if (!areAllControlsImplemented(at, implementedControls, customControls)) return at;
    changed = true;
    return { ...at, controlsImplemented: true as const };
  });
  return changed ? result : threats;
}
