import type { ActiveThreat } from '../data/schema';

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

// The implementedControls keys for every control the sidebar lists on this
// threat instance. Mirrors the key choice in ThreatCard, ConnectionThreatCard
// and ZoneThreatCard: tech-specific mitigations replace the generic controls
// when present.
export function getThreatControlKeys(at: ActiveThreat): string[] {
  const threatId = at.threat.id;
  if (at.isZoneThreat) {
    return at.threat.controls.map(c => buildControlKey({ kind: 'zone', threatId }, c.description));
  }
  if (at.isConnectionThreat) {
    return at.threat.controls.map(c => buildControlKey({ kind: 'connection', threatId }, c.description));
  }
  if (at.techMitigations && at.techMitigations.length > 0) {
    return at.techMitigations.map(m =>
      buildControlKey({ kind: 'node-tech', nodeId: at.sourceNodeId, threatId }, m));
  }
  return at.threat.controls.map(c =>
    buildControlKey({ kind: 'node-generic', nodeId: at.sourceNodeId, threatId }, c.description));
}

// True when the threat lists at least one control and every one is ticked.
export function areAllControlsImplemented(
  at: ActiveThreat,
  implementedControls: Record<string, true>,
): boolean {
  const keys = getThreatControlKeys(at);
  return keys.length > 0 && keys.every(key => implementedControls[key]);
}

// Flags threats whose controls are all ticked with controlsImplemented so
// isThreatMitigated treats them as mitigated. Threats already mitigated another
// way keep their original attribution. Returns the input array unchanged when
// nothing qualifies, so memoised consumers don't re-render needlessly.
export function markControlMitigatedThreats(
  threats: ActiveThreat[],
  implementedControls: Record<string, true>,
): ActiveThreat[] {
  let changed = false;
  const result = threats.map(at => {
    if (at.mitigatedBy || at.pathwayMitigatedBy?.mode === 'remove') return at;
    if (!areAllControlsImplemented(at, implementedControls)) return at;
    changed = true;
    return { ...at, controlsImplemented: true as const };
  });
  return changed ? result : threats;
}
