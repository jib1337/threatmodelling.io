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
