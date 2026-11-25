import type { CustomControl, CustomControlsMap } from '../data/schema';
import { MAX_CUSTOM_CONTROLS_PER_SCOPE } from '../data/schema';
import { buildCustomControlKey, normalizeCustomControlDescription } from './controlFingerprint';

// Pure state transitions and import sanitising for user-authored controls.
// The reducer delegates here so the rules are unit-testable without React.
// Every function returns its input unchanged (same reference) when it has
// nothing to do, so memoised consumers don't re-render needlessly.

// node:<nodeId>:<threatId> | connection:<threatId> | zone:<threatId>.
// Neither node ids (uuid) nor catalogue threat ids contain colons.
const SCOPE_KEY_PATTERN = /^(?:node:[^:]+:|connection:|zone:)[^:]+$/;
const CONTROL_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const CUSTOM_TICK_PATTERN = /^(.+)::custom:([^:]+)$/;

export function isValidCustomControlScope(scopeKey: string): boolean {
  return SCOPE_KEY_PATTERN.test(scopeKey);
}

function scopeControls(customControls: CustomControlsMap, scopeKey: string): CustomControl[] | undefined {
  return Object.prototype.hasOwnProperty.call(customControls, scopeKey)
    ? customControls[scopeKey]
    : undefined;
}

function nodeIdOfScope(scopeKey: string): string | null {
  return scopeKey.startsWith('node:') ? scopeKey.split(':')[1] : null;
}

// Appends a control to a scope. Ignored when the scope key or id is
// malformed, the id already exists in that scope, the description is blank
// after normalising, or the scope already holds the maximum.
export function addCustomControl(
  customControls: CustomControlsMap,
  scopeKey: string,
  control: CustomControl,
): CustomControlsMap {
  if (!isValidCustomControlScope(scopeKey) || !CONTROL_ID_PATTERN.test(control.id)) {
    return customControls;
  }
  const description = normalizeCustomControlDescription(control.description);
  if (description === null) return customControls;
  const existing = scopeControls(customControls, scopeKey) ?? [];
  if (existing.length >= MAX_CUSTOM_CONTROLS_PER_SCOPE) return customControls;
  if (existing.some(c => c.id === control.id)) return customControls;
  return {
    ...customControls,
    [scopeKey]: [...existing, { id: control.id, description }],
  };
}

export function updateCustomControl(
  customControls: CustomControlsMap,
  scopeKey: string,
  controlId: string,
  rawDescription: string,
): CustomControlsMap {
  const existing = scopeControls(customControls, scopeKey);
  if (!existing) return customControls;
  const description = normalizeCustomControlDescription(rawDescription);
  if (description === null) return customControls;
  const index = existing.findIndex(c => c.id === controlId);
  if (index === -1 || existing[index].description === description) return customControls;
  const next = existing.slice();
  next[index] = { ...existing[index], description };
  return { ...customControls, [scopeKey]: next };
}

export function removeCustomControl(
  customControls: CustomControlsMap,
  implementedControls: Record<string, true>,
  scopeKey: string,
  controlId: string,
): { customControls: CustomControlsMap; implementedControls: Record<string, true> } {
  const existing = scopeControls(customControls, scopeKey);
  if (!existing || !existing.some(c => c.id === controlId)) {
    return { customControls, implementedControls };
  }
  const remaining = existing.filter(c => c.id !== controlId);
  const { [scopeKey]: _removed, ...rest } = customControls;
  const nextCustom = remaining.length > 0 ? { ...rest, [scopeKey]: remaining } : rest;

  const tickKey = buildCustomControlKey(scopeKey, controlId);
  let nextImplemented = implementedControls;
  if (implementedControls[tickKey]) {
    const { [tickKey]: _tick, ...otherTicks } = implementedControls;
    nextImplemented = otherTicks;
  }
  return { customControls: nextCustom, implementedControls: nextImplemented };
}

// Builds a clean CustomControlsMap from an untrusted saved file. Silently
// drops anything malformed rather than failing the whole import:
// - scope keys that aren't node/connection/zone shaped, or name a node the
//   file doesn't contain (or whose technology failed to load)
// - entries without a string id and description, or with an unsafe id
// - descriptions blank after normalising; over-length ones are clipped to
//   MAX_CUSTOM_CONTROL_LENGTH, not dropped
// - repeated ids within a scope (the first wins)
// - entries beyond MAX_CUSTOM_CONTROLS_PER_SCOPE
export function sanitizeCustomControls(
  raw: unknown,
  nodeIds: ReadonlySet<string>,
): CustomControlsMap {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return {};
  const result: CustomControlsMap = {};
  for (const [scopeKey, entries] of Object.entries(raw as Record<string, unknown>)) {
    if (!isValidCustomControlScope(scopeKey) || !Array.isArray(entries)) continue;
    const nodeId = nodeIdOfScope(scopeKey);
    if (nodeId !== null && !nodeIds.has(nodeId)) continue;

    const seen = new Set<string>();
    const controls: CustomControl[] = [];
    for (const entry of entries) {
      if (controls.length >= MAX_CUSTOM_CONTROLS_PER_SCOPE) break;
      if (typeof entry !== 'object' || entry === null) continue;
      const { id, description } = entry as Record<string, unknown>;
      if (typeof id !== 'string' || !CONTROL_ID_PATTERN.test(id) || seen.has(id)) continue;
      if (typeof description !== 'string') continue;
      const normalized = normalizeCustomControlDescription(description);
      if (normalized === null) continue;
      seen.add(id);
      controls.push({ id, description: normalized });
    }
    if (controls.length > 0) result[scopeKey] = controls;
  }
  return result;
}

// Drops custom-control ticks whose control no longer exists, e.g. one the
// sanitiser discarded on import. Catalogue-control ticks are left alone.
export function pruneOrphanCustomControlTicks(
  implementedControls: Record<string, true>,
  customControls: CustomControlsMap,
): Record<string, true> {
  let changed = false;
  const next: Record<string, true> = {};
  for (const key of Object.keys(implementedControls)) {
    const match = CUSTOM_TICK_PATTERN.exec(key);
    if (match) {
      const [, scopeKey, controlId] = match;
      if (!scopeControls(customControls, scopeKey)?.some(c => c.id === controlId)) {
        changed = true;
        continue;
      }
    }
    next[key] = true;
  }
  return changed ? next : implementedControls;
}

export interface CustomControlReportItem {
  text: string;
  implemented: boolean;
}

// A scope's custom controls with their tick state. Used by the report exporters.
export function getCustomControlReportItems(
  scopeKey: string,
  customControls: CustomControlsMap,
  implementedControls: Record<string, true>,
): CustomControlReportItem[] {
  return (scopeControls(customControls, scopeKey) ?? []).map(control => ({
    text: control.description,
    implemented: !!implementedControls[buildCustomControlKey(scopeKey, control.id)],
  }));
}
