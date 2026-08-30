import type { ThreatModel } from '../data/schema';

// Versioned key so a future breaking change to the autosave shape can be
// introduced without colliding with stale data in users' browsers.
const AUTOSAVE_KEY = 'tmio:autosave:v1';

/**
 * Whether a model contains anything worth persisting. An empty model (no nodes
 * and no boundaries) should not overwrite a previously saved one, and there is
 * no value in writing it.
 */
export function modelHasContent(model: ThreatModel): boolean {
  return model.nodes.length > 0 || (model.zones?.length ?? 0) > 0;
}

/**
 * Persist the current model to localStorage. Swallows errors (quota exceeded,
 * private-mode restrictions, serialization failures) so autosave can never
 * break the app.
 */
export function savePersistedModel(model: ThreatModel): void {
  try {
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(model));
  } catch {
    // Storage may be full or unavailable; autosave is best-effort.
  }
}

/**
 * Load a previously autosaved model. Returns null when nothing is stored or the
 * stored value is missing/corrupt.
 */
export function loadPersistedModel(): ThreatModel | null {
  try {
    const raw = localStorage.getItem(AUTOSAVE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ThreatModel;
    // Minimal structural validation — anything without a nodes array is unusable.
    if (!parsed || !Array.isArray(parsed.nodes)) return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Remove the autosaved model (e.g. when the user clears the diagram). */
export function clearPersistedModel(): void {
  try {
    localStorage.removeItem(AUTOSAVE_KEY);
  } catch {
    // Best-effort.
  }
}
