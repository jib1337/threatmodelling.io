import threatData from './library/threats/common-threats.json';
import { ACTORS, ACTOR_PROVIDER, ACTOR_ID_PREFIX } from './actors';
import {
  LIBRARY_MANIFEST,
  CATEGORY_THREAT_PRESETS,
  LIBRARY_VERSION,
} from './librarySchema';
import type { Technology, Threat, ProviderData, CloudProvider } from './librarySchema';

export { CATEGORY_THREAT_PRESETS, LIBRARY_VERSION };

// Build maps — actors and threats are always needed immediately (small, sidebar-visible on load)
const technologyMap = new Map<string, Technology>();
const threatMap = new Map<string, Threat>();
const technologiesByProviderCache = new Map<CloudProvider, Technology[]>();

// --- App-owned loading and presentation policy ---
const PROVIDER_ORDER: CloudProvider[] = ['aws', 'gcp', 'azure', 'self-hosted', 'saas'];

const PROVIDER_MODULES = import.meta.glob<{ default: ProviderData }>(
  './library/technologies/*.json'
);

function registerProviderData(provider: CloudProvider, data: ProviderData): void {
  data.services.forEach(service => {
    technologyMap.set(service.id, service as Technology);
  });
  technologiesByProviderCache.set(provider, data.services as Technology[]);
}

(threatData.threats as Threat[]).forEach(threat => {
  threatMap.set(threat.id, threat);
});

const connectionThreatsCache: Threat[] = (threatData.threats as Threat[]).filter(t => t.isConnectionThreat);
const zoneThreatsCache: Threat[] = (threatData.threats as Threat[]).filter(t => t.isZoneThreat);

// --- Lazy provider loading ---

type ProviderLoadCallback = (provider: CloudProvider) => void;
const loadSubscribers = new Set<ProviderLoadCallback>();
const loadedProviderSet = new Set<CloudProvider>();
const activeLoads = new Map<CloudProvider, Promise<void>>();
const PROVIDER_LOADERS: Partial<Record<CloudProvider, () => Promise<unknown>>> = {};
const TECH_ID_PREFIXES: [string, CloudProvider][] = [
  ...LIBRARY_MANIFEST.providers.map(p => [p.idPrefix, p.id] as [string, CloudProvider]),
  [ACTOR_ID_PREFIX, ACTOR_PROVIDER] as [string, CloudProvider],
].sort((a, b) => b[0].length - a[0].length);

registerProviderData(ACTOR_PROVIDER as CloudProvider, ACTORS as unknown as ProviderData);
loadedProviderSet.add(ACTOR_PROVIDER as CloudProvider);

LIBRARY_MANIFEST.providers.forEach(entry => {
  const loader = PROVIDER_MODULES[`./library/${entry.file}`];
  if (!loader) {
    throw new Error(`Catalogue manifest lists ${entry.file} but the file is missing`);
  }
  PROVIDER_LOADERS[entry.id] = loader;
});

export const PROVIDER_SERVICE_COUNTS: Partial<Record<CloudProvider, number>> = Object.fromEntries(
  LIBRARY_MANIFEST.providers.map(p => [p.id, p.serviceCount])
);

export function getSelectableProviders(): CloudProvider[] {
  const available: CloudProvider[] = LIBRARY_MANIFEST.providers.map(p => p.id);

  const known = PROVIDER_ORDER.filter(id => available.includes(id));
  const unknown = available.filter(id => !PROVIDER_ORDER.includes(id));
  return [...known, ...unknown];
}

export function providerFromTechId(id: string): CloudProvider | null {
  for (const [prefix, provider] of TECH_ID_PREFIXES) {
    if (id.startsWith(prefix)) return provider;
  }
  return null;
}

export function isProviderLoaded(provider: CloudProvider): boolean {
  return loadedProviderSet.has(provider);
}

export function subscribeToProviderLoad(cb: ProviderLoadCallback): () => void {
  loadSubscribers.add(cb);
  return () => loadSubscribers.delete(cb);
}

export function loadProvider(provider: CloudProvider): Promise<void> {
  if (loadedProviderSet.has(provider)) return Promise.resolve();
  if (activeLoads.has(provider)) return activeLoads.get(provider)!;

  const loader = PROVIDER_LOADERS[provider];
  if (!loader) return Promise.resolve();

  const promise = loader().then(module => {
    const data = (module as { default: ProviderData }).default;
    registerProviderData(provider, data);
    loadedProviderSet.add(provider);
    activeLoads.delete(provider);
    loadSubscribers.forEach(cb => cb(provider));
  });

  activeLoads.set(provider, promise);
  return promise;
}

export function loadProviders(providers: CloudProvider[]): Promise<void> {
  return Promise.all(providers.map(loadProvider)).then(() => undefined);
}

// Export all technologies grouped by provider (returns cached Map)
export function getTechnologiesByProvider(): Map<CloudProvider, Technology[]> {
  return technologiesByProviderCache;
}

// Get a technology by ID
export function getTechnologyById(id: string): Technology | undefined {
  return technologyMap.get(id);
}

// Get a threat by ID
export function getThreatById(id: string): Threat | undefined {
  return threatMap.get(id);
}

// Get all threats for a technology
export function getThreatsForTechnology(technologyId: string): Threat[] {
  const technology = technologyMap.get(technologyId);
  if (!technology) return [];

  return technology.threatIds
    .map(threatId => threatMap.get(threatId))
    .filter((threat): threat is Threat => threat !== undefined);
}

// Get all threats for multiple technologies (deduplicates)
export function getThreatsForTechnologies(technologyIds: string[]): Map<string, { threat: Threat; sources: string[] }> {
  const result = new Map<string, { threat: Threat; sources: string[] }>();

  technologyIds.forEach(techId => {
    const technology = technologyMap.get(techId);
    if (!technology) return;

    technology.threatIds.forEach(threatId => {
      const threat = threatMap.get(threatId);
      if (!threat) return;

      const existing = result.get(threatId);
      if (existing) {
        existing.sources.push(technology.name);
      } else {
        result.set(threatId, { threat, sources: [technology.name] });
      }
    });
  });

  return result;
}

// Get all threats
export function getAllThreats(): Threat[] {
  return threatData.threats as Threat[];
}

// Get all connection-based threats (returns cached array)
export function getConnectionThreats(): Threat[] {
  return connectionThreatsCache;
}

// Get all zone-based threats (returns cached array)
export function getZoneThreats(): Threat[] {
  return zoneThreatsCache;
}

// Check if a technology is an actor (external client/device)
export function isActor(technologyId: string): boolean {
  const technology = technologyMap.get(technologyId);
  return technology?.provider === ACTOR_PROVIDER;
}

// Register a custom technology at runtime
export function registerCustomTechnology(tech: Technology): void {
  technologyMap.set(tech.id, tech);
  const customTechs = technologiesByProviderCache.get('custom') || [];
  if (!customTechs.some(t => t.id === tech.id)) {
    technologiesByProviderCache.set('custom', [...customTechs, tech]);
  }
}

// Unregister a custom technology at runtime
export function unregisterCustomTechnology(id: string): void {
  technologyMap.delete(id);
  const customTechs = technologiesByProviderCache.get('custom') || [];
  technologiesByProviderCache.set('custom', customTechs.filter(t => t.id !== id));
}

// Register multiple custom technologies at once
export function registerCustomTechnologies(techs: Technology[]): void {
  techs.forEach(tech => registerCustomTechnology(tech));
}

// Clear all custom technologies from the registry
export function clearCustomTechnologies(): void {
  const customTechs = technologiesByProviderCache.get('custom') || [];
  customTechs.forEach(tech => technologyMap.delete(tech.id));
  technologiesByProviderCache.set('custom', []);
}

// Get all registered custom technologies
export function getCustomTechnologies(): Technology[] {
  return technologiesByProviderCache.get('custom') || [];
}
