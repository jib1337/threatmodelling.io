// Vocabularies derived from the technology & threat catalogue.
//
// The catalogue is fetched into ./library/ at build time from its own repository
// (see scripts/fetch-library.mjs). Its types are generated from the data and ship
// with the bundle, so a provider or category added there reaches this typecheck
// without any change here.
//
// The catalogue describes only what it ships. This app also models two kinds of
// component the catalogue knows nothing about — external actors and user-created
// custom technologies — so the unions below widen the catalogue's own.
//
// Other app-owned types — diagram state, risk scoring, the saved-model format —
// live in src/types/app.ts instead.

import taxonomy from './library/taxonomy.json';
import manifest from './library/manifest.json';
import pathwayCatalogue from './library/mitigations/pathway-mitigations.json';
import { ACTOR_CATEGORY, ACTOR_CATEGORY_LABEL, ACTOR_PROVIDER, ACTOR_PROVIDER_LABEL } from './actors';

export type {
  StrideCategory,
  ThreatSeverity,
  PathwayMitigationType,
  ConnectionSecurity,
  MitreTechnique,
  Control,
  Threat,
  ThreatLibrary,
  ProviderManifestEntry,
  LibraryManifest,
  PathwayMitigationDefinition,
  CatalogueProvider,
  CatalogueCategory,
} from './library/types';

import type {
  StrideCategory,
  ThreatSeverity,
  PathwayMitigationType,
  LibraryManifest,
  PathwayMitigationDefinition,
  CatalogueProvider,
  CatalogueCategory,
  Technology as CatalogueTechnology,
  ProviderData as CatalogueProviderData,
} from './library/types';

// --- App-widened vocabularies ---

/** Catalogue providers, plus the two kinds of component this app adds itself. */
export type CloudProvider = CatalogueProvider | 'actor' | 'custom';

/** Catalogue categories, plus the one actors sit in. */
export type ServiceCategory = CatalogueCategory | 'actor';

export interface Technology extends Omit<CatalogueTechnology, 'provider' | 'category'> {
  provider: CloudProvider;
  category: ServiceCategory;
  /** True for user-created technologies; never set in the catalogue. */
  isCustom?: boolean;
}

export interface ProviderData extends Omit<CatalogueProviderData, 'provider' | 'services'> {
  provider: CloudProvider;
  services: Technology[];
}

// --- Parsed catalogue metadata ---

export const LIBRARY_MANIFEST = manifest as LibraryManifest;

export const LIBRARY_VERSION = LIBRARY_MANIFEST.libraryVersion;

export const PATHWAY_MITIGATION_DEFINITIONS =
  pathwayCatalogue.mitigations as PathwayMitigationDefinition[];

const labelsById = <K extends string>(rows: { id: string; label: string }[]) =>
  Object.fromEntries(rows.map(r => [r.id, r.label])) as Record<K, string>;

export const STRIDE_LABELS = labelsById<StrideCategory>(taxonomy.stride);

export const THREAT_SEVERITY_LABELS = labelsById<ThreatSeverity>(taxonomy.severities);

// Ordinal rank of each severity, ascending — used for risk scoring
export const THREAT_SEVERITY_VALUES = Object.fromEntries(
  taxonomy.severities.map((s, i) => [s.id, i + 1])
) as Record<ThreatSeverity, number>;

export const CATEGORY_LABELS = {
  ...labelsById<CatalogueCategory>(taxonomy.categories),
  [ACTOR_CATEGORY]: ACTOR_CATEGORY_LABEL,
} as Record<ServiceCategory, string>;

export const PROVIDER_LABELS = {
  ...Object.fromEntries(LIBRARY_MANIFEST.providers.map(p => [p.id, p.displayName])),
  [ACTOR_PROVIDER]: ACTOR_PROVIDER_LABEL,
  // Not part of the catalogue — user-created technologies
  custom: 'Custom',
} as Record<CloudProvider, string>;

// Default threat IDs offered when creating a custom technology in a category.
// Actors carry no threats of their own, so their category offers none.
export const CATEGORY_THREAT_PRESETS = {
  ...Object.fromEntries(taxonomy.categories.map(c => [c.id, c.presetThreatIds])),
  [ACTOR_CATEGORY]: [] as string[],
} as Record<ServiceCategory, string[]>;

export const PATHWAY_MITIGATION_LABELS = labelsById<PathwayMitigationType>(
  PATHWAY_MITIGATION_DEFINITIONS
);

export const PATHWAY_MITIGATION_DESCRIPTIONS = Object.fromEntries(
  PATHWAY_MITIGATION_DEFINITIONS.map(m => [m.id, m.description])
) as Record<PathwayMitigationType, string>;
