// Pathway mitigation lookups, derived from the catalogue's mitigation definitions
// (src/data/mitigations/pathway-mitigations.json).
//
// The catalogue declares each mitigation once — its label, the threats it
// addresses and the technologies that provide it. The maps below are the
// inverted views the app queries at runtime.

import { PATHWAY_MITIGATION_DEFINITIONS } from './librarySchema';
import type { PathwayMitigationType } from './librarySchema';

/**
 * Maps technology IDs to their mitigation capabilities.
 * Each technology can provide one or more types of mitigation.
 */
export const TECHNOLOGY_MITIGATION_CAPABILITIES: Record<string, PathwayMitigationType[]> =
  PATHWAY_MITIGATION_DEFINITIONS.reduce<Record<string, PathwayMitigationType[]>>(
    (acc, mitigation) => {
      mitigation.technologyIds.forEach(techId => {
        (acc[techId] ??= []).push(mitigation.id);
      });
      return acc;
    },
    {}
  );

/**
 * Maps mitigation types to the threat IDs they can mitigate.
 */
export const MITIGATION_TO_THREATS = Object.fromEntries(
  PATHWAY_MITIGATION_DEFINITIONS.map(m => [m.id, m.mitigatesThreatIds])
) as Record<PathwayMitigationType, string[]>;

/**
 * Display names for technologies that provide mitigations.
 * Used for showing which technologies provide each mitigation type.
 */
export const MITIGATION_PROVIDER_NAMES = Object.fromEntries(
  PATHWAY_MITIGATION_DEFINITIONS.map(m => [m.id, m.providerNames])
) as Record<PathwayMitigationType, string[]>;

/**
 * Check if a technology provides a specific mitigation type.
 */
export function technologyProvidesMitigation(
  technologyId: string,
  mitigationType: PathwayMitigationType
): boolean {
  const capabilities = TECHNOLOGY_MITIGATION_CAPABILITIES[technologyId];
  return capabilities?.includes(mitigationType) ?? false;
}

/**
 * Get all mitigation types a technology provides.
 */
export function getTechnologyMitigations(technologyId: string): PathwayMitigationType[] {
  return TECHNOLOGY_MITIGATION_CAPABILITIES[technologyId] ?? [];
}

/**
 * Get all threat IDs that a mitigation type can mitigate.
 */
export function getMitigatedThreats(mitigationType: PathwayMitigationType): string[] {
  return MITIGATION_TO_THREATS[mitigationType] ?? [];
}

/**
 * Check if a threat can be mitigated by a specific mitigation type.
 */
export function canMitigateThreat(
  threatId: string,
  mitigationType: PathwayMitigationType
): boolean {
  const threats = MITIGATION_TO_THREATS[mitigationType];
  return threats?.includes(threatId) ?? false;
}

/**
 * Get all mitigation types that can mitigate a specific threat.
 */
export function getMitigationTypesForThreat(threatId: string): PathwayMitigationType[] {
  const types: PathwayMitigationType[] = [];
  for (const [mitigationType, threats] of Object.entries(MITIGATION_TO_THREATS)) {
    if (threats.includes(threatId)) {
      types.push(mitigationType as PathwayMitigationType);
    }
  }
  return types;
}
