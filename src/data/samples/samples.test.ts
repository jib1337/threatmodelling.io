// Samples live in this repo but reference technology IDs owned by the catalogue,
// so a catalogue release that renames or drops a technology can silently break a
// sample. The catalogue's own validator cannot see these files; this test is what
// catches it instead.

import { describe, it, expect, beforeAll } from 'vitest';
import { SAMPLE_ARCHITECTURES } from './index';
import { getTechnologyById, loadProviders, providerFromTechId } from '../index';
import type { CloudProvider } from '../schema';

// Every provider a sample touches has to be resolved before IDs can be looked up,
// since non-actor providers are code-split and loaded on demand.
beforeAll(async () => {
  const providers = new Set<CloudProvider>();
  for (const sample of SAMPLE_ARCHITECTURES) {
    for (const node of sample.data.nodes) {
      const provider = providerFromTechId(node.technologyId);
      if (provider) providers.add(provider);
    }
  }
  await loadProviders([...providers]);
});

describe('sample threat models', () => {
  it('ships at least one sample', () => {
    expect(SAMPLE_ARCHITECTURES.length).toBeGreaterThan(0);
  });

  it('has unique sample ids', () => {
    const ids = SAMPLE_ARCHITECTURES.map(s => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(SAMPLE_ARCHITECTURES.map(s => [s.id, s] as const))(
    '%s resolves every technology it references',
    (_id, sample) => {
      const custom = new Set((sample.data.customTechnologies ?? []).map(t => t.id));
      const unresolved = sample.data.nodes
        .filter(n => !custom.has(n.technologyId) && !getTechnologyById(n.technologyId))
        .map(n => `${n.id} → ${n.technologyId}`);

      expect(unresolved).toEqual([]);
    }
  );

  it.each(SAMPLE_ARCHITECTURES.map(s => [s.id, s] as const))(
    '%s has internally consistent nodes, zones and edges',
    (_id, sample) => {
      const nodeIds = new Set(sample.data.nodes.map(n => n.id));
      expect(nodeIds.size).toBe(sample.data.nodes.length);

      const zoneIds = new Set((sample.data.zones ?? []).map(z => z.id));
      const danglingZones = sample.data.nodes
        .filter(n => n.zoneId && !zoneIds.has(n.zoneId))
        .map(n => `${n.id} → ${n.zoneId}`);
      expect(danglingZones).toEqual([]);

      const danglingEdges = (sample.data.edges ?? [])
        .filter(e => !nodeIds.has(e.source) || !nodeIds.has(e.target))
        .map(e => `${e.id}: ${e.source} → ${e.target}`);
      expect(danglingEdges).toEqual([]);
    }
  );
});
