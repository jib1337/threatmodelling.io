// Sample threat models shipped with the app.
//
// These are app documents, not catalogue data: each one is a saved ThreatModel
// complete with canvas coordinates, zones and a save-format version, so it is
// meaningful only to this app and lives here rather than in the technology and
// threat catalogue. They do reference catalogue technology IDs — samples.test.ts
// checks those still resolve after a catalogue upgrade.
//
// index.json carries the picker metadata; each entry names the model file loaded
// alongside it.

import type { ThreatModel } from '../schema';
import sampleIndex from './index.json';

export interface SampleArchitecture {
  id: string;
  name: string;
  description: string;
  providerTag: string;
  data: ThreatModel;
}

interface SampleIndexEntry {
  id: string;
  name: string;
  description: string;
  providerTag: string;
  file: string;
}

// Sample models are small and the picker previews them immediately, so they are
// bundled eagerly rather than code-split per sample. index.json is the metadata,
// not a model, so it is excluded.
const SAMPLE_MODELS = import.meta.glob<{ default: ThreatModel }>(
  ['./*.json', '!./index.json'],
  { eager: true }
);

export const SAMPLE_ARCHITECTURES: SampleArchitecture[] = (
  sampleIndex.samples as SampleIndexEntry[]
).map(entry => {
  const model = SAMPLE_MODELS[`./${entry.file}`];
  if (!model) {
    throw new Error(`Sample "${entry.id}" references missing model file ${entry.file}`);
  }
  return {
    id: entry.id,
    name: entry.name,
    description: entry.description,
    providerTag: entry.providerTag,
    data: model.default as unknown as ThreatModel,
  };
});
