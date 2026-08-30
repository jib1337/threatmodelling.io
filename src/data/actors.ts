// External actors

import actorsData from './actors.json';

export const ACTOR_PROVIDER = 'actor';
export const ACTOR_PROVIDER_LABEL = 'Actor';

export const ACTOR_CATEGORY = 'actor';
export const ACTOR_CATEGORY_LABEL = 'Actor';

/** Every actor ID starts with this, so it can be told apart from a catalogue ID. */
export const ACTOR_ID_PREFIX = 'actor-';

interface ActorData {
  provider: string;
  displayName: string;
  idPrefix: string;
  services: {
    id: string;
    name: string;
    provider: string;
    category: string;
    description: string;
    threatIds: string[];
  }[];
}

export const ACTORS = actorsData as ActorData;
