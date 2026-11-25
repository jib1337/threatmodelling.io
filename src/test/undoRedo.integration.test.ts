import { describe, it, expect, beforeAll } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import React, { type ReactNode } from 'react';
import { ThreatModelProvider, useThreatModel } from '../context/ThreatModelContext';
import { loadProviders } from '../data';
import type { DataSensitivity, ThreatModel } from '../data/schema';
import { DEFAULT_PATHWAY_MITIGATION_SETTINGS } from '../data/schema';

beforeAll(async () => {
  await loadProviders(['aws']);
});

const wrapper = ({ children }: { children: ReactNode }) =>
  React.createElement(ThreatModelProvider, null, children);

const model: ThreatModel = {
  version: '1.6',
  name: 'Undo',
  createdAt: '',
  updatedAt: '',
  nodes: [{ id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 }, sensitivity: 'public' }],
  edges: [],
  zones: [],
  pathwayMitigationSettings: DEFAULT_PATHWAY_MITIGATION_SETTINGS,
};

async function setup() {
  const { result } = renderHook(() => useThreatModel(), { wrapper });
  await act(async () => { await result.current.importModel(model); });
  const sensitivity = () => result.current.nodes.find(n => n.id === 'n1')?.data.sensitivity ?? 'no node';
  const change = (s: DataSensitivity) => act(() => { result.current.updateNodeSensitivity('n1', s); });
  const undo = () => act(() => { result.current.undo(); });
  const redo = () => act(() => { result.current.redo(); });
  return { result, sensitivity, change, undo, redo };
}

describe('Undo / redo', () => {
  it('undoes one action at a time, most recent first', async () => {
    const { sensitivity, change, undo } = await setup();
    change('internal');
    change('confidential');
    change('restricted');
    const seen = [sensitivity()];
    for (let i = 0; i < 3; i++) { undo(); seen.push(sensitivity()); }
    expect(seen).toEqual(['restricted', 'confidential', 'internal', 'public']);
  });

  it('undoes past the first edit back to before the import', async () => {
    const { result, change, undo, sensitivity } = await setup();
    change('internal');
    undo();
    expect(sensitivity()).toBe('public');
    undo();
    expect(result.current.nodes).toEqual([]);
    expect(result.current.canUndo).toBe(false);
  });

  it('redoes every undone step, including the latest', async () => {
    const { result, sensitivity, change, undo, redo } = await setup();
    change('internal');
    change('confidential');
    undo();
    undo();
    expect(sensitivity()).toBe('public');
    redo();
    expect(sensitivity()).toBe('internal');
    redo();
    expect(sensitivity()).toBe('confidential');
    expect(result.current.canRedo).toBe(false);
    redo();
    expect(sensitivity()).toBe('confidential');
  });

  it('alternating undo and redo stays on the same two states', async () => {
    const { sensitivity, change, undo, redo } = await setup();
    change('internal');
    change('confidential');
    for (let i = 0; i < 3; i++) {
      undo();
      expect(sensitivity()).toBe('internal');
      redo();
      expect(sensitivity()).toBe('confidential');
    }
  });

  it('a new action after undo discards the redo future without a duplicate step', async () => {
    const { result, sensitivity, change, undo, redo } = await setup();
    change('internal');
    change('confidential');
    undo();
    change('restricted');
    expect(result.current.canRedo).toBe(false);
    redo();
    expect(sensitivity()).toBe('restricted');
    undo();
    expect(sensitivity()).toBe('internal');
    undo();
    expect(sensitivity()).toBe('public');
  });

  it('reports canUndo and canRedo accurately', async () => {
    const { result, change, undo } = await setup();
    change('internal');
    expect(result.current.canUndo).toBe(true);
    expect(result.current.canRedo).toBe(false);
    undo();
    expect(result.current.canRedo).toBe(true);
  });

  it('starts with nothing to undo', () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
  });
});
