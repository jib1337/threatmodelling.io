import { describe, it, expect, beforeAll } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import React, { type ReactNode } from 'react';
import {
  ThreatModelProvider,
  useThreatModel,
} from '../context/ThreatModelContext';
import { loadProviders } from '../data';
import type { ThreatModel, Technology } from '../data/schema';
import { DEFAULT_PATHWAY_MITIGATION_SETTINGS } from '../data/schema';

// Preload real AWS data so getTechnologyById() resolves during IMPORT_MODEL.
beforeAll(async () => {
  await loadProviders(['aws', 'self-hosted']);
});

const wrapper = ({ children }: { children: ReactNode }) =>
  React.createElement(ThreatModelProvider, null, children);

function baseModel(overrides: Partial<ThreatModel> = {}): ThreatModel {
  const now = new Date().toISOString();
  return {
    version: '1.5',
    name: 'Test Model',
    createdAt: now,
    updatedAt: now,
    nodes: [],
    edges: [],
    zones: [],
    pathwayMitigationSettings: DEFAULT_PATHWAY_MITIGATION_SETTINGS,
    ...overrides,
  };
}

describe('Import workflow', () => {
  it('imports the model name', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(baseModel({ name: 'Payments API' }));
    });
    expect(result.current.modelName).toBe('Payments API');
  });

  it('imports nodes with all properties (sensitivity, customName, threatsDisabled, zoneId)', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          zones: [
            {
              id: 'z1',
              zoneType: 'private',
              position: { x: 0, y: 0 },
              dimensions: { width: 300, height: 200 },
              customName: 'VPC',
            },
          ],
          nodes: [
            {
              id: 'n1',
              technologyId: 'aws-ec2',
              position: { x: 100, y: 100 },
              sensitivity: 'restricted',
              customName: 'Prod EC2',
              zoneId: 'z1',
              threatsDisabled: false,
            },
            {
              id: 'n2',
              technologyId: 'aws-rds',
              position: { x: 300, y: 100 },
              sensitivity: 'confidential',
              threatsDisabled: true,
            },
          ],
        }),
      );
    });
    const { nodes } = result.current;
    expect(nodes).toHaveLength(2);
    const n1 = nodes.find(n => n.id === 'n1')!;
    expect(n1.data.sensitivity).toBe('restricted');
    expect(n1.data.customName).toBe('Prod EC2');
    expect(n1.parentId).toBe('z1');
    const n2 = nodes.find(n => n.id === 'n2')!;
    expect(n2.data.sensitivity).toBe('confidential');
    expect(n2.data.threatsDisabled).toBe(true);
  });

  it('imports edges with handles and labels preserved', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [
            { id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } },
            { id: 'n2', technologyId: 'aws-rds', position: { x: 200, y: 0 } },
          ],
          edges: [
            {
              id: 'e1',
              source: 'n1',
              target: 'n2',
              sourceHandle: 'right-source',
              targetHandle: 'left-target',
              label: 'SQL traffic',
            },
          ],
        }),
      );
    });
    const edge = result.current.edges[0];
    expect(edge.sourceHandle).toBe('right-source');
    expect(edge.targetHandle).toBe('left-target');
    expect((edge.data as { label?: string }).label).toBe('SQL traffic');
  });

  it('imports zones with risk reduction settings', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          zones: [
            {
              id: 'z1',
              zoneType: 'private',
              networkType: 'aws-vpc',
              position: { x: 0, y: 0 },
              dimensions: { width: 400, height: 300 },
              customName: 'Prod VPC',
              riskReductionEnabled: true,
              riskReductionPercent: 45,
            },
          ],
        }),
      );
    });
    const boundary = result.current.boundaries[0];
    expect(boundary.data.zoneType).toBe('private');
    expect(boundary.data.networkType).toBe('aws-vpc');
    expect(boundary.data.customName).toBe('Prod VPC');
    expect(boundary.data.riskReductionEnabled).toBe(true);
    expect(boundary.data.riskReductionPercent).toBe(45);
  });

  it('imports pathway mitigation settings verbatim', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const customSettings = {
      ...DEFAULT_PATHWAY_MITIGATION_SETTINGS,
      enabled: true,
      mitigations: {
        ...DEFAULT_PATHWAY_MITIGATION_SETTINGS.mitigations,
        'waf-protection': { enabled: true, mode: 'remove' as const, reductionPercent: 50 },
      },
    };
    await act(async () => {
      await result.current.importModel(
        baseModel({ pathwayMitigationSettings: customSettings }),
      );
    });
    expect(result.current.pathwayMitigationSettings).toEqual(customSettings);
  });

  it('gracefully skips nodes whose technology ID does not resolve', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [
            { id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } },
            { id: 'n-ghost', technologyId: 'aws-nonexistent-service-xyz', position: { x: 0, y: 0 } },
          ],
        }),
      );
    });
    // The valid node is kept; the unknown one is dropped silently
    expect(result.current.nodes.map(n => n.id)).toEqual(['n1']);
  });

  it('defaults node sensitivity to "internal" when omitted', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [{ id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } }],
        }),
      );
    });
    expect(result.current.nodes[0].data.sensitivity).toBe('internal');
  });

  it('populates default risk-reduction settings for private zones when omitted', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          zones: [
            {
              id: 'z1',
              zoneType: 'private',
              position: { x: 0, y: 0 },
              dimensions: { width: 300, height: 200 },
            },
          ],
        }),
      );
    });
    const boundary = result.current.boundaries[0];
    expect(boundary.data.riskReductionEnabled).toBe(true);
    expect(boundary.data.riskReductionPercent).toBe(20);
  });

  it('populates default risk-reduction settings for public zones (disabled) when omitted', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          zones: [
            {
              id: 'z1',
              zoneType: 'public',
              position: { x: 0, y: 0 },
              dimensions: { width: 300, height: 200 },
            },
          ],
        }),
      );
    });
    const boundary = result.current.boundaries[0];
    expect(boundary.data.riskReductionEnabled).toBe(false);
  });

  it('clears selection state when importing', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [{ id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } }],
        }),
      );
    });
    act(() => {
      result.current.setSelectedNode('n1');
    });
    expect(result.current.selectedNodeId).toBe('n1');
    await act(async () => {
      await result.current.importModel(baseModel());
    });
    expect(result.current.selectedNodeId).toBeNull();
  });

  it('imports severityOverrides map', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({ severityOverrides: { 'aws-ec2::t-1': 'critical' } }),
      );
    });
    // Override should be passed through — easiest assertion is via exportModel
    const exported = result.current.exportModel();
    expect(exported.severityOverrides).toEqual({ 'aws-ec2::t-1': 'critical' });
  });

  it('imports implementedControls map', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({ implementedControls: { 'node:n1:t-1::abcdefab': true } }),
      );
    });
    const exported = result.current.exportModel();
    expect(exported.implementedControls).toEqual({ 'node:n1:t-1::abcdefab': true });
  });

  it('imports customTechnologies and makes them resolvable for subsequent nodes', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const customTech: Technology = {
      id: 'custom-thing',
      name: 'Custom Thing',
      provider: 'custom',
      category: 'compute',
      description: 'A custom compute service',
      threatIds: [],
      isCustom: true,
    };
    await act(async () => {
      await result.current.importModel(
        baseModel({
          customTechnologies: [customTech],
          nodes: [
            { id: 'n1', technologyId: 'custom-thing', position: { x: 0, y: 0 } },
          ],
        }),
      );
    });
    expect(result.current.nodes[0].data.technology.id).toBe('custom-thing');
    expect(result.current.customTechnologies[0].id).toBe('custom-thing');
  });

  it('truncates custom technology descriptions over 150 characters', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const longDesc = 'x'.repeat(300);
    const customTech: Technology = {
      id: 'custom-longdesc',
      name: 'Long Desc',
      provider: 'custom',
      category: 'compute',
      description: longDesc,
      threatIds: [],
      isCustom: true,
    };
    await act(async () => {
      await result.current.importModel(baseModel({ customTechnologies: [customTech] }));
    });
    expect(result.current.customTechnologies[0].description.length).toBe(150);
  });

  it('clears previous nodes and zones on subsequent import', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [{ id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } }],
        }),
      );
    });
    expect(result.current.nodes).toHaveLength(1);
    await act(async () => {
      await result.current.importModel(baseModel()); // empty
    });
    expect(result.current.nodes).toHaveLength(0);
    expect(result.current.boundaries).toHaveLength(0);
  });

  it('applies default pathway mitigation settings when the field is missing', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const model = baseModel();
    delete model.pathwayMitigationSettings;
    await act(async () => {
      await result.current.importModel(model);
    });
    expect(result.current.pathwayMitigationSettings).toEqual(DEFAULT_PATHWAY_MITIGATION_SETTINGS);
  });
});

describe('Export workflow', () => {
  it('exports the current model name', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(baseModel({ name: 'Exported API' }));
    });
    const exported = result.current.exportModel();
    expect(exported.name).toBe('Exported API');
  });

  it('emits version 1.5', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(baseModel());
    });
    expect(result.current.exportModel().version).toBe('1.5');
  });

  it('exports nodes with their full shape (id, technologyId, position, sensitivity, customName, zoneId)', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          zones: [
            {
              id: 'z1',
              zoneType: 'private',
              position: { x: 0, y: 0 },
              dimensions: { width: 300, height: 200 },
            },
          ],
          nodes: [
            {
              id: 'n1',
              technologyId: 'aws-ec2',
              position: { x: 100, y: 200 },
              sensitivity: 'restricted',
              customName: 'DB',
              zoneId: 'z1',
            },
          ],
        }),
      );
    });
    const exported = result.current.exportModel();
    const node = exported.nodes[0];
    expect(node.id).toBe('n1');
    expect(node.technologyId).toBe('aws-ec2');
    expect(node.position).toEqual({ x: 100, y: 200 });
    expect(node.sensitivity).toBe('restricted');
    expect(node.customName).toBe('DB');
    expect(node.zoneId).toBe('z1');
  });

  it('exports edges with handles and labels', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [
            { id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } },
            { id: 'n2', technologyId: 'aws-rds', position: { x: 200, y: 0 } },
          ],
          edges: [
            {
              id: 'e1',
              source: 'n1',
              target: 'n2',
              sourceHandle: 'bottom-source',
              targetHandle: 'top-target',
              label: 'JDBC',
            },
          ],
        }),
      );
    });
    const exported = result.current.exportModel();
    expect(exported.edges[0]).toMatchObject({
      id: 'e1',
      source: 'n1',
      target: 'n2',
      sourceHandle: 'bottom-source',
      targetHandle: 'top-target',
      label: 'JDBC',
    });
  });

  it('omits severityOverrides / implementedControls keys when empty', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(baseModel());
    });
    const exported = result.current.exportModel();
    expect(exported.severityOverrides).toBeUndefined();
    expect(exported.implementedControls).toBeUndefined();
  });

  it('omits customTechnologies key when empty', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(baseModel());
    });
    expect(result.current.exportModel().customTechnologies).toBeUndefined();
  });
});

describe('Round-trip', () => {
  it('preserves full model data through export → import → export', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const original = baseModel({
      name: 'RT Test',
      zones: [
        {
          id: 'z1',
          zoneType: 'private',
          position: { x: 0, y: 0 },
          dimensions: { width: 300, height: 200 },
          customName: 'VPC',
          riskReductionEnabled: true,
          riskReductionPercent: 40,
        },
      ],
      nodes: [
        {
          id: 'n1',
          technologyId: 'aws-ec2',
          position: { x: 100, y: 100 },
          sensitivity: 'restricted',
          customName: 'App Server',
          zoneId: 'z1',
          threatsDisabled: false,
        },
      ],
      edges: [],
      severityOverrides: { 'aws-ec2::t-x': 'critical' },
      implementedControls: { 'node:n1:t-x::deadbeef': true },
    });

    await act(async () => {
      await result.current.importModel(original);
    });
    const firstExport = result.current.exportModel();

    // Re-import and re-export; the payload should be stable across the cycle
    await act(async () => {
      await result.current.importModel(firstExport);
    });
    const secondExport = result.current.exportModel();

    // Normalize: the exporter sets fresh timestamps, so ignore those
    const stripTimestamps = (m: ThreatModel) => ({
      ...m,
      createdAt: undefined,
      updatedAt: undefined,
    });
    expect(stripTimestamps(secondExport)).toEqual(stripTimestamps(firstExport));
  });

  it('preserves node IDs and edge connections through round-trip', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    await act(async () => {
      await result.current.importModel(
        baseModel({
          nodes: [
            { id: 'node-alpha', technologyId: 'aws-ec2', position: { x: 0, y: 0 } },
            { id: 'node-beta', technologyId: 'aws-rds', position: { x: 200, y: 0 } },
          ],
          edges: [
            {
              id: 'edge-1',
              source: 'node-alpha',
              target: 'node-beta',
              sourceHandle: 'bottom-source',
              targetHandle: 'top-target',
              label: 'SQL',
            },
          ],
        }),
      );
    });
    const exported = result.current.exportModel();
    expect(exported.nodes.map(n => n.id).sort()).toEqual(['node-alpha', 'node-beta']);
    expect(exported.edges[0]).toMatchObject({
      id: 'edge-1',
      source: 'node-alpha',
      target: 'node-beta',
    });
  });
});

describe('Version compatibility', () => {
  it('accepts v1.0 format (no zones field)', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const legacy = {
      version: '1.0',
      name: 'Legacy',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      nodes: [{ id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } }],
      edges: [],
    } as unknown as ThreatModel;
    await act(async () => {
      await result.current.importModel(legacy);
    });
    expect(result.current.nodes).toHaveLength(1);
    expect(result.current.boundaries).toHaveLength(0);
  });

  it('accepts v1.2 format (no pathway mitigation settings)', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const legacy = {
      version: '1.2',
      name: 'Legacy',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      nodes: [],
      edges: [],
      zones: [],
    } as unknown as ThreatModel;
    await act(async () => {
      await result.current.importModel(legacy);
    });
    // Should fall back to defaults, with the feature globally off
    expect(result.current.pathwayMitigationSettings.enabled).toBe(false);
  });

  it('fills in default handles for edges missing sourceHandle / targetHandle', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const legacy = {
      version: '1.0',
      name: 'Legacy edges',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      nodes: [
        { id: 'n1', technologyId: 'aws-ec2', position: { x: 0, y: 0 } },
        { id: 'n2', technologyId: 'aws-rds', position: { x: 200, y: 0 } },
      ],
      edges: [{ id: 'e1', source: 'n1', target: 'n2' }],
    } as unknown as ThreatModel;
    await act(async () => {
      await result.current.importModel(legacy);
    });
    const edge = result.current.edges[0];
    // Old edges are assumed bottom-of-source → top-of-target
    expect(edge.sourceHandle).toBe('bottom-source');
    expect(edge.targetHandle).toBe('top-target');
  });

  it('treats a missing implementedControls field as all-unchecked', async () => {
    const { result } = renderHook(() => useThreatModel(), { wrapper });
    const legacy = {
      version: '1.4',
      name: 'No controls field',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      nodes: [],
      edges: [],
      zones: [],
    } as unknown as ThreatModel;
    await act(async () => {
      await result.current.importModel(legacy);
    });
    const exported = result.current.exportModel();
    expect(exported.implementedControls).toBeUndefined();
  });
});
