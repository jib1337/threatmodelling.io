import { describe, it, expect } from 'vitest';
import type { Node } from '@xyflow/react';
import type { ActiveThreat, CustomControlsMap, TechNodeData, Threat } from '../data/schema';
import { HIDE_ALL_MITIGATED, SHOW_ALL_MITIGATED } from '../data/schema';
import { buildMarkdownReport } from './markdownExport';

// --- fixtures --------------------------------------------------------------

const makeThreat = (overrides: Partial<Threat> = {}): Threat => ({
  id: 't-1',
  name: 'Generic Threat',
  description: 'Some generic threat description',
  severity: 'high',
  stride: ['tampering'],
  mitreTechniques: [],
  controls: [{ id: 'ctrl-1', description: 'Apply best practices' }],
  ...overrides,
});

const makeNode = (id: string, name: string): Node<TechNodeData> => ({
  id,
  type: 'techNode',
  position: { x: 0, y: 0 },
  data: {
    technology: {
      id: `aws-${name}`,
      name,
      provider: 'aws',
      category: 'compute',
      description: '',
      threatIds: [],
    },
    label: name,
    sensitivity: 'internal',
  },
});

const makeActive = (threat: Threat, overrides: Partial<ActiveThreat> = {}): ActiveThreat => ({
  threat,
  sourceNodeId: 'n1',
  sourceTechName: 'EC2',
  sensitivity: 'internal',
  riskScore: 6,
  riskLevel: 'medium',
  ...overrides,
});

const live = makeActive(makeThreat({ id: 'live', name: 'Live Threat' }));
const removed = makeActive(makeThreat({ id: 'removed', name: 'Removed Threat' }), {
  riskScore: 12,
  riskLevel: 'high',
  pathwayMitigatedBy: {
    mitigationType: 'waf-protection',
    mitigatingTechId: 'aws-waf',
    mitigatingTechName: 'AWS WAF',
    mode: 'remove',
  },
});
const encrypted = makeActive(makeThreat({ id: 'mitm', name: 'Intercepted Traffic' }), {
  sourceNodeId: 'e1',
  sourceTechName: 'EC2 → RDS',
  isConnectionThreat: true,
  mitigatedBy: 'encrypted',
});

// Return the text of one "## " section, up to the next one
function section(md: string, heading: string): string {
  const start = md.indexOf(`## ${heading}`);
  if (start === -1) return '';
  const next = md.indexOf('\n## ', start + 1);
  return md.slice(start, next === -1 ? undefined : next);
}

describe('buildMarkdownReport', () => {
  it('keeps mitigated threats out of the active sections and totals', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live, removed, encrypted]);
    expect(section(md, 'Overview')).toContain('| Total Threats | 1 |');
    expect(section(md, 'Top Threats by Risk Score')).toContain('Live Threat');
    expect(section(md, 'Top Threats by Risk Score')).not.toContain('Removed Threat');
    expect(section(md, 'Component Details')).not.toContain('Removed Threat');
  });

  it('lists mitigated threats in their own section with what mitigates them', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live, removed, encrypted]);
    expect(section(md, 'Overview')).toContain('| Mitigated Threats | 2 |');
    const mitigated = section(md, 'Mitigated Threats');
    expect(mitigated).toContain('| Removed Threat | EC2 | 12 (');
    expect(mitigated).toContain('| AWS WAF (WAF Protection) |');
    expect(mitigated).toContain('| Intercepted Traffic | EC2 → RDS |');
    expect(mitigated).toContain('| TLS Encrypted |');
    // Highest unmitigated score first
    expect(mitigated.indexOf('Removed Threat')).toBeLessThan(mitigated.indexOf('Intercepted Traffic'));
  });

  it('omits mitigated threats entirely when every kind is hidden', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live, removed, encrypted], {}, HIDE_ALL_MITIGATED);
    expect(md).not.toContain('Mitigated Threats');
    expect(md).not.toContain('Removed Threat');
    expect(md).not.toContain('Intercepted Traffic');
  });

  it('omits only the hidden kind of mitigated threat', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live, removed, encrypted], {},
      { ...SHOW_ALL_MITIGATED, hideConnection: true });
    expect(md).toContain('Mitigated Threats');
    expect(md).toContain('Removed Threat');
    expect(md).not.toContain('Intercepted Traffic');
  });

  it('omits the mitigated section when nothing is mitigated', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live]);
    expect(md).not.toContain('Mitigated Threats');
  });
});

describe('buildMarkdownReport custom controls', () => {
  const node = makeNode('n1', 'EC2');
  const threat = makeThreat({ id: 't-1', name: 'Generic Threat' });
  const component = makeActive(threat);

  // The "Mitigating Controls" cell of the first table that has one
  function controlsCell(md: string, from = 0): string {
    const start = md.indexOf('| Mitigating Controls | ', from);
    expect(start).toBeGreaterThan(-1);
    const end = md.indexOf(' |\n', start + 22);
    return md.slice(start + '| Mitigating Controls | '.length, end);
  }

  it('lists custom controls after the catalogue ones, unmarked, with tick state', () => {
    const custom: CustomControlsMap = {
      'node:n1:t-1': [
        { id: 'a', description: 'Quarterly access review' },
        { id: 'b', description: 'Pen test' },
      ],
    };
    const md = buildMarkdownReport('M', [node], [], [component], { 'node:n1:t-1::custom:b': true }, SHOW_ALL_MITIGATED, custom);
    expect(controlsCell(md).split('<br>')).toEqual([
      '☐ Apply best practices',
      '☐ Quarterly access review',
      '☑ ~~Pen test~~',
    ]);
  });

  it('only shows a node\'s own custom controls', () => {
    const custom: CustomControlsMap = { 'node:n2:t-1': [{ id: 'a', description: 'Belongs to n2' }] };
    const md = buildMarkdownReport('M', [node], [], [component], {}, SHOW_ALL_MITIGATED, custom);
    expect(md).not.toContain('Belongs to n2');
  });

  it('uses the consolidated scope for connection threats', () => {
    const conn = makeActive(makeThreat({ id: 't-conn', name: 'Conn Threat' }), {
      isConnectionThreat: true,
      connectionInfo: { edgeId: 'e1', sourceNodeName: 'EC2', targetNodeName: 'RDS' },
    });
    const custom: CustomControlsMap = { 'connection:t-conn': [{ id: 'a', description: 'mTLS everywhere' }] };
    const md = buildMarkdownReport(
      'M', [node, makeNode('n2', 'RDS')], [{ id: 'e1', source: 'n1', target: 'n2' }], [conn], {}, SHOW_ALL_MITIGATED, custom,
    );
    expect(controlsCell(md)).toContain('☐ mTLS everywhere');
  });

  it('includes custom controls on zone threats', () => {
    const zone = makeActive(makeThreat({ id: 't-zone', name: 'Zone Threat', controls: [] }), {
      isZoneThreat: true,
      zoneInfo: { boundaryId: 'z1', zoneName: 'VPC' },
    });
    const custom: CustomControlsMap = { 'zone:t-zone': [{ id: 'a', description: 'Egress allow-list' }] };
    const md = buildMarkdownReport('M', [], [], [zone], { 'zone:t-zone::custom:a': true }, SHOW_ALL_MITIGATED, custom);
    const zones = section(md, 'Network Zone Threats');
    expect(controlsCell(zones)).toBe('☑ ~~Egress allow\\-list~~');
  });

  it('escapes HTML and Markdown in custom text so it renders as plain text', () => {
    const custom: CustomControlsMap = {
      'node:n1:t-1': [{ id: 'a', description: '<img src=x onerror=alert(1)> [click](javascript:alert(1)) **bold** a|b & c' }],
    };
    const md = buildMarkdownReport('M', [node], [], [component], {}, SHOW_ALL_MITIGATED, custom);
    const line = controlsCell(md).split('<br>')[1];
    expect(line).not.toContain('<img');
    expect(line).toContain('&lt;img src=x onerror=alert\\(1\\)&gt;');
    expect(line).not.toMatch(/(?<!\\)\]\(/); // no live link syntax
    expect(line).toContain('\\*\\*bold\\*\\*');
    expect(line).toContain('a\\|b &amp; c');
  });

  it('produces identical output when there are no custom controls', () => {
    const without = buildMarkdownReport('M', [node], [], [component], {}, SHOW_ALL_MITIGATED);
    const withEmpty = buildMarkdownReport('M', [node], [], [component], {}, SHOW_ALL_MITIGATED, {});
    // Only the timestamp could differ; strip the footer
    const strip = (md: string) => md.replace(/\*Generated by[^\n]*\n/, '');
    expect(strip(withEmpty)).toBe(strip(without));
  });
});
