import { describe, it, expect } from 'vitest';
import type { Node } from '@xyflow/react';
import type { ActiveThreat, TechNodeData, Threat } from '../data/schema';
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

  it('omits mitigated threats entirely when hideMitigated is set', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live, removed, encrypted], {}, true);
    expect(md).not.toContain('Mitigated Threats');
    expect(md).not.toContain('Removed Threat');
    expect(md).not.toContain('Intercepted Traffic');
  });

  it('omits the mitigated section when nothing is mitigated', () => {
    const md = buildMarkdownReport('M', [makeNode('n1', 'EC2')], [], [live]);
    expect(md).not.toContain('Mitigated Threats');
  });
});
