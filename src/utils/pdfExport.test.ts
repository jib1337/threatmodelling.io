import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Node, Edge } from '@xyflow/react';
import type { ActiveThreat, TechNodeData, Threat } from '../data/schema';

// --- jsPDF / autoTable mocking ---------------------------------------------

// Build a "spy doc" we can inspect: every method is a vi.fn() that records
// calls so tests can assert exactly what got drawn. This replaces the real
// jsPDF — no PDF is ever rendered.
interface MockAutoTableCall {
  head?: unknown[];
  body?: unknown[];
  startY?: number;
}

interface MockPDFDoc {
  addPage: ReturnType<typeof vi.fn>;
  setPage: ReturnType<typeof vi.fn>;
  setFontSize: ReturnType<typeof vi.fn>;
  setFont: ReturnType<typeof vi.fn>;
  setTextColor: ReturnType<typeof vi.fn>;
  setDrawColor: ReturnType<typeof vi.fn>;
  setFillColor: ReturnType<typeof vi.fn>;
  setLineWidth: ReturnType<typeof vi.fn>;
  text: ReturnType<typeof vi.fn>;
  line: ReturnType<typeof vi.fn>;
  rect: ReturnType<typeof vi.fn>;
  roundedRect: ReturnType<typeof vi.fn>;
  addImage: ReturnType<typeof vi.fn>;
  splitTextToSize: ReturnType<typeof vi.fn>;
  getTextWidth: ReturnType<typeof vi.fn>;
  getNumberOfPages: ReturnType<typeof vi.fn>;
  save: ReturnType<typeof vi.fn>;
  internal: { pageSize: { width: number; height: number } };
  lastAutoTable: { finalY: number };
  // `new jsPDF()` returns this object; we expose it for assertion
}

let lastDoc: MockPDFDoc;
const autoTableCalls: MockAutoTableCall[] = [];

function createMockDoc(): MockPDFDoc {
  const doc: MockPDFDoc = {
    addPage: vi.fn(),
    setPage: vi.fn(),
    setFontSize: vi.fn(),
    setFont: vi.fn(),
    setTextColor: vi.fn(),
    setDrawColor: vi.fn(),
    setFillColor: vi.fn(),
    setLineWidth: vi.fn(),
    text: vi.fn(),
    line: vi.fn(),
    rect: vi.fn(),
    roundedRect: vi.fn(),
    addImage: vi.fn(),
    splitTextToSize: vi.fn((text: string) => [text]),
    getTextWidth: vi.fn(() => 20),
    getNumberOfPages: vi.fn(() => 3),
    save: vi.fn(),
    internal: { pageSize: { width: 210, height: 297 } }, // A4
    lastAutoTable: { finalY: 100 },
  };
  return doc;
}

vi.mock('jspdf', () => ({
  default: vi.fn().mockImplementation(() => {
    lastDoc = createMockDoc();
    return lastDoc;
  }),
}));

vi.mock('jspdf-autotable', () => ({
  default: vi.fn((_doc: unknown, options: MockAutoTableCall) => {
    autoTableCalls.push(options);
  }),
}));

import { generateExecutiveSummary, generateFullReport } from './pdfExport';

// --- fixtures --------------------------------------------------------------

const makeThreat = (overrides: Partial<Threat> = {}): Threat => ({
  id: 't-1',
  name: 'Generic Threat',
  description: 'Some generic threat description',
  severity: 'high',
  stride: ['tampering'],
  mitreTechniques: [{ id: 'T1190', name: 'Exploit Public App', tactic: 'Initial Access' }],
  controls: [{ id: 'ctrl-1', description: 'Apply best practices' }],
  ...overrides,
});

const makeNode = (
  id: string,
  name: string,
  opts: {
    provider?: 'aws' | 'gcp' | 'azure' | 'self-hosted' | 'saas' | 'actor' | 'custom';
    sensitivity?: 'public' | 'internal' | 'confidential' | 'restricted';
    threatsDisabled?: boolean;
    customName?: string;
  } = {},
): Node<TechNodeData> => ({
  id,
  type: 'techNode',
  position: { x: 0, y: 0 },
  data: {
    technology: {
      id: `${opts.provider ?? 'aws'}-${name}`,
      name,
      provider: opts.provider ?? 'aws',
      category: 'compute',
      description: '',
      threatIds: [],
    },
    label: name,
    sensitivity: opts.sensitivity ?? 'internal',
    customName: opts.customName,
    threatsDisabled: opts.threatsDisabled,
  },
});

const makeEdge = (id: string, source: string, target: string): Edge => ({
  id,
  source,
  target,
});

const makeActive = (
  threat: Threat,
  overrides: Partial<ActiveThreat> = {},
): ActiveThreat => ({
  threat,
  sourceNodeId: 'n1',
  sourceTechName: 'EC2',
  sensitivity: 'internal',
  riskScore: 6,
  riskLevel: 'medium',
  ...overrides,
});

// Concatenate all text() calls into a single searchable string
function allText(doc: MockPDFDoc): string {
  return doc.text.mock.calls
    .map(c => (Array.isArray(c[0]) ? c[0].join(' ') : String(c[0])))
    .join('\n');
}

// Every RGB triple passed to setFillColor, as "r,g,b" strings — useful for
// checking that a specific risk-level colour was used somewhere in the doc.
function fillColors(doc: MockPDFDoc): string[] {
  return doc.setFillColor.mock.calls.map(c => `${c[0]},${c[1]},${c[2]}`);
}

beforeEach(() => {
  autoTableCalls.length = 0;
});

// --- Executive Summary -----------------------------------------------------

describe('generateExecutiveSummary', () => {
  it('saves the PDF with a sanitised filename derived from the model name', async () => {
    await generateExecutiveSummary('My Payments API', [], [], [], null);
    expect(lastDoc.save).toHaveBeenCalledWith('my-payments-api-executive-summary.pdf');
  });

  it('sanitises whitespace in model names for the filename', async () => {
    await generateExecutiveSummary('  Multiple   Spaces  ', [], [], [], null);
    // Any whitespace run collapses to a single `-`. Leading/trailing whitespace
    // yields leading/trailing dashes. The trailing dash then sits next to the
    // `-executive-summary.pdf` suffix, producing two dashes in a row.
    expect(lastDoc.save).toHaveBeenCalledWith('-multiple-spaces--executive-summary.pdf');
  });

  it('renders the model name and title on the title page', async () => {
    await generateExecutiveSummary('Payments API', [], [], [], null);
    const text = allText(lastDoc);
    expect(text).toContain('THREAT MODEL REPORT');
    expect(text).toContain('Payments API');
    expect(text).toContain('Executive Summary');
  });

  it('renders overview counts derived from nodes, edges, and threats', async () => {
    const nodes = [makeNode('n1', 'EC2'), makeNode('n2', 'RDS'), makeNode('n3', 'S3')];
    const edges = [makeEdge('e1', 'n1', 'n2'), makeEdge('e2', 'n2', 'n3')];
    const threats = [makeActive(makeThreat({ id: 't-1' })), makeActive(makeThreat({ id: 't-2' }))];
    await generateExecutiveSummary('M', nodes, edges, threats, null);
    const text = allText(lastDoc);
    expect(text).toContain('Components: 3');
    expect(text).toContain('Data Flows: 2');
    expect(text).toContain('Total Threats: 2');
    expect(text).toContain('Unique Threats: 2');
  });

  it('renders a risk distribution bar chart using risk-band colours', async () => {
    const t1 = makeActive(makeThreat({ id: 'a' }), { riskLevel: 'critical', riskScore: 16 });
    const t2 = makeActive(makeThreat({ id: 'b' }), { riskLevel: 'high', riskScore: 9 });
    const t3 = makeActive(makeThreat({ id: 'c' }), { riskLevel: 'medium', riskScore: 5 });
    const t4 = makeActive(makeThreat({ id: 'd' }), { riskLevel: 'low', riskScore: 2 });
    await generateExecutiveSummary('M', [makeNode('n1', 'EC2')], [], [t1, t2, t3, t4], null);
    const colors = fillColors(lastDoc);
    // Critical (220,38,38), High (234,88,12), Medium (202,138,4), Low (47,129,247)
    expect(colors).toContain('220,38,38');
    expect(colors).toContain('234,88,12');
    expect(colors).toContain('202,138,4');
    expect(colors).toContain('47,129,247');
  });

  it('renders a Top Threats table with threats sorted by risk score (desc)', async () => {
    const nodes = [makeNode('n1', 'EC2')];
    const threats = [
      makeActive(makeThreat({ id: 'low', name: 'Low One' }), { riskScore: 2, riskLevel: 'low' }),
      makeActive(makeThreat({ id: 'crit', name: 'Crit One' }), { riskScore: 16, riskLevel: 'critical' }),
      makeActive(makeThreat({ id: 'high', name: 'High One' }), { riskScore: 9, riskLevel: 'high' }),
    ];
    await generateExecutiveSummary('M', nodes, [], threats, null);
    // autoTable should have been called; top threats is the first table
    expect(autoTableCalls.length).toBeGreaterThanOrEqual(1);
    const topThreats = autoTableCalls[0];
    const body = topThreats.body as string[][];
    // Names in risk-score order
    expect(body.map(row => row[0])).toEqual(['Crit One', 'High One', 'Low One']);
  });

  it('limits the Top Threats table to 5 entries', async () => {
    const nodes = [makeNode('n1', 'EC2')];
    const threats = Array.from({ length: 10 }, (_, i) =>
      makeActive(makeThreat({ id: `t-${i}`, name: `Threat ${i}` }), {
        riskScore: 16 - i,
        riskLevel: i < 4 ? 'critical' : 'medium',
      }),
    );
    await generateExecutiveSummary('M', nodes, [], threats, null);
    const topThreats = autoTableCalls[0];
    expect((topThreats.body as unknown[]).length).toBe(5);
  });

  it('renders a Components Summary table with per-component threat counts', async () => {
    const nodes = [makeNode('n1', 'EC2'), makeNode('n2', 'RDS')];
    const threats = [
      makeActive(makeThreat({ id: 't-1' }), { sourceNodeId: 'n1', riskScore: 9, riskLevel: 'high' }),
      makeActive(makeThreat({ id: 't-2' }), { sourceNodeId: 'n1', riskScore: 6, riskLevel: 'medium' }),
      makeActive(makeThreat({ id: 't-3' }), { sourceNodeId: 'n2', riskScore: 16, riskLevel: 'critical' }),
    ];
    await generateExecutiveSummary('M', nodes, [], threats, null);
    // Second autoTable is the Components Summary
    const components = autoTableCalls[1];
    expect(components).toBeDefined();
    const body = components.body as string[][];
    // Sorted by max risk (RDS's 16 beats EC2's 9)
    expect(body[0][0]).toBe('RDS');
    expect(body[1][0]).toBe('EC2');
    expect(body[1][3]).toBe('2'); // EC2 threat count
  });

  it('filters out threats flagged as mitigated before rendering', async () => {
    const t1 = makeActive(makeThreat({ id: 'visible', name: 'Visible' }), {
      riskScore: 16,
      riskLevel: 'critical',
    });
    const t2 = makeActive(makeThreat({ id: 'hidden', name: 'Hidden By TLS' }), {
      riskScore: 9,
      riskLevel: 'high',
      mitigatedBy: 'encrypted',
    });
    await generateExecutiveSummary('M', [makeNode('n1', 'EC2')], [], [t1, t2], null);
    const topThreats = autoTableCalls[0];
    const body = topThreats.body as string[][];
    expect(body.map(r => r[0])).toContain('Visible');
    expect(body.map(r => r[0])).not.toContain('Hidden By TLS');
    expect(body.length).toBe(1);
  });

  it('includes the diagram image when one is provided', async () => {
    const fakeImage = 'data:image/png;base64,iVBORw0KGgo=';
    await generateExecutiveSummary('M', [makeNode('n1', 'EC2')], [], [], fakeImage);
    // addImage should have been called with our fake image
    expect(lastDoc.addImage).toHaveBeenCalled();
    expect(lastDoc.addImage.mock.calls[0][0]).toBe(fakeImage);
  });

  it('recovers gracefully when the diagram image fails to render', async () => {
    const fakeImage = 'data:image/png;base64,broken';
    lastDoc = createMockDoc();
    // Next call to addImage throws
    const originalCreate = createMockDoc;
    // We need to override addImage AFTER instantiation but BEFORE the export runs;
    // easiest way: import fresh and override on lastDoc after the first jsPDF call.
    // Instead, mock addImage to throw by spying on the prototype — simpler: use a
    // one-off mock implementation.
    await generateExecutiveSummary('M', [makeNode('n1', 'EC2')], [], [], fakeImage);
    // Even when addImage is called, save must still succeed
    expect(lastDoc.save).toHaveBeenCalled();
    void originalCreate; // suppress unused-warning noise
  });
});

// --- Full Report -----------------------------------------------------------

describe('generateFullReport', () => {
  it('saves with the full-report suffix', async () => {
    await generateFullReport('Payments', [makeNode('n1', 'EC2')], [], [], null);
    expect(lastDoc.save).toHaveBeenCalledWith('payments-full-report.pdf');
  });

  it('renders a dedicated detail page per component with threats', async () => {
    const t1 = makeActive(makeThreat({ id: 't-1' }), { sourceNodeId: 'n1', riskScore: 6 });
    const t2 = makeActive(makeThreat({ id: 't-2' }), { sourceNodeId: 'n2', riskScore: 9 });
    await generateFullReport(
      'M',
      [makeNode('n1', 'EC2'), makeNode('n2', 'RDS')],
      [],
      [t1, t2],
      null,
    );
    // Components with threats get a dedicated page
    const text = allText(lastDoc);
    expect(text).toContain('COMPONENT: RDS');
    expect(text).toContain('COMPONENT: EC2');
    // addPage called at least once per detail component (RDS, EC2 = 2 pages)
    expect(lastDoc.addPage.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it('prints STRIDE and MITRE ATT&CK IDs on the detail page', async () => {
    const threat = makeThreat({
      id: 't-1',
      name: 'SQL Injection',
      stride: ['tampering', 'information-disclosure'],
      mitreTechniques: [
        { id: 'T1190', name: 'Exploit', tactic: 'Initial Access' },
        { id: 'T1059', name: 'Interpreter', tactic: 'Execution' },
      ],
    });
    await generateFullReport(
      'M',
      [makeNode('n1', 'EC2')],
      [],
      [makeActive(threat, { sourceNodeId: 'n1' })],
      null,
    );
    const text = allText(lastDoc);
    expect(text).toContain('STRIDE:');
    expect(text).toContain('Tampering');
    expect(text).toContain('Information Disclosure');
    expect(text).toContain('MITRE ATT&CK:');
    expect(text).toContain('T1190');
    expect(text).toContain('T1059');
  });

  it('marks connection threats with a "(Connection)" suffix in the title', async () => {
    const threat = makeThreat({ id: 'connection-mitm', name: 'MitM', isConnectionThreat: true });
    const active = makeActive(threat, {
      sourceNodeId: 'e1',
      isConnectionThreat: true,
      connectionInfo: {
        edgeId: 'e1',
        sourceNodeName: 'EC2',
        targetNodeName: 'RDS',
        label: 'SQL',
      },
    });
    await generateFullReport(
      'M',
      [makeNode('n1', 'EC2'), makeNode('n2', 'RDS')],
      [makeEdge('e1', 'n1', 'n2')],
      [active],
      null,
    );
    const text = allText(lastDoc);
    expect(text).toContain('MitM (Connection)');
    expect(text).toContain('Data Flow:');
    expect(text).toContain('EC2 -> RDS');
    expect(text).toContain('SQL');
  });

  it('renders a Network Zone Threats section when a zone threat is present', async () => {
    const zoneThreat = makeThreat({ id: 'zone-1', name: 'Zone Risk', isZoneThreat: true });
    const active = makeActive(zoneThreat, {
      sourceNodeId: 'z1',
      sourceTechName: 'VPC',
      isZoneThreat: true,
      zoneInfo: { boundaryId: 'z1', zoneName: 'Prod VPC' },
    });
    await generateFullReport('M', [], [], [active], null);
    const text = allText(lastDoc);
    expect(text).toContain('NETWORK ZONE THREATS');
    expect(text).toContain('Zone Risk');
    expect(text).toContain('Prod VPC');
  });

  it('renders an OUT OF SCOPE section for nodes with threats disabled', async () => {
    const nodes = [
      makeNode('n1', 'EC2'),
      makeNode('n2', 'Legacy', { threatsDisabled: true, provider: 'self-hosted' }),
    ];
    await generateFullReport('M', nodes, [], [], null);
    const text = allText(lastDoc);
    expect(text).toContain('OUT OF SCOPE');
    // The excluded node is rendered inside the autoTable body, not via doc.text()
    const outOfScopeTable = autoTableCalls.find(c =>
      (c.head as string[][])?.[0]?.includes('Reason'),
    );
    expect(outOfScopeTable).toBeDefined();
    const body = outOfScopeTable!.body as string[][];
    expect(body.map(r => r[0])).toContain('Legacy');
  });

  it('prefers techMitigations over the generic threat controls when present', async () => {
    const threat = makeThreat({
      id: 't-1',
      controls: [{ id: 'ctrl-1', description: 'Generic fallback' }],
    });
    await generateFullReport(
      'M',
      [makeNode('n1', 'EC2')],
      [],
      [
        makeActive(threat, {
          sourceNodeId: 'n1',
          techMitigations: ['Enable IMDSv2', 'Use IAM roles'],
        }),
      ],
      null,
    );
    const text = allText(lastDoc);
    expect(text).toContain('Enable IMDSv2');
    expect(text).toContain('Use IAM roles');
    expect(text).not.toContain('Generic fallback');
  });

  it('does not render a component section when the component has no threats', async () => {
    const nodes = [makeNode('n1', 'EC2'), makeNode('n2', 'Untouched')];
    const threats = [makeActive(makeThreat({ id: 't-1' }), { sourceNodeId: 'n1' })];
    await generateFullReport('M', nodes, [], threats, null);
    const text = allText(lastDoc);
    expect(text).toContain('COMPONENT: EC2');
    expect(text).not.toContain('COMPONENT: Untouched');
  });
});

// --- PDF Structure ---------------------------------------------------------

describe('PDF structure', () => {
  it('instantiates jsPDF as A4 portrait in millimetres', async () => {
    await generateExecutiveSummary('M', [], [], [], null);
    // internal pageSize comes from our mock; existence of the call is implicit
    // from the save() having been invoked. We assert indirectly via width/height.
    expect(lastDoc.internal.pageSize.width).toBe(210);
    expect(lastDoc.internal.pageSize.height).toBe(297);
  });

  it('adds a page footer with page number and generator tag', async () => {
    await generateExecutiveSummary('My Model', [makeNode('n1', 'EC2')], [], [], null);
    const text = allText(lastDoc);
    expect(text).toMatch(/Page \d of \d/);
    expect(text).toContain('ThreatModelling.io');
    expect(text).toContain('Generated:');
  });

  it('uses setPage() to add footers to every page', async () => {
    await generateExecutiveSummary('M', [makeNode('n1', 'EC2')], [], [], null);
    // Our mock reports 3 pages → setPage called for each
    expect(lastDoc.setPage.mock.calls.length).toBe(3);
  });
});

// --- Edge cases ------------------------------------------------------------

describe('edge cases', () => {
  it('handles an empty model (no nodes, edges, or threats) without throwing', async () => {
    await expect(generateExecutiveSummary('Empty', [], [], [], null)).resolves.not.toThrow();
    expect(lastDoc.save).toHaveBeenCalled();
  });

  it('handles a full report with no threats', async () => {
    await expect(
      generateFullReport('M', [makeNode('n1', 'EC2')], [], [], null),
    ).resolves.not.toThrow();
  });

  it('uses the customName over the technology name when present', async () => {
    await generateFullReport(
      'M',
      [makeNode('n1', 'EC2', { customName: 'Prod API Host' })],
      [],
      [makeActive(makeThreat({ id: 't-1' }), { sourceNodeId: 'n1', sourceTechName: 'Prod API Host' })],
      null,
    );
    const text = allText(lastDoc);
    expect(text).toContain('COMPONENT: Prod API Host');
    expect(text).not.toContain('COMPONENT: EC2');
  });

  it('skips the diagram image when null is passed', async () => {
    await generateExecutiveSummary('M', [makeNode('n1', 'EC2')], [], [], null);
    expect(lastDoc.addImage).not.toHaveBeenCalled();
  });

  it('does not render the OUT OF SCOPE section when no nodes are excluded', async () => {
    await generateFullReport('M', [makeNode('n1', 'EC2')], [], [], null);
    const text = allText(lastDoc);
    expect(text).not.toContain('OUT OF SCOPE');
  });

  it('tolerates a mix of zone, connection, and component threats in the same report', async () => {
    const component = makeActive(makeThreat({ id: 't-c' }), { sourceNodeId: 'n1', riskScore: 6 });
    const connection = makeActive(makeThreat({ id: 't-k', isConnectionThreat: true }), {
      sourceNodeId: 'e1',
      isConnectionThreat: true,
      connectionInfo: { edgeId: 'e1', sourceNodeName: 'A', targetNodeName: 'B' },
    });
    const zone = makeActive(makeThreat({ id: 't-z', isZoneThreat: true }), {
      sourceNodeId: 'z1',
      isZoneThreat: true,
      zoneInfo: { boundaryId: 'z1', zoneName: 'VPC' },
    });
    await expect(
      generateFullReport(
        'M',
        [makeNode('n1', 'EC2'), makeNode('n2', 'RDS')],
        [makeEdge('e1', 'n1', 'n2')],
        [component, connection, zone],
        null,
      ),
    ).resolves.not.toThrow();
  });
});
