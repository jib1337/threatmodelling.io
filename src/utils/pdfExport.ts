import type { jsPDF as JsPDFType } from 'jspdf';
import type { ActiveThreat, TechNodeData, RiskLevel, ZoneNetworkType } from '../data/schema';
import { STRIDE_LABELS, RISK_LEVEL_LABELS, DATA_SENSITIVITY_LABELS, PROVIDER_LABELS, ZONE_NETWORK_TYPE_LABELS } from '../data/schema';
import type { Node, Edge } from '@xyflow/react';
import { buildControlKey } from './controlFingerprint';

// Extended jsPDF type to include autoTable
interface ExtendedJsPDF extends JsPDFType {
  lastAutoTable: { finalY: number };
}

// Type for autoTable function
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AutoTableFn = (doc: ExtendedJsPDF, options: any) => void;

// Colors for risk levels
const RISK_COLORS: Record<RiskLevel, [number, number, number]> = {
  critical: [220, 38, 38],   // Red
  high: [234, 88, 12],       // Orange
  medium: [202, 138, 4],     // Yellow/Amber
  low: [47, 129, 247],        // Blue
};

const HEADER_COLOR: [number, number, number] = [30, 41, 59]; // Slate-800

interface ComponentSummary {
  name: string;
  provider: string;
  sensitivity: string;
  threatCount: number;
  maxRiskScore: number;
  maxRiskLevel: RiskLevel;
  threats: ActiveThreat[];
}

// Draws a small checkbox at (x, y) where y is the text baseline. Filled box +
// tick for implemented controls, empty outlined box otherwise. Returns the
// horizontal offset (in mm) consumed, so callers can place text to the right.
function drawControlCheckbox(doc: ExtendedJsPDF, x: number, y: number, implemented: boolean): number {
  const size = 2.6;
  const top = y - 2.5;
  if (implemented) {
    doc.setFillColor(90, 90, 90);
    doc.setDrawColor(90, 90, 90);
    doc.setLineWidth(0.15);
    doc.roundedRect(x, top, size, size, 0.4, 0.4, 'FD');
    // Tick: two short strokes forming a check
    doc.setDrawColor(255, 255, 255);
    doc.setLineWidth(0.35);
    doc.line(x + 0.55, top + size * 0.55, x + size * 0.45, top + size - 0.5);
    doc.line(x + size * 0.45, top + size - 0.5, x + size - 0.35, top + 0.55);
  } else {
    doc.setDrawColor(120, 120, 120);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, top, size, size, 0.4, 0.4, 'S');
  }
  return size + 1.2;
}

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function addPageFooter(doc: ExtendedJsPDF, pageNum: number, totalPages: number, generatedAt: string) {
  const pageHeight = doc.internal.pageSize.height;
  const pageWidth = doc.internal.pageSize.width;

  doc.setFontSize(8);
  doc.setTextColor(128, 128, 128);
  doc.text(`Page ${pageNum} of ${totalPages}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
  doc.text(`Generated: ${generatedAt}`, 14, pageHeight - 10);
  doc.text('ThreatModelling.io', pageWidth - 14, pageHeight - 10, { align: 'right' });
}

function groupThreatsByComponent(
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[]
): Map<string, ComponentSummary> {
  const componentMap = new Map<string, ComponentSummary>();

  // Initialize components from nodes
  nodes.forEach(node => {
    const displayName = node.data.customName || node.data.technology.name;
    componentMap.set(node.id, {
      name: displayName,
      provider: PROVIDER_LABELS[node.data.technology.provider],
      sensitivity: DATA_SENSITIVITY_LABELS[node.data.sensitivity],
      threatCount: 0,
      maxRiskScore: 0,
      maxRiskLevel: 'low',
      threats: [],
    });
  });

  // Group threats by source component (skip zone threats - they're handled separately)
  threats.forEach(threat => {
    // Skip zone threats - they don't belong to components
    if (threat.isZoneThreat) {
      return;
    }

    // For connection threats, group under source node
    let componentId = threat.sourceNodeId;

    // If it's a connection threat, find the source node from the edge
    if (threat.isConnectionThreat && threat.connectionInfo) {
      const edge = edges.find(e => e.id === threat.connectionInfo!.edgeId);
      if (edge) {
        componentId = edge.source;
      }
    }

    const component = componentMap.get(componentId);
    if (component) {
      component.threats.push(threat);
      component.threatCount++;
      if (threat.riskScore > component.maxRiskScore) {
        component.maxRiskScore = threat.riskScore;
        component.maxRiskLevel = threat.riskLevel;
      }
    }
  });

  return componentMap;
}

function getRiskDistribution(threats: ActiveThreat[]): Record<RiskLevel, number> {
  const distribution: Record<RiskLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  threats.forEach(threat => {
    distribution[threat.riskLevel]++;
  });

  return distribution;
}

function addExecutiveSummaryContent(
  doc: ExtendedJsPDF,
  autoTable: AutoTableFn,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  diagramImage: string | null,
  startY: number
): number {
  let y = startY;
  const pageWidth = doc.internal.pageSize.width;
  const margin = 14;
  const contentWidth = pageWidth - 2 * margin;

  // Overview section
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('OVERVIEW', margin, y);
  y += 8;

  const uniqueThreats = new Set(threats.map(t => t.threat.id)).size;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);

  const overviewItems = [
    [`Components: ${nodes.length}`, `Data Flows: ${edges.length}`],
    [`Total Threats: ${threats.length}`, `Unique Threats: ${uniqueThreats}`],
  ];

  overviewItems.forEach(row => {
    doc.text(row[0], margin, y);
    doc.text(row[1], margin + contentWidth / 2, y);
    y += 6;
  });
  y += 4;

  // Risk Distribution
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('RISK DISTRIBUTION', margin, y);
  y += 8;

  const distribution = getRiskDistribution(threats);
  const maxCount = Math.max(...Object.values(distribution), 1);
  const barMaxWidth = 100;

  (['critical', 'high', 'medium', 'low'] as RiskLevel[]).forEach(level => {
    const count = distribution[level];
    const barWidth = (count / maxCount) * barMaxWidth;
    const color = RISK_COLORS[level];

    // Draw bar
    doc.setFillColor(color[0], color[1], color[2]);
    doc.rect(margin, y - 3, barWidth, 5, 'F');

    // Draw label
    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    doc.text(`${RISK_LEVEL_LABELS[level]}: ${count}`, margin + barMaxWidth + 5, y);
    y += 8;
  });
  y += 4;

  // Top Threats Table
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('TOP THREATS BY RISK SCORE', margin, y);
  y += 4;

  const sortedThreats = [...threats].sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);

  autoTable(doc, {
    startY: y,
    head: [['Threat', 'Component', 'Score', 'Level']],
    body: sortedThreats.map(t => [
      t.threat.name,
      t.sourceTechName,
      t.riskScore.toString(),
      RISK_LEVEL_LABELS[t.riskLevel],
    ]),
    headStyles: {
      fillColor: HEADER_COLOR,
      fontSize: 9,
      fontStyle: 'bold',
    },
    bodyStyles: {
      fontSize: 9,
    },
    columnStyles: {
      0: { cellWidth: 60 },
      1: { cellWidth: 50 },
      2: { cellWidth: 20, halign: 'center' },
      3: { cellWidth: 25 },
    },
    margin: { left: margin, right: margin },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    didParseCell: (data: any) => {
      // Color the risk level column
      if (data.section === 'body' && data.column.index === 3) {
        const level = sortedThreats[data.row.index]?.riskLevel;
        if (level) {
          data.cell.styles.textColor = RISK_COLORS[level];
          data.cell.styles.fontStyle = 'bold';
        }
      }
    },
  });

  y = doc.lastAutoTable.finalY + 8;

  // Components Summary Table
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('COMPONENTS SUMMARY', margin, y);
  y += 4;

  const componentMap = groupThreatsByComponent(nodes, edges, threats);
  const componentData = Array.from(componentMap.values())
    .filter(c => c.threatCount > 0)
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore);

  autoTable(doc, {
    startY: y,
    head: [['Component', 'Provider', 'Sensitivity', 'Threats', 'Max Risk']],
    body: componentData.map(c => [
      c.name,
      c.provider,
      c.sensitivity,
      c.threatCount.toString(),
      `${c.maxRiskScore} (${RISK_LEVEL_LABELS[c.maxRiskLevel]})`,
    ]),
    headStyles: {
      fillColor: HEADER_COLOR,
      fontSize: 9,
      fontStyle: 'bold',
    },
    bodyStyles: {
      fontSize: 9,
    },
    margin: { left: margin, right: margin },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    didParseCell: (data: any) => {
      // Color the max risk column
      if (data.section === 'body' && data.column.index === 4) {
        const component = componentData[data.row.index];
        if (component) {
          data.cell.styles.textColor = RISK_COLORS[component.maxRiskLevel];
          data.cell.styles.fontStyle = 'bold';
        }
      }
    },
  });

  y = doc.lastAutoTable.finalY + 8;

  // Add diagram if provided and there's space
  if (diagramImage) {
    const remainingSpace = doc.internal.pageSize.height - y - 20;
    if (remainingSpace > 60) {
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(0, 0, 0);
      doc.text('ARCHITECTURE DIAGRAM', margin, y);
      y += 4;

      const imgHeight = Math.min(remainingSpace - 10, 80);
      const imgWidth = imgHeight * (16 / 9); // Maintain aspect ratio
      const imgX = (pageWidth - imgWidth) / 2;

      try {
        doc.addImage(diagramImage, 'PNG', imgX, y, imgWidth, imgHeight);
        y += imgHeight + 4;
      } catch {
        // Image failed to load, skip it
      }
    }
  }

  return y;
}

// Filter out mitigated connection threats (those protected by TLS-enforcing services)
function filterMitigatedThreats(threats: ActiveThreat[]): ActiveThreat[] {
  return threats.filter(t => !t.mitigatedBy);
}

function addOutOfScopeSection(
  doc: ExtendedJsPDF,
  autoTable: AutoTableFn,
  nodes: Node<TechNodeData>[],
  margin: number,
  startY: number
): number {
  const excludedNodes = nodes.filter(node => node.data.threatsDisabled);

  if (excludedNodes.length === 0) {
    return startY;
  }

  let y = startY;
  const pageHeight = doc.internal.pageSize.height;

  // Check if we need a new page
  if (y > pageHeight - 60) {
    doc.addPage();
    y = 20;
  }

  // Section header
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('OUT OF SCOPE', margin, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);
  doc.text('The following components have been excluded from threat analysis:', margin, y);
  y += 4;

  autoTable(doc, {
    startY: y,
    head: [['Component', 'Provider', 'Sensitivity', 'Reason']],
    body: excludedNodes.map(node => {
      const displayName = node.data.customName || node.data.technology.name;
      const provider = PROVIDER_LABELS[node.data.technology.provider];
      const sensitivity = DATA_SENSITIVITY_LABELS[node.data.sensitivity];
      return [displayName, provider, sensitivity, 'Excluded by user'];
    }),
    headStyles: {
      fillColor: HEADER_COLOR,
      fontSize: 9,
      fontStyle: 'bold',
    },
    bodyStyles: {
      fontSize: 9,
    },
    margin: { left: margin, right: margin },
  });

  return doc.lastAutoTable.finalY + 8;
}

export async function generateExecutiveSummary(
  modelName: string,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  diagramImage: string | null
): Promise<void> {
  // Dynamically import jspdf and jspdf-autotable
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import('jspdf'),
    import('jspdf-autotable'),
  ]);

  // Filter out mitigated threats before generating the report
  const filteredThreats = filterMitigatedThreats(threats);

  // Cast to ExtendedJsPDF since jspdf-autotable adds lastAutoTable property
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  }) as ExtendedJsPDF;

  const pageWidth = doc.internal.pageSize.width;
  const margin = 14;
  const generatedAt = formatDate(new Date());

  // Title
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('THREAT MODEL REPORT', pageWidth / 2, 20, { align: 'center' });

  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);
  doc.text(modelName, pageWidth / 2, 28, { align: 'center' });

  doc.setFontSize(10);
  doc.text(`Executive Summary | ${generatedAt}`, pageWidth / 2, 35, { align: 'center' });

  // Divider line
  doc.setDrawColor(200, 200, 200);
  doc.line(margin, 40, pageWidth - margin, 40);

  // Add content
  let y = addExecutiveSummaryContent(doc, autoTable, nodes, edges, filteredThreats, diagramImage, 48);

  // Add out of scope section
  addOutOfScopeSection(doc, autoTable, nodes, margin, y);

  // Add footer
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    addPageFooter(doc, i, totalPages, generatedAt);
  }

  // Save
  const filename = `${modelName.toLowerCase().replace(/\s+/g, '-')}-executive-summary.pdf`;
  doc.save(filename);
}

interface GroupedZoneThreat {
  threat: ActiveThreat['threat'];
  zones: Array<{
    boundaryId: string;
    zoneName: string;
    networkType?: ZoneNetworkType;
    riskScore: number;
    riskLevel: RiskLevel;
    riskReductionPercent?: number;
  }>;
  maxRiskScore: number;
  maxRiskLevel: RiskLevel;
}

function groupZoneThreats(threats: ActiveThreat[]): GroupedZoneThreat[] {
  const zoneMap = new Map<string, GroupedZoneThreat>();

  threats.forEach(threat => {
    if (!threat.isZoneThreat || !threat.zoneInfo) {
      return;
    }

    const existing = zoneMap.get(threat.threat.id);
    const zoneData = {
      boundaryId: threat.zoneInfo.boundaryId,
      zoneName: threat.zoneInfo.zoneName,
      networkType: threat.zoneInfo.networkType,
      riskScore: threat.riskScore,
      riskLevel: threat.riskLevel,
      riskReductionPercent: threat.zoneInfo.riskReductionPercent,
    };

    if (existing) {
      existing.zones.push(zoneData);
      if (threat.riskScore > existing.maxRiskScore) {
        existing.maxRiskScore = threat.riskScore;
        existing.maxRiskLevel = threat.riskLevel;
      }
    } else {
      zoneMap.set(threat.threat.id, {
        threat: threat.threat,
        zones: [zoneData],
        maxRiskScore: threat.riskScore,
        maxRiskLevel: threat.riskLevel,
      });
    }
  });

  return Array.from(zoneMap.values())
    .filter(g => g.zones.length > 0)
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore);
}

function addZoneThreatPages(
  doc: ExtendedJsPDF,
  threats: ActiveThreat[],
  margin: number,
  implementedControls: Record<string, true> = {}
): void {
  const groupedZoneThreats = groupZoneThreats(threats);

  if (groupedZoneThreats.length === 0) {
    return;
  }

  const pageWidth = doc.internal.pageSize.width;
  const pageHeight = doc.internal.pageSize.height;

  // Add new page for zone threats
  doc.addPage();

  let y = 20;

  // Section header
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('NETWORK ZONE THREATS', margin, y);
  y += 8;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);
  doc.text('The following threats apply to private network zones in the architecture.', margin, y);
  y += 4;

  doc.setDrawColor(200, 200, 200);
  doc.line(margin, y, pageWidth - margin, y);
  y += 8;

  for (const groupedThreat of groupedZoneThreats) {
    const threat = groupedThreat.threat;

    // Check if we need a new page
    if (y > pageHeight - 80) {
      doc.addPage();
      y = 20;
    }

    // Threat name with risk badge
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text(threat.name, margin, y);

    // Risk badge
    const riskColor = RISK_COLORS[groupedThreat.maxRiskLevel];
    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    const badgeX = margin + doc.getTextWidth(threat.name) + 4;
    doc.roundedRect(badgeX, y - 4, 25, 6, 1, 1, 'F');
    doc.setFontSize(8);
    doc.setTextColor(255, 255, 255);
    doc.text(`${groupedThreat.maxRiskScore}/16`, badgeX + 12.5, y - 0.5, { align: 'center' });
    y += 6;

    // Risk details
    doc.setFontSize(9);
    doc.setTextColor(80, 80, 80);
    doc.text(`Risk Level: ${RISK_LEVEL_LABELS[groupedThreat.maxRiskLevel]}  |  Severity: ${threat.severity.toUpperCase()}  |  Zones: ${groupedThreat.zones.length}`, margin, y);
    y += 5;

    // STRIDE
    doc.setTextColor(80, 80, 80);
    const strideLabels = threat.stride.map(s => STRIDE_LABELS[s]).join(', ');
    doc.text(`STRIDE: ${strideLabels}`, margin, y);
    y += 5;

    // MITRE
    const mitreIds = threat.mitreTechniques.map(t => t.id).join(', ');
    doc.text(`MITRE ATT&CK: ${mitreIds}`, margin, y);
    y += 5;

    // Description
    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    const descLines = doc.splitTextToSize(threat.description, pageWidth - 2 * margin);
    doc.text(descLines, margin, y);
    y += descLines.length * 4 + 2;

    // Affected zones
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text('Affected Network Zones:', margin, y);
    y += 4;

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(60, 60, 60);
    groupedThreat.zones.forEach(zone => {
      const networkTypeLabel = zone.networkType && zone.networkType !== 'generic'
        ? ` (${ZONE_NETWORK_TYPE_LABELS[zone.networkType]})`
        : '';
      const zoneColor = RISK_COLORS[zone.riskLevel];

      doc.setTextColor(60, 60, 60);
      doc.text(`• ${zone.zoneName}${networkTypeLabel}: `, margin + 2, y);

      // Add colored risk score
      const textWidth = doc.getTextWidth(`• ${zone.zoneName}${networkTypeLabel}: `);
      doc.setTextColor(zoneColor[0], zoneColor[1], zoneColor[2]);
      doc.setFont('helvetica', 'bold');
      doc.text(`${zone.riskScore} (${RISK_LEVEL_LABELS[zone.riskLevel]})`, margin + 2 + textWidth, y);
      doc.setFont('helvetica', 'normal');
      y += 4;
    });
    y += 2;

    // Controls
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text('Mitigating Controls:', margin, y);
    y += 4;

    doc.setFont('helvetica', 'normal');
    threat.controls.forEach(control => {
      if (y > pageHeight - 20) {
        doc.addPage();
        y = 20;
      }
      const key = buildControlKey({ kind: 'zone', threatId: threat.id }, control.description);
      const implemented = !!implementedControls[key];
      const textX = margin + 2 + drawControlCheckbox(doc, margin + 2, y, implemented);
      const controlLines = doc.splitTextToSize(control.description, pageWidth - margin - textX);
      doc.setTextColor(implemented ? 140 : 60, implemented ? 140 : 60, implemented ? 140 : 60);
      doc.text(controlLines, textX, y);
      if (implemented) {
        const strikeY = y - 1.2;
        controlLines.forEach((line: string, idx: number) => {
          const lineWidth = doc.getTextWidth(line);
          doc.setDrawColor(140, 140, 140);
          doc.setLineWidth(0.2);
          doc.line(textX, strikeY + idx * 4, textX + lineWidth, strikeY + idx * 4);
        });
      }
      y += controlLines.length * 4;
    });

    y += 6;

    // Divider between threats
    if (y < pageHeight - 30) {
      doc.setDrawColor(230, 230, 230);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;
    }
  }
}

export async function generateFullReport(
  modelName: string,
  nodes: Node<TechNodeData>[],
  edges: Edge[],
  threats: ActiveThreat[],
  diagramImage: string | null,
  implementedControls: Record<string, true> = {}
): Promise<void> {
  // Dynamically import jspdf and jspdf-autotable
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import('jspdf'),
    import('jspdf-autotable'),
  ]);

  // Filter out mitigated threats before generating the report
  const filteredThreats = filterMitigatedThreats(threats);

  // Cast to ExtendedJsPDF since jspdf-autotable adds lastAutoTable property
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  }) as ExtendedJsPDF;

  const pageWidth = doc.internal.pageSize.width;
  const pageHeight = doc.internal.pageSize.height;
  const margin = 14;
  const generatedAt = formatDate(new Date());

  // Page 1: Title + Executive Summary
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('THREAT MODEL REPORT', pageWidth / 2, 20, { align: 'center' });

  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);
  doc.text(modelName, pageWidth / 2, 28, { align: 'center' });

  doc.setFontSize(10);
  doc.text(`Full Report | ${generatedAt}`, pageWidth / 2, 35, { align: 'center' });

  doc.setDrawColor(200, 200, 200);
  doc.line(margin, 40, pageWidth - margin, 40);

  addExecutiveSummaryContent(doc, autoTable, nodes, edges, filteredThreats, diagramImage, 48);

  // Group threats by component for detail pages
  const componentMap = groupThreatsByComponent(nodes, edges, filteredThreats);
  const components = Array.from(componentMap.entries())
    .filter(([, c]) => c.threatCount > 0)
    .sort((a, b) => b[1].maxRiskScore - a[1].maxRiskScore);

  // Detail pages for each component
  for (const [, component] of components) {
    doc.addPage();

    let y = 20;

    // Component header
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text(`COMPONENT: ${component.name}`, margin, y);
    y += 8;

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(60, 60, 60);
    doc.text(`Provider: ${component.provider}  |  Sensitivity: ${component.sensitivity}  |  Threats: ${component.threatCount}`, margin, y);
    y += 4;

    doc.setDrawColor(200, 200, 200);
    doc.line(margin, y, pageWidth - margin, y);
    y += 8;

    // Sort threats by risk score
    const sortedThreats = [...component.threats].sort((a, b) => b.riskScore - a.riskScore);

    for (const activeThreat of sortedThreats) {
      const threat = activeThreat.threat;

      // Check if we need a new page
      if (y > pageHeight - 60) {
        doc.addPage();
        y = 20;
      }

      // Threat name with risk badge
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(0, 0, 0);

      const threatTitle = activeThreat.isConnectionThreat
        ? `${threat.name} (Connection)`
        : threat.name;
      doc.text(threatTitle, margin, y);

      // Risk badge
      const riskColor = RISK_COLORS[activeThreat.riskLevel];
      doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
      const badgeX = margin + doc.getTextWidth(threatTitle) + 4;
      doc.roundedRect(badgeX, y - 4, 25, 6, 1, 1, 'F');
      doc.setFontSize(8);
      doc.setTextColor(255, 255, 255);
      doc.text(`${activeThreat.riskScore}/16`, badgeX + 12.5, y - 0.5, { align: 'center' });
      y += 6;

      // Risk details
      doc.setFontSize(9);
      doc.setTextColor(80, 80, 80);
      doc.text(`Risk Level: ${RISK_LEVEL_LABELS[activeThreat.riskLevel]}  |  Severity: ${threat.severity.toUpperCase()}  |  Sensitivity: ${DATA_SENSITIVITY_LABELS[activeThreat.sensitivity]}`, margin, y);
      y += 5;

      // Connection info if applicable
      if (activeThreat.isConnectionThreat && activeThreat.connectionInfo) {
        doc.text(`Data Flow: ${activeThreat.connectionInfo.sourceNodeName} -> ${activeThreat.connectionInfo.targetNodeName}${activeThreat.connectionInfo.label ? ` (${activeThreat.connectionInfo.label})` : ''}`, margin, y);
        y += 5;
      }

      // STRIDE
      const strideLabels = threat.stride.map(s => STRIDE_LABELS[s]).join(', ');
      doc.text(`STRIDE: ${strideLabels}`, margin, y);
      y += 5;

      // MITRE
      const mitreIds = threat.mitreTechniques.map(t => t.id).join(', ');
      doc.text(`MITRE ATT&CK: ${mitreIds}`, margin, y);
      y += 5;

      // Description
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 60);
      const descLines = doc.splitTextToSize(threat.description, pageWidth - 2 * margin);
      doc.text(descLines, margin, y);
      y += descLines.length * 4 + 2;

      // Controls
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(0, 0, 0);
      doc.text('Mitigating Controls:', margin, y);
      y += 4;

      doc.setFont('helvetica', 'normal');
      const hasTechMitigations = activeThreat.techMitigations && activeThreat.techMitigations.length > 0;
      const mitigations = hasTechMitigations
        ? activeThreat.techMitigations!.map(m => ({ text: m }))
        : threat.controls.map(c => ({ text: c.description }));
      const controlScope = activeThreat.isConnectionThreat
        ? { kind: 'connection' as const, threatId: threat.id }
        : hasTechMitigations
          ? { kind: 'node-tech' as const, nodeId: activeThreat.sourceNodeId, threatId: threat.id }
          : { kind: 'node-generic' as const, nodeId: activeThreat.sourceNodeId, threatId: threat.id };
      mitigations.forEach(item => {
        if (y > pageHeight - 20) {
          doc.addPage();
          y = 20;
        }
        const key = buildControlKey(controlScope, item.text);
        const implemented = !!implementedControls[key];
        const textX = margin + 2 + drawControlCheckbox(doc, margin + 2, y, implemented);
        const controlLines = doc.splitTextToSize(item.text, pageWidth - margin - textX);
        doc.setTextColor(implemented ? 140 : 60, implemented ? 140 : 60, implemented ? 140 : 60);
        doc.text(controlLines, textX, y);
        if (implemented) {
          const strikeY = y - 1.2;
          controlLines.forEach((line: string, idx: number) => {
            const lineWidth = doc.getTextWidth(line);
            doc.setDrawColor(140, 140, 140);
            doc.setLineWidth(0.2);
            doc.line(textX, strikeY + idx * 4, textX + lineWidth, strikeY + idx * 4);
          });
        }
        y += controlLines.length * 4;
      });

      y += 6;

      // Divider between threats
      if (y < pageHeight - 30) {
        doc.setDrawColor(230, 230, 230);
        doc.line(margin, y, pageWidth - margin, y);
        y += 6;
      }
    }
  }

  // Add zone threat pages (if any private zones exist)
  addZoneThreatPages(doc, filteredThreats, margin, implementedControls);

  // Add out of scope section on a new page (if there are excluded nodes)
  const excludedNodes = nodes.filter(node => node.data.threatsDisabled);
  if (excludedNodes.length > 0) {
    doc.addPage();
    addOutOfScopeSection(doc, autoTable, nodes, margin, 20);
  }

  // Add page numbers to all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    addPageFooter(doc, i, totalPages, generatedAt);
  }

  // Save
  const filename = `${modelName.toLowerCase().replace(/\s+/g, '-')}-full-report.pdf`;
  doc.save(filename);
}
