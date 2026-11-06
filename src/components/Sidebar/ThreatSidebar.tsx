import { useCallback, useMemo, useState } from 'react';
import { ShieldCheck, ChevronRight } from 'lucide-react';
import { useThreats, useSelection, useDiagramState, useSettings } from '../../context/ThreatModelContext';
import { groupThreatsByTechnology } from '../../utils/threatResolver';
import type { ActiveThreat, RiskLevel, CloudProvider, ZoneNetworkType, ThreatSeverity } from '../../data/schema';
import { RISK_LEVEL_LABELS, partitionMitigatedThreats, describeThreatMitigation } from '../../data/schema';
import ThreatCard from './ThreatCard';
import ConnectionThreatCard from './ConnectionThreatCard';
import ZoneThreatCard from './ZoneThreatCard';
import './ThreatSidebar.css';

type SortOption = 'source' | 'risk-high' | 'risk-low';

// Grouped connection threat for deduplicated display
export interface GroupedConnectionThreat {
  threat: ActiveThreat['threat'];
  connections: Array<{
    edgeId: string;
    sourceNodeName: string;
    targetNodeName: string;
    label?: string;
    riskScore: number;
    riskLevel: RiskLevel;
    sourceProvider?: CloudProvider;
    targetProvider?: CloudProvider;
    zoneMultiplier?: number;
    overriddenSeverity?: ThreatSeverity;
    // Set when this connection's threat is mitigated (e.g. "TLS Encrypted")
    mitigation?: string;
  }>;
  maxRiskScore: number;
  maxRiskLevel: RiskLevel;
}

// Grouped zone threat for deduplicated display
export interface GroupedZoneThreat {
  threat: ActiveThreat['threat'];
  zones: Array<{
    boundaryId: string;
    zoneName: string;
    networkType?: ZoneNetworkType;
    riskScore: number;
    riskLevel: RiskLevel;
    riskReductionPercent?: number;
    overriddenSeverity?: ThreatSeverity;
  }>;
  maxRiskScore: number;
  maxRiskLevel: RiskLevel;
}

// Separate component threats from connection and zone threats, and group the
// connection and zone threats by threat ID for deduplicated display
function groupThreatsForDisplay(threats: ActiveThreat[]): {
  componentThreats: ActiveThreat[];
  groupedConnectionThreats: GroupedConnectionThreat[];
  groupedZoneThreats: GroupedZoneThreat[];
} {
  const component: ActiveThreat[] = [];
  const connectionMap = new Map<string, GroupedConnectionThreat>();
  const zoneMap = new Map<string, GroupedZoneThreat>();

  threats.forEach(at => {
    if (at.isConnectionThreat && at.connectionInfo) {
      const existing = connectionMap.get(at.threat.id);
      const connectionData = {
        edgeId: at.connectionInfo.edgeId,
        sourceNodeName: at.connectionInfo.sourceNodeName,
        targetNodeName: at.connectionInfo.targetNodeName,
        label: at.connectionInfo.label,
        riskScore: at.riskScore,
        riskLevel: at.riskLevel,
        sourceProvider: at.connectionInfo.sourceProvider,
        targetProvider: at.connectionInfo.targetProvider,
        zoneMultiplier: at.zoneMultiplier,
        overriddenSeverity: at.overriddenSeverity,
        mitigation: describeThreatMitigation(at),
      };

      if (existing) {
        existing.connections.push(connectionData);
        if (at.riskScore > existing.maxRiskScore) {
          existing.maxRiskScore = at.riskScore;
          existing.maxRiskLevel = at.riskLevel;
        }
      } else {
        connectionMap.set(at.threat.id, {
          threat: at.threat,
          connections: [connectionData],
          maxRiskScore: at.riskScore,
          maxRiskLevel: at.riskLevel,
        });
      }
    } else if (at.isZoneThreat && at.zoneInfo) {
      // Handle zone threats
      const existing = zoneMap.get(at.threat.id);
      const zoneData = {
        boundaryId: at.zoneInfo.boundaryId,
        zoneName: at.zoneInfo.zoneName,
        networkType: at.zoneInfo.networkType,
        riskScore: at.riskScore,
        riskLevel: at.riskLevel,
        riskReductionPercent: at.zoneInfo.riskReductionPercent,
        overriddenSeverity: at.overriddenSeverity,
      };

      if (existing) {
        existing.zones.push(zoneData);
        if (at.riskScore > existing.maxRiskScore) {
          existing.maxRiskScore = at.riskScore;
          existing.maxRiskLevel = at.riskLevel;
        }
      } else {
        zoneMap.set(at.threat.id, {
          threat: at.threat,
          zones: [zoneData],
          maxRiskScore: at.riskScore,
          maxRiskLevel: at.riskLevel,
        });
      }
    } else {
      component.push(at);
    }
  });

  // Convert maps to arrays, filter out threats with no entries, and sort by max risk score
  const groupedConnections = Array.from(connectionMap.values())
    .filter(g => g.connections.length > 0)
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore);

  const groupedZones = Array.from(zoneMap.values())
    .filter(g => g.zones.length > 0)
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore);

  return { componentThreats: component, groupedConnectionThreats: groupedConnections, groupedZoneThreats: groupedZones };
}

export default function ThreatSidebar() {
  const { activeThreats } = useThreats();
  const { pathwayMitigationSettings } = useSettings();
  const hideMitigated = pathwayMitigationSettings.hideMitigated;
  const { selectedNodeId, selectedEdgeId, selectedBoundaryId, setSelectedNode, setSelectedEdge, setSelectedBoundary } = useSelection();
  const { nodes, edges } = useDiagramState();
  const [filterQuery, setFilterQuery] = useState('');
  const [sortBy, setSortBy] = useState<SortOption>('risk-high');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | null>(null);
  const [mitigatedExpanded, setMitigatedExpanded] = useState(true);

  const hasSelection = selectedNodeId !== null || selectedEdgeId !== null || selectedBoundaryId !== null;

  // Filter threats by selected element
  const selectionFilteredThreats = useMemo(() => {
    if (selectedNodeId) {
      // Find edges connected to this node
      const connectedEdgeIds = new Set(
        edges.filter(e => e.source === selectedNodeId || e.target === selectedNodeId).map(e => e.id)
      );
      return activeThreats.filter(at => {
        // Component threats for this node
        if (!at.isConnectionThreat && !at.isZoneThreat && at.sourceNodeId === selectedNodeId) return true;
        // Connection threats for edges connected to this node
        if (at.isConnectionThreat && at.connectionInfo && connectedEdgeIds.has(at.connectionInfo.edgeId)) return true;
        return false;
      });
    }
    if (selectedEdgeId) {
      return activeThreats.filter(at =>
        at.isConnectionThreat && at.connectionInfo?.edgeId === selectedEdgeId
      );
    }
    if (selectedBoundaryId) {
      // Find nodes inside this boundary
      const nodesInBoundary = new Set(
        nodes.filter(n => n.parentId === selectedBoundaryId).map(n => n.id)
      );
      return activeThreats.filter(at => {
        // Zone threats for this boundary
        if (at.isZoneThreat && at.zoneInfo?.boundaryId === selectedBoundaryId) return true;
        // Component threats for nodes inside the boundary
        if (!at.isConnectionThreat && !at.isZoneThreat && nodesInBoundary.has(at.sourceNodeId)) return true;
        return false;
      });
    }
    return activeThreats;
  }, [activeThreats, selectedNodeId, selectedEdgeId, selectedBoundaryId, edges, nodes]);

  // Selection label for the filter indicator
  const selectionLabel = useMemo(() => {
    if (selectedNodeId) {
      const node = nodes.find(n => n.id === selectedNodeId);
      return node?.data?.customName || node?.data?.technology?.name || 'Selected node';
    }
    if (selectedEdgeId) {
      const edge = edges.find(e => e.id === selectedEdgeId);
      if (edge) {
        const srcNode = nodes.find(n => n.id === edge.source);
        const tgtNode = nodes.find(n => n.id === edge.target);
        const srcName = srcNode?.data?.customName || srcNode?.data?.technology?.name || '?';
        const tgtName = tgtNode?.data?.customName || tgtNode?.data?.technology?.name || '?';
        return `${srcName} → ${tgtName}`;
      }
      return 'Selected connection';
    }
    if (selectedBoundaryId) {
      return 'Selected zone';
    }
    return null;
  }, [selectedNodeId, selectedEdgeId, selectedBoundaryId, nodes, edges]);

  const clearSelection = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setSelectedBoundary(null);
  };

  // Split into active and mitigated threats. Mitigated threats are listed in
  // their own section (or dropped when hidden) and never count towards totals.
  const { active: selectionActiveThreats, mitigated: selectionMitigatedThreats } = useMemo(
    () => partitionMitigatedThreats(selectionFilteredThreats, hideMitigated),
    [selectionFilteredThreats, hideMitigated],
  );

  const totalThreatCount = selectionActiveThreats.length;
  const hasAnyThreats = selectionActiveThreats.length > 0 || selectionMitigatedThreats.length > 0;

  // Calculate risk summary from active selection-filtered threats
  const riskSummary = useMemo(() => {
    const summary: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    selectionActiveThreats.forEach(at => {
      summary[at.riskLevel]++;
    });
    return summary;
  }, [selectionActiveThreats]);

  // Filter threats (risk level and text search apply to both sections)
  const applyFilters = useCallback((threats: ActiveThreat[]) => {
    let result = threats;

    // Apply risk level filter
    if (riskFilter) {
      result = result.filter(at => at.riskLevel === riskFilter);
    }

    // Apply text search filter
    if (filterQuery.trim()) {
      const query = filterQuery.toLowerCase();
      result = result.filter(at =>
        at.threat.name.toLowerCase().includes(query) ||
        at.threat.description.toLowerCase().includes(query) ||
        at.threat.stride.some(s => s.toLowerCase().includes(query)) ||
        at.threat.mitreTechniques.some(
          m =>
            m.id.toLowerCase().includes(query) ||
            m.name.toLowerCase().includes(query) ||
            m.tactic.toLowerCase().includes(query)
        )
      );
    }

    return result;
  }, [filterQuery, riskFilter]);

  const filteredThreats = useMemo(
    () => applyFilters(selectionActiveThreats),
    [applyFilters, selectionActiveThreats],
  );
  const filteredMitigatedThreats = useMemo(
    () => applyFilters(selectionMitigatedThreats),
    [applyFilters, selectionMitigatedThreats],
  );

  // Sort threats
  const sortThreats = useCallback((threats: ActiveThreat[]) => {
    if (sortBy === 'risk-high') {
      return [...threats].sort((a, b) => b.riskScore - a.riskScore);
    } else if (sortBy === 'risk-low') {
      return [...threats].sort((a, b) => a.riskScore - b.riskScore);
    }
    return threats;
  }, [sortBy]);

  const sortedThreats = useMemo(() => sortThreats(filteredThreats), [sortThreats, filteredThreats]);
  const sortedMitigatedThreats = useMemo(
    () => sortThreats(filteredMitigatedThreats),
    [sortThreats, filteredMitigatedThreats],
  );

  // Group threats by source (only when sortBy === 'source')
  const groupedThreats = useMemo(() => {
    if (sortBy !== 'source') return null;
    return groupThreatsByTechnology(filteredThreats);
  }, [filteredThreats, sortBy]);

  // Build active threat map for grouped view
  const threatsByNodeId = useMemo(() => {
    const map = new Map<string, ActiveThreat[]>();
    filteredThreats.forEach(at => {
      const existing = map.get(at.sourceNodeId) || [];
      existing.push(at);
      map.set(at.sourceNodeId, existing);
    });
    return map;
  }, [filteredThreats]);

  const { componentThreats, groupedConnectionThreats, groupedZoneThreats } = useMemo(
    () => groupThreatsForDisplay(sortedThreats),
    [sortedThreats],
  );

  const mitigatedGroups = useMemo(
    () => groupThreatsForDisplay(sortedMitigatedThreats),
    [sortedMitigatedThreats],
  );

  return (
    <div className="threat-sidebar">
      <div className="sidebar-header">
        <div className="header-top">
          <h2>Threats</h2>
          <span className="threat-count">{totalThreatCount}</span>
        </div>

        {hasSelection && selectionLabel && (
          <div className="selection-filter-banner">
            <span className="selection-filter-label" title={selectionLabel}>{selectionLabel}</span>
            <button className="selection-filter-clear" onClick={clearSelection} title="Show all threats">&times;</button>
          </div>
        )}

        {hasAnyThreats && (
          <div className="risk-summary">
            {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map(level => (
              <button
                key={level}
                className={`risk-summary-item ${level} ${riskFilter === level ? 'active' : ''}`}
                title={`${RISK_LEVEL_LABELS[level]} risk - Click to ${riskFilter === level ? 'clear filter' : 'filter'}`}
                onClick={() => setRiskFilter(riskFilter === level ? null : level)}
              >
                {riskSummary[level]}
              </button>
            ))}
          </div>
        )}

        {hasAnyThreats && (
          <div className="controls-row">
            <select
              className="sort-select"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
            >
              <option value="risk-high">Risk: High to Low</option>
              <option value="risk-low">Risk: Low to High</option>
              <option value="source">Group by Source</option>
            </select>
          </div>
        )}

        {hasAnyThreats && (
          <input
            type="search"
            placeholder="Filter threats..."
            value={filterQuery}
            onChange={e => setFilterQuery(e.target.value)}
            className="filter-input"
          />
        )}
      </div>

      <div className="sidebar-content">
        {!hasAnyThreats ? (
          <div className="empty-state">
            <div className="empty-icon"><ShieldCheck size={48} strokeWidth={1.5} /></div>
            <p>No threats to display</p>
            <p className="empty-hint">
              {hasSelection
                ? 'No threats associated with this selection'
                : 'Add technologies to the diagram to see associated threats'}
            </p>
          </div>
        ) : filteredThreats.length === 0 && filteredMitigatedThreats.length === 0 ? (
          <div className="no-results">
            {riskFilter && !filterQuery.trim()
              ? `No ${RISK_LEVEL_LABELS[riskFilter].toLowerCase()} risk threats`
              : riskFilter && filterQuery.trim()
              ? `No ${RISK_LEVEL_LABELS[riskFilter].toLowerCase()} risk threats match "${filterQuery}"`
              : `No threats match "${filterQuery}"`}
          </div>
        ) : (
          <>
            {filteredThreats.length === 0 ? (
              <div className="no-results">No active threats</div>
            ) : sortBy === 'source' && groupedThreats ? (
              // Grouped view
              Array.from(groupedThreats.entries()).map(([nodeId, { techName, isConnection }]) => {
                const nodeThreats = threatsByNodeId.get(nodeId) || [];
                if (nodeThreats.length === 0) return null;

                return (
                  <div key={nodeId} className={`tech-threat-group ${isConnection ? 'connection-group' : ''}`}>
                    <div className="group-header">
                      <span className="group-icon">{isConnection ? '🔗' : '🖥️'}</span>
                      <span className="group-name">{techName}</span>
                      <span className="group-count">{nodeThreats.length}</span>
                    </div>
                    <div className="group-threats">
                      {nodeThreats.map(activeThreat => (
                        <ThreatCard
                          key={`${nodeId}-${activeThreat.threat.id}`}
                          activeThreat={activeThreat}
                        />
                      ))}
                    </div>
                  </div>
                );
              })
            ) : (
              // Flat sorted list with deduplicated connection threats
              <div className="threats-list">
                {/* Component threats */}
                {componentThreats.map(activeThreat => (
                  <ThreatCard
                    key={`${activeThreat.sourceNodeId}-${activeThreat.threat.id}`}
                    activeThreat={activeThreat}
                  />
                ))}

                {/* Grouped connection threats */}
                {groupedConnectionThreats.length > 0 && (
                  <div className="connection-threats-section">
                    <div className="section-divider">
                      <span className="section-icon">🔗</span>
                      <span className="section-label">Connection Threats</span>
                    </div>
                    {groupedConnectionThreats.map(groupedThreat => (
                      <ConnectionThreatCard
                        key={groupedThreat.threat.id}
                        groupedThreat={groupedThreat}
                      />
                    ))}
                  </div>
                )}

                {/* Grouped zone threats */}
                {groupedZoneThreats.length > 0 && (
                  <div className="zone-threats-section">
                    <div className="section-divider zone-section">
                      <span className="section-icon">🔒</span>
                      <span className="section-label">Network Zone Threats</span>
                    </div>
                    {groupedZoneThreats.map(groupedThreat => (
                      <ZoneThreatCard
                        key={groupedThreat.threat.id}
                        groupedThreat={groupedThreat}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Mitigated threats, below all active threats */}
            {filteredMitigatedThreats.length > 0 && (
              <div className="mitigated-threats-section">
                <button
                  className="section-divider mitigated-section"
                  onClick={() => setMitigatedExpanded(!mitigatedExpanded)}
                  aria-expanded={mitigatedExpanded}
                >
                  <ChevronRight
                    size={14}
                    className={`section-chevron ${mitigatedExpanded ? 'expanded' : ''}`}
                  />
                  <span className="section-label">Mitigated Threats</span>
                  <span className="section-count">{filteredMitigatedThreats.length}</span>
                </button>
                {mitigatedExpanded && (
                  <div className="threats-list">
                    {mitigatedGroups.componentThreats.map(activeThreat => (
                      <ThreatCard
                        key={`${activeThreat.sourceNodeId}-${activeThreat.threat.id}`}
                        activeThreat={activeThreat}
                      />
                    ))}
                    {mitigatedGroups.groupedConnectionThreats.map(groupedThreat => (
                      <ConnectionThreatCard
                        key={groupedThreat.threat.id}
                        groupedThreat={groupedThreat}
                        mitigated
                      />
                    ))}
                    {mitigatedGroups.groupedZoneThreats.map(groupedThreat => (
                      <ZoneThreatCard
                        key={groupedThreat.threat.id}
                        groupedThreat={groupedThreat}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
