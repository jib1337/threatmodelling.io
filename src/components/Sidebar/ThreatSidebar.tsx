import { useMemo, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { useThreats, useSelection, useDiagramState } from '../../context/ThreatModelContext';
import { groupThreatsByTechnology } from '../../utils/threatResolver';
import type { ActiveThreat, RiskLevel, CloudProvider, ZoneNetworkType, ThreatSeverity } from '../../data/schema';
import { RISK_LEVEL_LABELS } from '../../data/schema';
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

export default function ThreatSidebar() {
  const { activeThreats } = useThreats();
  const { selectedNodeId, selectedEdgeId, selectedBoundaryId, setSelectedNode, setSelectedEdge, setSelectedBoundary } = useSelection();
  const { nodes, edges } = useDiagramState();
  const [filterQuery, setFilterQuery] = useState('');
  const [sortBy, setSortBy] = useState<SortOption>('risk-high');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | null>(null);

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

  const totalThreatCount = selectionFilteredThreats.length;

  // Calculate risk summary from selection-filtered threats
  const riskSummary = useMemo(() => {
    const summary: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    selectionFilteredThreats.forEach(at => {
      summary[at.riskLevel]++;
    });
    return summary;
  }, [selectionFilteredThreats]);

  // Filter threats
  const filteredThreats = useMemo(() => {
    let result = selectionFilteredThreats;

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
  }, [selectionFilteredThreats, filterQuery, riskFilter]);

  // Sort threats
  const sortedThreats = useMemo(() => {
    if (sortBy === 'risk-high') {
      return [...filteredThreats].sort((a, b) => b.riskScore - a.riskScore);
    } else if (sortBy === 'risk-low') {
      return [...filteredThreats].sort((a, b) => a.riskScore - b.riskScore);
    }
    return filteredThreats;
  }, [filteredThreats, sortBy]);

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

  // Separate component threats from connection and zone threats, and group them by threat ID
  // Filter out mitigated connections entirely
  const { componentThreats, groupedConnectionThreats, groupedZoneThreats } = useMemo(() => {
    const component: ActiveThreat[] = [];
    const connectionMap = new Map<string, GroupedConnectionThreat>();
    const zoneMap = new Map<string, GroupedZoneThreat>();

    sortedThreats.forEach(at => {
      if (at.isConnectionThreat && at.connectionInfo) {
        // Skip mitigated connections entirely
        if (at.mitigatedBy) {
          return;
        }

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
  }, [sortedThreats]);

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

        {selectionFilteredThreats.length > 0 && (
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

        {selectionFilteredThreats.length > 0 && (
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

        {selectionFilteredThreats.length > 0 && (
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
        {selectionFilteredThreats.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon"><ShieldCheck size={48} strokeWidth={1.5} /></div>
            <p>No threats to display</p>
            <p className="empty-hint">
              {hasSelection
                ? 'No threats associated with this selection'
                : 'Add technologies to the diagram to see associated threats'}
            </p>
          </div>
        ) : filteredThreats.length === 0 ? (
          <div className="no-results">
            {riskFilter && !filterQuery.trim()
              ? `No ${RISK_LEVEL_LABELS[riskFilter].toLowerCase()} risk threats`
              : riskFilter && filterQuery.trim()
              ? `No ${RISK_LEVEL_LABELS[riskFilter].toLowerCase()} risk threats match "${filterQuery}"`
              : `No threats match "${filterQuery}"`}
          </div>
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
      </div>
    </div>
  );
}
