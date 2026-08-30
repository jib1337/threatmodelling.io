import { useState, useMemo, useEffect, useCallback, memo, type DragEvent } from 'react';
import type { Technology, CloudProvider } from '../../data/schema';
import { CATEGORY_LABELS, PROVIDER_LABELS } from '../../data/schema';
import {
  getTechnologiesByProvider,
  getSelectableProviders,
  loadProvider,
  loadProviders,
  subscribeToProviderLoad,
  PROVIDER_SERVICE_COUNTS,
} from '../../data';
import { useActions, useCustomTechnologies } from '../../context/ThreatModelContext';
import { useMobilePanel } from '../App';
import { Box, Plus, SquareUserRound } from 'lucide-react';
import ProviderIcon from '../ProviderIcon';
import ActorIcon from '../ActorIcon';
import CustomTechModal from '../CustomTechModal/CustomTechModal';
import ConfirmDeleteModal from '../ConfirmDeleteModal/ConfirmDeleteModal';
import './TechPalette.css';

// Provider sections come from the catalogue manifest, so a new provider appears
// in the palette without a code change here.
const providerOrder: CloudProvider[] = getSelectableProviders();
const ACTOR_PROVIDER = 'actor' as CloudProvider;

export default memo(function TechPalette() {
  const { addNode, getViewportCenter } = useActions();
  const { customTechnologies, registerCustomTechnology, removeCustomTechnology } = useCustomTechnologies();
  const { activePanel } = useMobilePanel();
  const [expandedProviders, setExpandedProviders] = useState<Set<CloudProvider>>(
    new Set()
  );
  const [actorsExpanded, setActorsExpanded] = useState(false);
  const [customExpanded, setCustomExpanded] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [deletingTech, setDeletingTech] = useState<Technology | null>(null);

  // Tracks which providers have finished loading — drives re-renders when new data arrives
  const [loadedProviders, setLoadedProviders] = useState<Set<CloudProvider>>(() => {
    // Seed with any providers already loaded (e.g. actors, or providers pre-loaded for canvas restore)
    const initial = new Set<CloudProvider>();
    for (const p of [...providerOrder, ACTOR_PROVIDER]) {
      if (getTechnologiesByProvider().has(p)) initial.add(p);
    }
    return initial;
  });

  // Subscribe to provider load events so the palette re-renders as each chunk arrives
  useEffect(() => {
    return subscribeToProviderLoad(provider => {
      setLoadedProviders(prev => {
        if (prev.has(provider)) return prev;
        const next = new Set(prev);
        next.add(provider);
        return next;
      });
    });
  }, []);

  // On mobile, preload all providers the moment the technologies panel opens.
  // This runs during the panel open animation, so data is ready before the user taps anything.
  useEffect(() => {
    if (activePanel === 'technologies') {
      loadProviders(providerOrder);
    }
  }, [activePanel]);

  // Debounce search query to avoid filtering on every keystroke
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(searchQuery);
    }, 200);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Re-derive provider data whenever loadedProviders changes
  const technologiesByProvider = useMemo(
    () => getTechnologiesByProvider(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [loadedProviders]
  );

  // Filter custom technologies by search
  const filteredCustomTechs = useMemo(() => {
    const query = debouncedQuery.toLowerCase().trim();
    if (!query) return customTechnologies;
    return customTechnologies.filter(
      tech =>
        tech.name.toLowerCase().includes(query) ||
        tech.description.toLowerCase().includes(query) ||
        CATEGORY_LABELS[tech.category].toLowerCase().includes(query)
    );
  }, [customTechnologies, debouncedQuery]);

  // Separate actors from regular technologies
  const { actors, filteredTechnologies } = useMemo(() => {
    const allActors = technologiesByProvider.get(ACTOR_PROVIDER) || [];
    const query = debouncedQuery.toLowerCase().trim();

    // Filter actors
    const filteredActors = query
      ? allActors.filter(
          actor =>
            actor.name.toLowerCase().includes(query) ||
            actor.description.toLowerCase().includes(query)
        )
      : allActors;

    // Filter technologies (excluding actors and custom)
    const result = new Map<CloudProvider, Technology[]>();
    if (!query) {
      technologiesByProvider.forEach((techs, provider) => {
        if (provider !== ACTOR_PROVIDER && provider !== 'custom') {
          result.set(provider, techs);
        }
      });
    } else {
      technologiesByProvider.forEach((techs, provider) => {
        if (provider === ACTOR_PROVIDER || provider === 'custom') return;
        const filtered = techs.filter(
          tech =>
            tech.name.toLowerCase().includes(query) ||
            tech.description.toLowerCase().includes(query) ||
            CATEGORY_LABELS[tech.category].toLowerCase().includes(query)
        );
        if (filtered.length > 0) {
          result.set(provider, filtered);
        }
      });
    }

    return { actors: filteredActors, filteredTechnologies: result };
  }, [technologiesByProvider, debouncedQuery, loadedProviders]);

  const toggleProvider = (provider: CloudProvider) => {
    setExpandedProviders(prev => {
      const next = new Set(prev);
      if (next.has(provider)) {
        next.delete(provider);
      } else {
        next.add(provider);
      }
      return next;
    });
  };

  const handleProviderClick = useCallback((provider: CloudProvider) => {
    loadProvider(provider);
    toggleProvider(provider);
  }, []);

  const handleProviderMouseEnter = useCallback((provider: CloudProvider) => {
    loadProvider(provider);
  }, []);

  // Load all providers when search is focused so results are complete
  const handleSearchFocus = useCallback(() => {
    loadProviders(providerOrder);
  }, []);

  const onDragStart = (event: DragEvent, technology: Technology) => {
    event.dataTransfer.setData('application/technology', technology.id);
    event.dataTransfer.effectAllowed = 'move';
  };

  const onDoubleClick = (technology: Technology) => {
    // Place node at the current viewport center (with slight randomization to avoid stacking)
    const center = getViewportCenter();
    const randomOffset = () => Math.random() * 100 - 50; // -50 to +50
    const position = {
      x: (center?.x ?? 400) + randomOffset(),
      y: (center?.y ?? 200) + randomOffset(),
    };
    addNode(technology, position);
  };

  const handleDeleteCustomTech = useCallback((e: React.MouseEvent, tech: Technology) => {
    e.stopPropagation();
    e.preventDefault();
    setDeletingTech(tech);
  }, []);

  const hasCustomTechs = filteredCustomTechs.length > 0;
  const showCustomSection = hasCustomTechs || !debouncedQuery;

  return (
    <div className="tech-palette">
      <div className="palette-header">
        <h2>Components</h2>
        <input
          type="search"
          placeholder="Search services..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onFocus={handleSearchFocus}
          className="search-input"
        />
      </div>

      <div className="palette-content">
        {/* Actors section - separate from providers */}
        {actors.length > 0 && (
          <div className="actor-section">
            <button
              className="provider-header provider-actor"
              onClick={() => setActorsExpanded(prev => !prev)}
            >
              <span className="provider-icon">
                <SquareUserRound size={18} />
              </span>
              <span className="provider-name">Actors</span>
              <span className="provider-count">{actors.length}</span>
              <span className={`chevron ${actorsExpanded || debouncedQuery.trim() !== '' ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>

            {(actorsExpanded || debouncedQuery.trim() !== '') && (
              <div className="tech-list">
                {actors.map(actor => (
                  <div
                    key={actor.id}
                    className="tech-item actor-item"
                    draggable
                    onDragStart={e => onDragStart(e, actor)}
                    onDoubleClick={() => onDoubleClick(actor)}
                    title="Drag to canvas or double-click to add"
                  >
                    <span className="actor-item-icon">
                      <ActorIcon actorId={actor.id} size="small" />
                    </span>
                    <div className="tech-item-info">
                      <div className="tech-item-name">{actor.name}</div>
                      <div className="tech-item-category">{actor.category}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Provider sections — always rendered so hover preload works even before data arrives */}
        {providerOrder.map(provider => {
          const isLoaded = loadedProviders.has(provider);
          const technologies = filteredTechnologies.get(provider);
          const isExpanded = expandedProviders.has(provider) || debouncedQuery.trim() !== '';

          // In search mode, hide providers that are loaded but have no matches
          if (debouncedQuery && isLoaded && (!technologies || technologies.length === 0)) return null;

          return (
            <div key={provider} className="provider-section">
              <button
                className={`provider-header provider-${provider}`}
                onClick={() => handleProviderClick(provider)}
                onMouseEnter={() => handleProviderMouseEnter(provider)}
                onTouchStart={() => handleProviderMouseEnter(provider)}
              >
                <span className="provider-icon">
                  <ProviderIcon provider={provider} size="small" />
                </span>
                <span className="provider-name">{PROVIDER_LABELS[provider]}</span>
                <span className="provider-count">
                  {isLoaded && technologies ? technologies.length : PROVIDER_SERVICE_COUNTS[provider]}
                </span>
                <span className={`chevron ${isExpanded ? 'expanded' : ''}`}>
                  ▶
                </span>
              </button>

              {isExpanded && isLoaded && technologies && technologies.length > 0 && (
                <div className="tech-list">
                  {technologies.map(tech => (
                    <div
                      key={tech.id}
                      className="tech-item"
                      draggable
                      onDragStart={e => onDragStart(e, tech)}
                      onDoubleClick={() => onDoubleClick(tech)}
                      title="Drag to canvas or double-click to add"
                    >
                      <div className="tech-item-name">{tech.name}</div>
                      <div className="tech-item-category">
                        {CATEGORY_LABELS[tech.category]}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}

        {/* Custom technologies section */}
        {showCustomSection && (
          <div className="custom-section">
            <div className="provider-header provider-custom" onClick={() => setCustomExpanded(prev => !prev)}>
              <span className="provider-icon"><Box size={16} color="#10b981" /></span>
              <span className="provider-name">Custom</span>
              {hasCustomTechs && (
                <span className="provider-count">{filteredCustomTechs.length}</span>
              )}
              <button
                className="custom-add-button"
                onClick={e => { e.stopPropagation(); setShowCreateModal(true); }}
                title="Create custom component"
              >
                <Plus size={12} strokeWidth={3} />
                <span>Create</span>
              </button>
              {hasCustomTechs && (
                <span className={`chevron ${customExpanded || debouncedQuery.trim() !== '' ? 'expanded' : ''}`}>
                  ▶
                </span>
              )}
            </div>

            {hasCustomTechs && (customExpanded || debouncedQuery.trim() !== '') && (
              <div className="tech-list">
                {filteredCustomTechs.map(tech => (
                  <div
                    key={tech.id}
                    className="tech-item custom-tech-item"
                    draggable
                    onDragStart={e => onDragStart(e, tech)}
                    onDoubleClick={() => onDoubleClick(tech)}
                    title="Drag to canvas or double-click to add"
                  >
                    <span className="custom-tech-item-icon"><Box size={16} color="#10b981" /></span>
                    <div className="tech-item-info">
                      <div className="tech-item-name">{tech.name}</div>
                      <div className="tech-item-category">
                        {CATEGORY_LABELS[tech.category]}
                      </div>
                    </div>
                    <button
                      className="custom-tech-delete"
                      onClick={e => handleDeleteCustomTech(e, tech)}
                      title="Remove custom technology"
                    >
                      &times;
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {filteredTechnologies.size === 0 && actors.length === 0 && !hasCustomTechs && debouncedQuery && (
          <div className="no-results">
            No services match "{debouncedQuery}"
          </div>
        )}
      </div>

      <CustomTechModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSave={registerCustomTechnology}
      />

      <ConfirmDeleteModal
        isOpen={deletingTech !== null}
        onConfirm={() => {
          if (deletingTech) removeCustomTechnology(deletingTech.id);
          setDeletingTech(null);
        }}
        onCancel={() => setDeletingTech(null)}
        title="Delete Custom Component"
        message={deletingTech ? `This will permanently delete "${deletingTech.name}" and remove all nodes using it from the diagram.` : ''}
      />
    </div>
  );
})
