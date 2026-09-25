import { useEffect, useRef, useState, type ReactNode, type PointerEvent } from 'react';
import { ChevronUp } from 'lucide-react';
import { useIsMobile } from '../../hooks/useIsMobile';
import './PropertiesSheet.css';

// Movement (px) before a press on the header counts as a drag rather than a tap
const DRAG_SLOP = 6;
// Drag distance (px) that commits a flick up to expanded, or down to collapsed
const SNAP_DISTANCE = 40;

interface PropertiesSheetProps {
  /** The panel's own class, which carries its desktop side-panel styling */
  className: string;
  /** Names the selection in the collapsed mobile peek bar */
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
}

/**
 * The shell shared by the node and zone properties panels.
 *
 * On desktop it is the plain side panel. On mobile it is a bottom sheet that
 * opens collapsed to a peek bar, so selecting a node doesn't cover half the
 * canvas; the user taps or drags the bar up to expand it and down to collapse.
 * The expanded state persists while the selection moves between items of the
 * same kind, and resets when the sheet closes.
 */
export default function PropertiesSheet({ className, subtitle, onClose, children }: PropertiesSheetProps) {
  const isMobile = useIsMobile();
  const [expanded, setExpanded] = useState(false);
  // Live translateY (px) while the user drags the header; null when at rest
  const [dragOffset, setDragOffset] = useState<number | null>(null);
  const sheetRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const drag = useRef<{ startY: number; base: number; max: number; moved: boolean } | null>(null);
  // Set when a drag ends so the click that follows the pointerup doesn't also toggle
  const suppressClick = useRef(false);

  const collapsed = isMobile && !expanded;

  // Keep the off-screen body out of the tab order and accessibility tree.
  // React 18 has no typed `inert` prop, so set the attribute directly.
  useEffect(() => {
    bodyRef.current?.toggleAttribute('inert', collapsed);
  }, [collapsed]);

  const handlePointerDown = (e: PointerEvent<HTMLDivElement>) => {
    suppressClick.current = false;
    if (!isMobile || (e.target as HTMLElement).closest('.close-button')) return;
    // How far down the sheet travels when collapsed: everything but the peek bar
    const max = (sheetRef.current?.offsetHeight ?? 0) - (headerRef.current?.offsetHeight ?? 0);
    drag.current = { startY: e.clientY, base: expanded ? 0 : max, max, moved: false };
  };

  const handlePointerMove = (e: PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d) return;
    const dy = e.clientY - d.startY;
    if (!d.moved) {
      if (Math.abs(dy) < DRAG_SLOP) return;
      // Capture only once it is a drag, so a plain tap still clicks the toggle
      d.moved = true;
      e.currentTarget.setPointerCapture(e.pointerId);
    }
    setDragOffset(Math.min(d.max, Math.max(0, d.base + dy)));
  };

  const handlePointerUp = (e: PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    drag.current = null;
    if (!d?.moved) return;
    suppressClick.current = true;
    const dy = e.clientY - d.startY;
    if (dy <= -SNAP_DISTANCE) setExpanded(true);
    else if (dy >= SNAP_DISTANCE) setExpanded(false);
    setDragOffset(null);
  };

  const handlePointerCancel = () => {
    drag.current = null;
    setDragOffset(null);
  };

  const handleToggle = () => {
    if (suppressClick.current) {
      suppressClick.current = false;
      return;
    }
    setExpanded(prev => !prev);
  };

  const sheetClass = isMobile
    ? ` properties-sheet ${collapsed ? 'collapsed' : 'expanded'}${dragOffset !== null ? ' dragging' : ''}`
    : '';

  return (
    <div
      ref={sheetRef}
      className={`${className}${sheetClass}`}
      style={dragOffset !== null ? { transform: `translateY(${dragOffset}px)` } : undefined}
    >
      <div
        ref={headerRef}
        className="panel-header"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerCancel}
      >
        {isMobile ? (
          <button
            className="sheet-toggle"
            onClick={handleToggle}
            aria-expanded={expanded}
            title={expanded ? 'Collapse properties' : 'Expand properties'}
          >
            <span className="sheet-grabber" aria-hidden="true" />
            <span className="sheet-title">
              <h3>Properties</h3>
              {subtitle && <span className="sheet-subtitle">{subtitle}</span>}
            </span>
            <ChevronUp size={18} className="sheet-chevron" aria-hidden="true" />
          </button>
        ) : (
          <h3>Properties</h3>
        )}
        <button className="close-button" onClick={onClose} title="Close panel">
          &times;
        </button>
      </div>

      <div ref={bodyRef} className="sheet-body">
        {children}
      </div>
    </div>
  );
}
