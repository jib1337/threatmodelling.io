import './ActorIcon.css';

interface ActorIconProps {
  actorId: string;
  size?: 'small' | 'medium' | 'large';
  className?: string;
}

// Inline SVG paths for each actor type (using currentColor for theme support)
const ACTOR_SVG_PATHS: Record<string, React.ReactNode> = {
  'actor-mobile': (
    <>
      <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/>
      <line x1="12" y1="18" x2="12.01" y2="18"/>
    </>
  ),
  'actor-desktop': (
    <>
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
      <line x1="8" y1="21" x2="16" y2="21"/>
      <line x1="12" y1="17" x2="12" y2="21"/>
    </>
  ),
  'actor-iot': (
    <>
      <rect x="4" y="4" width="16" height="16" rx="2" ry="2"/>
      <circle cx="12" cy="12" r="3"/>
      <line x1="12" y1="2" x2="12" y2="4"/>
      <line x1="12" y1="20" x2="12" y2="22"/>
      <line x1="2" y1="12" x2="4" y2="12"/>
      <line x1="20" y1="12" x2="22" y2="12"/>
    </>
  ),
  'actor-browser': (
    <>
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </>
  ),
  'actor-api-client': (
    <>
      <path d="M4 17l6-6-6-6"/>
      <path d="M12 19h8"/>
    </>
  ),
  'actor-server': (
    <>
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
      <line x1="6" y1="6" x2="6.01" y2="6"/>
      <line x1="6" y1="18" x2="6.01" y2="18"/>
    </>
  ),
};

export default function ActorIcon({ actorId, size = 'medium', className = '' }: ActorIconProps) {
  const svgContent = ACTOR_SVG_PATHS[actorId];

  if (svgContent) {
    return (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={`actor-icon actor-icon-${size} ${className}`}
      >
        {svgContent}
      </svg>
    );
  }

  // Fallback for unknown actors
  return (
    <span className={`actor-icon-emoji actor-icon-${size} ${className}`}>
      👤
    </span>
  );
}
