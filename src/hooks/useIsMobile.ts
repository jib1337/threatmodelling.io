import { useCallback, useSyncExternalStore } from 'react';

// Keep in step with the `@media (max-width: 768px)` blocks in the component
// stylesheets — CSS can't import this constant, so it is the JS copy of that breakpoint.
export const MOBILE_BREAKPOINT = 768;
export const MOBILE_MEDIA_QUERY = `(max-width: ${MOBILE_BREAKPOINT}px)`;

/**
 * Tracks a CSS media query and re-renders when it starts or stops matching.
 * Returns false where `matchMedia` is unavailable (jsdom, SSR).
 */
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      const mql = window.matchMedia?.(query);
      if (!mql) return () => {};
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    },
    [query]
  );

  return useSyncExternalStore(
    subscribe,
    () => window.matchMedia?.(query).matches ?? false,
    () => false
  );
}

/** True when the app is in its mobile layout (drawers, bottom sheets, icon-only toolbar). */
export function useIsMobile(): boolean {
  return useMediaQuery(MOBILE_MEDIA_QUERY);
}
