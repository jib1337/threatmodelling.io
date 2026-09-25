import { describe, it, expect, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useIsMobile, useMediaQuery, MOBILE_MEDIA_QUERY } from './useIsMobile';

function mockMatchMedia(initial: boolean) {
  let matches = initial;
  const listeners = new Set<() => void>();
  const matchMedia = vi.fn((query: string) => ({
    get matches() { return matches; },
    media: query,
    addEventListener: (_: string, cb: () => void) => listeners.add(cb),
    removeEventListener: (_: string, cb: () => void) => listeners.delete(cb),
  }));
  vi.stubGlobal('matchMedia', matchMedia);
  return {
    matchMedia,
    listeners,
    set(next: boolean) {
      matches = next;
      listeners.forEach(cb => cb());
    },
  };
}

describe('useMediaQuery', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns false when matchMedia is unavailable', () => {
    vi.stubGlobal('matchMedia', undefined);
    const { result } = renderHook(() => useMediaQuery('(pointer: coarse)'));
    expect(result.current).toBe(false);
  });

  it('reflects the current match and updates when it changes', () => {
    const media = mockMatchMedia(false);
    const { result } = renderHook(() => useMediaQuery('(pointer: coarse)'));
    expect(result.current).toBe(false);

    act(() => media.set(true));
    expect(result.current).toBe(true);
  });

  it('unsubscribes on unmount', () => {
    const media = mockMatchMedia(true);
    const { unmount } = renderHook(() => useMediaQuery('(pointer: coarse)'));
    expect(media.listeners.size).toBe(1);

    unmount();
    expect(media.listeners.size).toBe(0);
  });
});

describe('useIsMobile', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('queries the shared mobile breakpoint', () => {
    const media = mockMatchMedia(true);
    const { result } = renderHook(() => useIsMobile());
    expect(result.current).toBe(true);
    expect(media.matchMedia).toHaveBeenCalledWith(MOBILE_MEDIA_QUERY);
  });
});
