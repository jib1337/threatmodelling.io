// Tiny publish/subscribe bus for transient notifications. Kept out of React
// context so non-component code (e.g. the ThreatModelProvider's restore
// effect) can raise toasts without worrying about provider nesting order.
// ToastContainer subscribes and renders whatever is emitted.

export type ToastType = 'info' | 'success' | 'error';

export interface ToastOptions {
  type?: ToastType;
  /** Auto-dismiss delay in ms. Defaults to 4000, or 8000 when an action is present. */
  duration?: number;
  actionLabel?: string;
  onAction?: () => void;
}

export interface ToastItem extends ToastOptions {
  id: number;
  message: string;
}

type ToastListener = (toast: ToastItem) => void;

let listeners: ToastListener[] = [];
let nextId = 1;

export function showToast(message: string, options: ToastOptions = {}): void {
  const toast: ToastItem = { id: nextId++, message, ...options };
  listeners.forEach(listener => listener(toast));
}

export function subscribeToToasts(listener: ToastListener): () => void {
  listeners.push(listener);
  return () => {
    listeners = listeners.filter(l => l !== listener);
  };
}
