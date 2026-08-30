import { useState, useEffect, useCallback } from 'react';
import { subscribeToToasts, type ToastItem } from '../../utils/toast';
import './Toast.css';

interface ToastProps {
  toast: ToastItem;
  onDismiss: (id: number) => void;
}

function Toast({ toast, onDismiss }: ToastProps) {
  useEffect(() => {
    const duration = toast.duration ?? (toast.actionLabel ? 8000 : 4000);
    const handle = window.setTimeout(() => onDismiss(toast.id), duration);
    return () => window.clearTimeout(handle);
  }, [toast, onDismiss]);

  return (
    <div className={`toast toast-${toast.type ?? 'info'}`}>
      <span className="toast-message">{toast.message}</span>
      {toast.actionLabel && (
        <button
          className="toast-action"
          onClick={() => {
            toast.onAction?.();
            onDismiss(toast.id);
          }}
        >
          {toast.actionLabel}
        </button>
      )}
      <button
        className="toast-dismiss"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
      >
        &times;
      </button>
    </div>
  );
}

export default function ToastContainer() {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => {
    return subscribeToToasts(toast => {
      setToasts(prev => [...prev, toast]);
    });
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="toast-container" role="status" aria-live="polite">
      {toasts.map(toast => (
        <Toast key={toast.id} toast={toast} onDismiss={dismiss} />
      ))}
    </div>
  );
}
