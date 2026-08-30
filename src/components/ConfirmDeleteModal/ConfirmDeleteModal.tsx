import { useEffect, useCallback } from 'react';
import './ConfirmDeleteModal.css';

interface ConfirmDeleteModalProps {
  isOpen: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
}

export default function ConfirmDeleteModal({ isOpen, onConfirm, onCancel, title, message, confirmLabel = 'Delete' }: ConfirmDeleteModalProps) {
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onCancel]);

  const handleOverlayClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onCancel();
  }, [onCancel]);

  if (!isOpen) return null;

  return (
    <div className="confirm-delete-overlay" onClick={handleOverlayClick}>
      <div className="confirm-delete-modal">
        <h3 className="confirm-delete-title">{title}</h3>
        <p className="confirm-delete-message">{message}</p>
        <div className="confirm-delete-buttons">
          <button className="confirm-delete-cancel" onClick={onCancel}>
            Cancel
          </button>
          <button className="confirm-delete-confirm" onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
