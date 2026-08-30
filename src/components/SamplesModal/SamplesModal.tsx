import { useState, useEffect, useCallback } from 'react';
import { useModel, useDiagramState } from '../../context/ThreatModelContext';
import { SAMPLE_ARCHITECTURES } from '../../data/samples';
import ConfirmDeleteModal from '../ConfirmDeleteModal/ConfirmDeleteModal';
import './SamplesModal.css';

interface SamplesModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SamplesModal({ isOpen, onClose }: SamplesModalProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showConfirm, setShowConfirm] = useState(false);
  const { importModel } = useModel();
  const { nodes } = useDiagramState();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  const handleOverlayClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose();
  }, [onClose]);

  const loadSample = useCallback(async () => {
    const sample = SAMPLE_ARCHITECTURES[selectedIndex];
    await importModel(sample.data);
    onClose();
  }, [selectedIndex, importModel, onClose]);

  const handleLoad = useCallback(() => {
    if (nodes.length > 0) {
      setShowConfirm(true);
    } else {
      loadSample();
    }
  }, [nodes.length, loadSample]);

  if (!isOpen) return null;

  const selected = SAMPLE_ARCHITECTURES[selectedIndex];

  return (
    <>
      <div className="samples-modal-overlay" onClick={handleOverlayClick}>
        <div className="samples-modal">
          <div className="samples-modal-header">
            <h2>Sample Architectures</h2>
            <button className="samples-modal-close" onClick={onClose} title="Close">
              &times;
            </button>
          </div>

          <div className="samples-modal-body">
            <div className="samples-list">
              {SAMPLE_ARCHITECTURES.map((sample, i) => (
                <button
                  key={sample.id}
                  className={`sample-card ${i === selectedIndex ? 'selected' : ''}`}
                  onClick={() => setSelectedIndex(i)}
                >
                  <span className="sample-card-name">{sample.name}</span>
                </button>
              ))}
            </div>

            <div className="sample-detail">
              <h3 className="sample-detail-name">{selected.name}</h3>
              <p className="sample-detail-description">{selected.description}</p>
              <button className="sample-load-button" onClick={handleLoad}>
                Load Sample
              </button>
            </div>
          </div>
        </div>
      </div>

      <ConfirmDeleteModal
        isOpen={showConfirm}
        onConfirm={() => {
          setShowConfirm(false);
          loadSample();
        }}
        onCancel={() => setShowConfirm(false)}
        title="Load Sample"
        message="Loading a sample will replace your current diagram. Are you sure you want to continue?"
        confirmLabel="Load"
      />
    </>
  );
}
