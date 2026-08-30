import { useState, useEffect } from 'react';
import { Keyboard } from 'lucide-react';
import './ShortcutsModal.css';

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);
const MOD = isMac ? '⌘' : 'Ctrl';

interface Shortcut {
  keys: string[];
  description: string;
}

interface ShortcutGroup {
  title: string;
  shortcuts: Shortcut[];
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    title: 'Selection',
    shortcuts: [
      { keys: [`${MOD}`, 'A'], description: 'Select all nodes' },
      { keys: ['Shift', 'Click'], description: 'Add / remove node from selection' },
      { keys: ['Esc'], description: 'Deselect all / cancel zone drawing' },
    ],
  },
  {
    title: 'Clipboard',
    shortcuts: [
      { keys: [`${MOD}`, 'C'], description: 'Copy selected nodes' },
      { keys: [`${MOD}`, 'X'], description: 'Cut selected nodes' },
      { keys: [`${MOD}`, 'V'], description: 'Paste' },
      { keys: [`${MOD}`, 'D'], description: 'Duplicate selected nodes' },
    ],
  },
  {
    title: 'Editing',
    shortcuts: [
      { keys: ['Delete'], description: 'Delete selected nodes' },
      { keys: ['Arrows'], description: 'Nudge selected nodes (10px)' },
      { keys: ['Shift', 'Arrows'], description: 'Fine nudge (1px)' },
      { keys: ['Double-click'], description: 'Palette item: add to canvas · Connection: edit label' },
    ],
  },
  {
    title: 'History',
    shortcuts: [
      { keys: [`${MOD}`, 'Z'], description: 'Undo' },
      { keys: [`${MOD}`, 'Shift', 'Z'], description: 'Redo' },
      { keys: [`${MOD}`, 'Y'], description: 'Redo (alternative)' },
    ],
  },
];

/**
 * Self-contained keyboard shortcuts cheat sheet. Mounts a global listener:
 * "?" toggles the overlay, Escape closes it. A full reference also lives in
 * the About modal's "How to Use" tab; this is the quick-glance version.
 */
export default function ShortcutsModal() {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsOpen(false);
        return;
      }
      // Skip when typing in an input field
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        (e.target instanceof HTMLElement && e.target.isContentEditable)
      ) {
        return;
      }
      if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        setIsOpen(open => !open);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  if (!isOpen) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      setIsOpen(false);
    }
  };

  return (
    <div className="shortcuts-modal-overlay" onClick={handleOverlayClick}>
      <div className="shortcuts-modal" role="dialog" aria-label="Keyboard shortcuts">
        <button className="shortcuts-modal-close" onClick={() => setIsOpen(false)} title="Close">
          &times;
        </button>
        <div className="shortcuts-modal-header">
          <Keyboard size={18} />
          <h2>Keyboard Shortcuts</h2>
        </div>
        <div className="shortcuts-modal-grid">
          {SHORTCUT_GROUPS.map(group => (
            <div key={group.title} className="shortcuts-group">
              <h3>{group.title}</h3>
              {group.shortcuts.map(shortcut => (
                <div key={shortcut.description} className="shortcut-row">
                  <span className="shortcut-keys">
                    {shortcut.keys.map((key, i) => (
                      <span key={key}>
                        {i > 0 && <span className="shortcut-plus">+</span>}
                        <kbd>{key}</kbd>
                      </span>
                    ))}
                  </span>
                  <span className="shortcut-description">{shortcut.description}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div className="shortcuts-modal-footer">
          Press <kbd>?</kbd> to toggle this panel · Full guide in the About menu
        </div>
      </div>
    </div>
  );
}
