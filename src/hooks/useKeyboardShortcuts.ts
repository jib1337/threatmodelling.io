import { useEffect, useRef, useCallback } from 'react';
import { useHistory, useClipboard, useSelection, useActions } from '../context/ThreatModelContext';

const NUDGE_AMOUNT = 10;
const FINE_NUDGE_AMOUNT = 1;
const NUDGE_HISTORY_DELAY = 500; // ms to wait before saving history after nudge

export function useKeyboardShortcuts() {
  const { undo, redo, canUndo, canRedo } = useHistory();
  const { copySelection, pasteClipboard, cutSelection, duplicateSelection, hasClipboard } = useClipboard();
  const { selectedNodes, selectAll, deselectAll } = useSelection();
  const { removeSelectedNodes, nudgeNodes, saveHistory } = useActions();

  // Track nudge bursts: history is saved once before the first nudge of a
  // burst, and the burst ends after a pause, so rapid arrow presses undo as one
  const nudgeTimeoutRef = useRef<number | null>(null);
  const hasNudgedRef = useRef(false);

  const endNudgeBurst = useCallback(() => {
    hasNudgedRef.current = false;
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Skip if user is typing in an input field
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        (e.target instanceof HTMLElement && e.target.isContentEditable)
      ) {
        return;
      }

      const isMod = e.ctrlKey || e.metaKey;

      // Undo: Ctrl/Cmd + Z (without Shift)
      if (isMod && e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        if (canUndo) undo();
        return;
      }

      // Redo: Ctrl/Cmd + Y or Ctrl/Cmd + Shift + Z
      if (isMod && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) {
        e.preventDefault();
        if (canRedo) redo();
        return;
      }

      // Copy: Ctrl/Cmd + C
      // Only intercept when nodes are selected and the user isn't copying
      // highlighted text (e.g. a threat description in the sidebar).
      if (isMod && e.key === 'c') {
        if (selectedNodes.length === 0 || window.getSelection()?.toString()) {
          return; // let the browser handle the copy
        }
        e.preventDefault();
        copySelection();
        return;
      }

      // Paste: Ctrl/Cmd + V
      if (isMod && e.key === 'v') {
        e.preventDefault();
        if (hasClipboard) pasteClipboard();
        return;
      }

      // Cut: Ctrl/Cmd + X (same text-selection guard as copy)
      if (isMod && e.key === 'x') {
        if (selectedNodes.length === 0 || window.getSelection()?.toString()) {
          return;
        }
        e.preventDefault();
        cutSelection();
        return;
      }

      // Duplicate: Ctrl/Cmd + D
      if (isMod && e.key === 'd') {
        e.preventDefault();
        if (selectedNodes.length > 0) duplicateSelection();
        return;
      }

      // Select All: Ctrl/Cmd + A
      if (isMod && e.key === 'a') {
        e.preventDefault();
        selectAll();
        return;
      }

      // Delete: Delete or Backspace
      if (e.key === 'Delete' || e.key === 'Backspace') {
        e.preventDefault();
        if (selectedNodes.length > 0) removeSelectedNodes();
        return;
      }

      // Escape: Deselect all
      if (e.key === 'Escape') {
        e.preventDefault();
        deselectAll();
        return;
      }

      // Arrow keys: Nudge selected nodes
      if (e.key.startsWith('Arrow') && selectedNodes.length > 0) {
        e.preventDefault();
        const amount = e.shiftKey ? FINE_NUDGE_AMOUNT : NUDGE_AMOUNT;
        let dx = 0;
        let dy = 0;

        switch (e.key) {
          case 'ArrowUp':
            dy = -amount;
            break;
          case 'ArrowDown':
            dy = amount;
            break;
          case 'ArrowLeft':
            dx = -amount;
            break;
          case 'ArrowRight':
            dx = amount;
            break;
        }

        if (dx !== 0 || dy !== 0) {
          // Save history before the first nudge of a burst so the whole
          // burst undoes as a single step (NUDGE_NODES doesn't save history).
          if (!hasNudgedRef.current) {
            saveHistory();
            hasNudgedRef.current = true;
          }
          nudgeNodes(dx, dy);

          // A pause ends the burst; the next nudge starts a new undo step
          if (nudgeTimeoutRef.current) {
            window.clearTimeout(nudgeTimeoutRef.current);
          }
          nudgeTimeoutRef.current = window.setTimeout(endNudgeBurst, NUDGE_HISTORY_DELAY);
        }
        return;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (nudgeTimeoutRef.current) {
        window.clearTimeout(nudgeTimeoutRef.current);
      }
    };
  }, [
    undo,
    redo,
    canUndo,
    canRedo,
    copySelection,
    pasteClipboard,
    cutSelection,
    duplicateSelection,
    removeSelectedNodes,
    selectAll,
    deselectAll,
    nudgeNodes,
    selectedNodes,
    hasClipboard,
    saveHistory,
    endNudgeBurst,
  ]);
}
