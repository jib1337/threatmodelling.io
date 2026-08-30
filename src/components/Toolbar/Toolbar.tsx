import { useState, useEffect, useCallback } from 'react';
import { getNodesBounds, getViewportForBounds } from '@xyflow/react';
import {
  Undo2,
  Redo2,
  Sun,
  Moon,
  FolderOpen,
  Download,
  FileJson,
  FileCode,
  FileText,
  ClipboardList,
  Trash2,
  Shield,
  Plus,
  ChevronDown,
  Globe,
  Lock,
  Settings,
} from 'lucide-react';
import { useModel, useDiagramState, useHistory, useThreats, useDrawing } from '../../context/ThreatModelContext';
import { useTheme } from '../../context/ThemeContext';
import { useFileOperations } from '../../hooks/useFileOperations';
import { useMobilePanel } from '../App';
import { generateMarkdownReport } from '../../utils/markdownExport';
import { exportThreatcl } from '../../utils/threatclExport';
import { showToast } from '../../utils/toast';
import AboutModal from '../AboutModal/AboutModal';
import SettingsModal from '../SettingsModal/SettingsModal';
import SupportModal from '../SupportModal/SupportModal';
import SamplesModal from '../SamplesModal/SamplesModal';
import ConfirmDeleteModal from '../ConfirmDeleteModal/ConfirmDeleteModal';
import './Toolbar.css';

const IMAGE_WIDTH = 1920;
const IMAGE_HEIGHT = 1080;

export default function Toolbar() {
  const { modelName, setModelName, exportModel, importModel, clearDiagram } = useModel();
  const { nodes, edges, boundaries } = useDiagramState();
  const { canUndo, canRedo, undo, redo } = useHistory();
  const { activeThreats, implementedControls } = useThreats();
  const { drawingZoneType, startDrawingPublicZone, startDrawingPrivateZone, cancelDrawingMode } = useDrawing();
  const { theme, toggleTheme } = useTheme();
  const { exportToFile, importFromFile } = useFileOperations();
  const { activePanel, setActivePanel } = useMobilePanel();
  const [isEditing, setIsEditing] = useState(false);
  const [editValue, setEditValue] = useState(modelName);
  const [isAboutOpen, setIsAboutOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isSupportOpen, setIsSupportOpen] = useState(false);
  const [isSamplesOpen, setIsSamplesOpen] = useState(false);
  const [exportDropdownOpen, setExportDropdownOpen] = useState(false);
  const [isClearConfirmOpen, setIsClearConfirmOpen] = useState(false);

  const toggleThreatsPanel = () => {
    setActivePanel(activePanel === 'threats' ? null : 'threats');
  };

  const toggleTechPanel = () => {
    setActivePanel(activePanel === 'technologies' ? null : 'technologies');
  };

  const togglePublicZone = () => {
    if (drawingZoneType === 'public') {
      cancelDrawingMode();
    } else {
      startDrawingPublicZone();
      setActivePanel(null); // Close any open mobile panels
    }
  };

  const togglePrivateZone = () => {
    if (drawingZoneType === 'private') {
      cancelDrawingMode();
    } else {
      startDrawingPrivateZone();
      setActivePanel(null); // Close any open mobile panels
    }
  };

  const captureDiagramImage = useCallback(async (): Promise<string | null> => {
    const viewportEl = document.querySelector('.react-flow__viewport') as HTMLElement;
    // Include both boundaries and nodes in the check and bounds calculation
    const allNodes = [...boundaries, ...nodes];
    if (!viewportEl || allNodes.length === 0) return null;

    // Dynamically import html-to-image
    const { toPng } = await import('html-to-image');

    const nodesBounds = getNodesBounds(allNodes);
    const { x, y, zoom } = getViewportForBounds(
      nodesBounds,
      IMAGE_WIDTH,
      IMAGE_HEIGHT,
      0.5,
      2,
      0.2
    );

    const bgColor = getComputedStyle(document.documentElement)
      .getPropertyValue('--bg-primary')
      .trim();

    try {
      return await toPng(viewportEl, {
        backgroundColor: bgColor || '#0d1117',
        width: IMAGE_WIDTH,
        height: IMAGE_HEIGHT,
        style: {
          width: String(IMAGE_WIDTH),
          height: String(IMAGE_HEIGHT),
          transform: `translate(${x}px, ${y}px) scale(${zoom})`,
        },
      });
    } catch {
      return null;
    }
  }, [nodes, boundaries]);

  const handleExportJson = useCallback(() => {
    const model = exportModel();
    exportToFile(model);
    setExportDropdownOpen(false);
    showToast('Model exported as JSON', { type: 'success' });
  }, [exportModel, exportToFile]);

  const handleExportPdfSummary = useCallback(async () => {
    setExportDropdownOpen(false);
    const [diagramImage, { generateExecutiveSummary }] = await Promise.all([
      captureDiagramImage(),
      import('../../utils/pdfExport'),
    ]);
    await generateExecutiveSummary(modelName, nodes, edges, activeThreats, diagramImage);
    showToast('PDF summary exported', { type: 'success' });
  }, [modelName, nodes, edges, activeThreats, captureDiagramImage]);

  const handleExportPdfFull = useCallback(async () => {
    setExportDropdownOpen(false);
    const [diagramImage, { generateFullReport }] = await Promise.all([
      captureDiagramImage(),
      import('../../utils/pdfExport'),
    ]);
    await generateFullReport(modelName, nodes, edges, activeThreats, diagramImage, implementedControls);
    showToast('PDF report exported', { type: 'success' });
  }, [modelName, nodes, edges, activeThreats, captureDiagramImage, implementedControls]);

  const handleExportMarkdown = useCallback(async () => {
    setExportDropdownOpen(false);
    await generateMarkdownReport(modelName, nodes, edges, activeThreats, implementedControls);
    showToast('Markdown report exported', { type: 'success' });
  }, [modelName, nodes, edges, activeThreats, implementedControls]);

  const handleExportThreatcl = useCallback(() => {
    setExportDropdownOpen(false);
    exportThreatcl(modelName, nodes, edges, activeThreats, boundaries, implementedControls);
    showToast('threatcl file exported', { type: 'success' });
  }, [modelName, nodes, edges, activeThreats, boundaries, implementedControls]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      if (!target.closest('.export-dropdown')) {
        setExportDropdownOpen(false);
      }
    };

    if (exportDropdownOpen) {
      document.addEventListener('click', handleClickOutside);
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [exportDropdownOpen]);

  const handleImport = async () => {
    try {
      const model = await importFromFile();
      await importModel(model);
      showToast(`Imported "${model.name}"`, { type: 'success' });
    } catch (err) {
      console.error('Failed to import model:', err);
      showToast('Import failed — the file is not a valid threat model JSON', {
        type: 'error',
        duration: 6000,
      });
    }
  };

  const handleClear = () => {
    if (nodes.length === 0) return;
    setIsClearConfirmOpen(true);
  };

  const handleNameSubmit = () => {
    setModelName(editValue.trim() || 'Untitled Threat Model');
    setIsEditing(false);
  };

  const handleNameKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleNameSubmit();
    } else if (e.key === 'Escape') {
      setEditValue(modelName);
      setIsEditing(false);
    }
  };

  return (
    <header className="toolbar">
      <div className="toolbar-left">
        <div className="logo">
          <h1 className="logo-text">ThreatModelling.io</h1>
        </div>
        <div className="toolbar-nav-buttons">
          <button
            className="about-button"
            onClick={() => setIsAboutOpen(true)}
            title="About this tool"
          >
            About
          </button>
          <button
            className="samples-button"
            onClick={() => setIsSamplesOpen(true)}
            title="Load sample architectures"
          >
            Samples
          </button>
          <button
            className="support-button"
            onClick={() => setIsSupportOpen(true)}
            title="Support this project"
          >
            Support
          </button>
        </div>
      </div>

      <div className="toolbar-right">
        {/* Mobile-only panel toggles */}
        <button
          className="toolbar-button mobile-only"
          onClick={toggleThreatsPanel}
          title="View Threats"
        >
          <Shield size={16} />
          <span className="badge">{activeThreats.length}</span>
        </button>
        <button
          className="toolbar-button mobile-only"
          onClick={toggleTechPanel}
          title="Add Technologies"
        >
          <Plus size={16} />
        </button>
        <div className="toolbar-divider mobile-only" />
        {/* Mobile-only zone drawing buttons */}
        <button
          className={`toolbar-button mobile-only ${drawingZoneType === 'public' ? 'zone-active zone-public' : ''}`}
          onClick={togglePublicZone}
          title={drawingZoneType === 'public' ? 'Cancel drawing' : 'Draw Public Zone'}
        >
          <Globe size={16} />
        </button>
        <button
          className={`toolbar-button mobile-only ${drawingZoneType === 'private' ? 'zone-active zone-private' : ''}`}
          onClick={togglePrivateZone}
          title={drawingZoneType === 'private' ? 'Cancel drawing' : 'Draw Private Zone'}
        >
          <Lock size={16} />
        </button>
        <div className="toolbar-divider mobile-only" />

        {/* Desktop buttons with labels */}
        <button
          className="toolbar-button desktop-only"
          onClick={undo}
          disabled={!canUndo}
          title="Undo (Ctrl+Z)"
        >
          <Undo2 size={16} />
          <span className="button-label">Undo</span>
        </button>
        <button
          className="toolbar-button desktop-only"
          onClick={redo}
          disabled={!canRedo}
          title="Redo (Ctrl+Y)"
        >
          <Redo2 size={16} />
          <span className="button-label">Redo</span>
        </button>
        <div className="toolbar-divider desktop-only" />
        <button
          className="toolbar-button theme-toggle desktop-only"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        <button
          className="toolbar-button desktop-only"
          onClick={() => setIsSettingsOpen(true)}
          title="Model Settings"
        >
          <Settings size={16} />
          <span className="button-label">Settings</span>
        </button>
        <div className="toolbar-divider desktop-only" />
        <div className="model-name desktop-only">
          {isEditing ? (
            <input
              type="text"
              value={editValue}
              onChange={e => setEditValue(e.target.value)}
              onBlur={handleNameSubmit}
              onKeyDown={handleNameKeyDown}
              className="name-input"
              placeholder="Enter model name"
              autoFocus
            />
          ) : (
            <button
              className="name-button"
              onClick={() => {
                setEditValue(modelName === 'Untitled Threat Model' ? '' : modelName);
                setIsEditing(true);
              }}
              title="Click to rename"
            >
              {modelName}
            </button>
          )}
        </div>
        <div className="toolbar-divider desktop-only" />
        <button className="toolbar-button desktop-only" onClick={handleImport}>
          <FolderOpen size={16} />
          <span className="button-label">Import JSON</span>
        </button>
        <div className="export-dropdown desktop-only">
          <button
            className="toolbar-button"
            onClick={() => setExportDropdownOpen(!exportDropdownOpen)}
            disabled={nodes.length === 0}
          >
            <Download size={16} />
            <span className="button-label">Export</span>
            <ChevronDown size={14} />
          </button>
          {exportDropdownOpen && (
            <div className="export-dropdown-menu">
              <button onClick={handleExportJson}>
                <FileJson size={14} /> JSON
              </button>
              <button onClick={handleExportPdfSummary}>
                <FileText size={14} /> PDF Summary
              </button>
              <button onClick={handleExportPdfFull}>
                <ClipboardList size={14} /> PDF Report
              </button>
              <button onClick={handleExportMarkdown}>
                <FileText size={14} /> Markdown Report
              </button>
              <button onClick={handleExportThreatcl}>
                <FileCode size={14} /> threatcl (HCL)
              </button>
            </div>
          )}
        </div>
        <button
          className="toolbar-button danger desktop-only"
          onClick={handleClear}
          disabled={nodes.length === 0}
        >
          <Trash2 size={16} />
          <span className="button-label">Clear</span>
        </button>

        {/* Mobile icon-only buttons */}
        <button
          className="toolbar-button mobile-only"
          onClick={undo}
          disabled={!canUndo}
          title="Undo"
        >
          <Undo2 size={16} />
        </button>
        <button
          className="toolbar-button mobile-only"
          onClick={redo}
          disabled={!canRedo}
          title="Redo"
        >
          <Redo2 size={16} />
        </button>
        <button
          className="toolbar-button theme-toggle mobile-only"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
        <button
          className="toolbar-button mobile-only"
          onClick={() => setIsSettingsOpen(true)}
          title="Model Settings"
        >
          <Settings size={16} />
        </button>
        <button className="toolbar-button mobile-only" onClick={handleImport} title="Import">
          <FolderOpen size={16} />
        </button>
        <div className="export-dropdown mobile-only">
          <button
            className="toolbar-button"
            onClick={() => setExportDropdownOpen(!exportDropdownOpen)}
            disabled={nodes.length === 0}
            title="Export"
          >
            <Download size={16} />
          </button>
          {exportDropdownOpen && (
            <div className="export-dropdown-menu">
              <button onClick={handleExportJson}>
                <FileJson size={14} /> JSON
              </button>
              <button onClick={handleExportPdfSummary}>
                <FileText size={14} /> PDF Summary
              </button>
              <button onClick={handleExportPdfFull}>
                <ClipboardList size={14} /> PDF Full Report
              </button>
              <button onClick={handleExportMarkdown}>
                <FileText size={14} /> Markdown Report
              </button>
              <button onClick={handleExportThreatcl}>
                <FileCode size={14} /> threatcl (HCL)
              </button>
            </div>
          )}
        </div>
        <button
          className="toolbar-button danger mobile-only"
          onClick={handleClear}
          disabled={nodes.length === 0}
          title="Clear"
        >
          <Trash2 size={16} />
        </button>
      </div>

      <AboutModal isOpen={isAboutOpen} onClose={() => setIsAboutOpen(false)} />
      <SettingsModal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
      <SupportModal isOpen={isSupportOpen} onClose={() => setIsSupportOpen(false)} />
      <SamplesModal isOpen={isSamplesOpen} onClose={() => setIsSamplesOpen(false)} />
      <ConfirmDeleteModal
        isOpen={isClearConfirmOpen}
        onConfirm={() => {
          clearDiagram();
          setIsClearConfirmOpen(false);
        }}
        onCancel={() => setIsClearConfirmOpen(false)}
        title="Clear Diagram"
        message="Are you sure you want to clear the diagram? All nodes, edges, and zones will be removed."
        confirmLabel="Clear"
      />
    </header>
  );
}
