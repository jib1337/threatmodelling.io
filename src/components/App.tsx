import { useState, createContext, useContext } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { ThreatModelProvider } from '../context/ThreatModelContext';
import { ThemeProvider } from '../context/ThemeContext';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import Toolbar from './Toolbar/Toolbar';
import ThreatSidebar from './Sidebar/ThreatSidebar';
import DiagramCanvas from './Diagram/DiagramCanvas';
import TechPalette from './TechPalette/TechPalette';
import ToastContainer from './Toast/ToastContainer';
import ShortcutsModal from './ShortcutsModal/ShortcutsModal';
import './App.css';

// Mobile panel context
interface MobilePanelContextValue {
  activePanel: 'threats' | 'technologies' | null;
  setActivePanel: (panel: 'threats' | 'technologies' | null) => void;
}

const MobilePanelContext = createContext<MobilePanelContextValue | null>(null);

export function useMobilePanel() {
  const context = useContext(MobilePanelContext);
  if (!context) {
    throw new Error('useMobilePanel must be used within MobilePanelProvider');
  }
  return context;
}

// Inner component that has access to ThreatModel context
function AppContent() {
  const [activePanel, setActivePanel] = useState<'threats' | 'technologies' | null>(null);

  // Initialize keyboard shortcuts
  useKeyboardShortcuts();

  const closePanelOnMobile = () => {
    setActivePanel(null);
  };

  return (
    <MobilePanelContext.Provider value={{ activePanel, setActivePanel }}>
      <div className="app">
        <Toolbar />
        <main className="app-content">
          <aside className={`mobile-panel-wrapper left ${activePanel === 'threats' ? 'open' : ''}`} aria-label="Threats panel">
            <ThreatSidebar />
            <button className="mobile-panel-close" onClick={closePanelOnMobile} aria-label="Close threats panel">×</button>
          </aside>
          <DiagramCanvas />
          <aside className={`mobile-panel-wrapper right ${activePanel === 'technologies' ? 'open' : ''}`} aria-label="Components panel">
            <TechPalette />
            <button className="mobile-panel-close" onClick={closePanelOnMobile} aria-label="Close components panel">×</button>
          </aside>
          {activePanel && <div className="mobile-panel-overlay" onClick={closePanelOnMobile} aria-hidden="true" />}
        </main>
        <ToastContainer />
        <ShortcutsModal />
      </div>
    </MobilePanelContext.Provider>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ReactFlowProvider>
        <ThreatModelProvider>
          <AppContent />
        </ThreatModelProvider>
      </ReactFlowProvider>
    </ThemeProvider>
  );
}
