import { Lock } from 'lucide-react';
import { LIBRARY_VERSION } from '../../data';
import { useState, useEffect, useRef, useCallback } from 'react';
import './AboutModal.css';

interface AboutModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type TabId = 'what-is' | 'how-to' | 'about';

export default function AboutModal({ isOpen, onClose }: AboutModalProps) {
  const [activeTab, setActiveTab] = useState<TabId>('what-is');
  const contentRef = useRef<HTMLDivElement>(null);

  const scrollToSection = useCallback((sectionId: string) => {
    const element = document.getElementById(sectionId);
    const container = contentRef.current;
    if (element && container) {
      const offsetTop = element.offsetTop - container.offsetTop;
      container.scrollTo({ top: offsetTop - 16, behavior: 'smooth' });
    }
  }, []);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
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

  if (!isOpen) return null;

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="about-modal-overlay" onClick={handleOverlayClick}>
      <div className="about-modal">
        <button className="about-modal-close" onClick={onClose} title="Close">
          &times;
        </button>

        <div className="about-modal-tabs">
          <button
            className={`about-modal-tab ${activeTab === 'what-is' ? 'active' : ''}`}
            onClick={() => setActiveTab('what-is')}
          >
            What is Threat Modelling?
          </button>
          <button
            className={`about-modal-tab ${activeTab === 'how-to' ? 'active' : ''}`}
            onClick={() => setActiveTab('how-to')}
          >
            How to Use This Tool
          </button>
          <button
            className={`about-modal-tab ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => setActiveTab('about')}
          >
            About
          </button>
        </div>

        <div className="about-modal-content" ref={contentRef}>
          {activeTab === 'what-is' && (
            <div className="tab-content">
              <h2>What is Threat Modelling?</h2>
              <p>
                Threat modelling is a structured approach to identifying, quantifying, and
                addressing security risks in a system. It helps teams proactively discover
                potential vulnerabilities before they can be exploited.
              </p>

              <h3>Why Threat Model?</h3>
              <p>
                By analysing your system architecture early in the design process, you can:
              </p>
              <ul>
                <li>Identify security weaknesses before they become vulnerabilities</li>
                <li>Prioritize security investments based on risk</li>
                <li>Communicate security concerns across technical and non-technical teams</li>
                <li>Build a shared understanding of system security posture</li>
              </ul>

              <h3>The Process</h3>
              <p>
                A typical threat modelling process involves:
              </p>
              <ul>
                <li><strong>Decompose</strong> - Break down the system into components and data flows</li>
                <li><strong>Identify</strong> - Find potential threats using a structured framework</li>
                <li><strong>Mitigate</strong> - Determine controls and countermeasures</li>
                <li><strong>Validate</strong> - Verify that mitigations are effective</li>
              </ul>

              <h3>Threat Frameworks</h3>
              <p>
                Threat frameworks provide structure through defined terminology and
                process to keep threat models consistent across different systems.
                This tool uses STRIDE and MITRE ATT&CK to categorize and contextualize threats.
              </p>

              <a href="https://en.wikipedia.org/wiki/STRIDE_model" target="_blank" rel="noopener noreferrer">
                <h4>STRIDE</h4>
              </a>
              <p>
                Developed by Microsoft, STRIDE categorizes threats into six types:
              </p>
              <ul>
                <li><strong>Spoofing</strong> - Impersonating something or someone else</li>
                <li><strong>Tampering</strong> - Modifying data or code without authorization</li>
                <li><strong>Repudiation</strong> - Denying having performed an action</li>
                <li><strong>Information Disclosure</strong> - Exposing data to unauthorized parties</li>
                <li><strong>Denial of Service</strong> - Making a system unavailable</li>
                <li><strong>Elevation of Privilege</strong> - Gaining unauthorized capabilities</li>
              </ul>

              <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">
                <h4>MITRE ATT&CK</h4>
              </a>
              <p>
                A knowledge base of adversary tactics and techniques based on real-world observations.
                Each threat in this tool is mapped to relevant ATT&CK techniques, providing context
                on how attackers might exploit vulnerabilities.
              </p>

              <h4>Other Frameworks</h4>
              <p>
                Depending on your use case, you may find these frameworks useful:
              </p>
              <ul>
                <li>
                  <a href="https://owasp.org/www-community/Threat_Modeling" target="_blank" rel="noopener noreferrer">
                    <strong>OWASP Threat Modelling</strong>
                  </a>
                  {' '}- Web application security focused methodology
                </li>
                <li>
                  <a href="https://www.linddun.org/" target="_blank" rel="noopener noreferrer">
                    <strong>LINDDUN</strong>
                  </a>
                  {' '}- Privacy-focused threat modelling framework
                </li>
                <li>
                  <a href="https://threat-modeling.com/pasta-threat-modeling/" target="_blank" rel="noopener noreferrer">
                    <strong>PASTA</strong>
                  </a>
                  {' '}- Process for Attack Simulation and Threat Analysis
                </li>
                <li>
                  <a href="https://smartstatetech.medium.com/threat-modeling-methodology-vast-5c7de64cd924" target="_blank" rel="noopener noreferrer">
                    <strong>VAST</strong>
                  </a>
                  {' '}- Visual, Agile, and Simple Threat modelling
                </li>
              </ul>
            </div>
          )}

          {activeTab === 'how-to' && (
            <div className="tab-content">
              <h2>How to Use This Tool</h2>

              <nav className="toc">
                <div className="toc-title">Contents</div>
                <ul className="toc-list">
                  <li><button onClick={() => scrollToSection('section-technologies')}>Components</button></li>
                  <li><button onClick={() => scrollToSection('section-custom-tech')}>Custom Components</button></li>
                  <li><button onClick={() => scrollToSection('section-connections')}>Connections</button></li>
                  <li><button onClick={() => scrollToSection('section-zones')}>Network Zones</button></li>
                  <li><button onClick={() => scrollToSection('section-threats')}>Viewing Threats</button></li>
                  <li><button onClick={() => scrollToSection('section-risk')}>Understanding Risk Scores</button></li>
                  <li><button onClick={() => scrollToSection('section-settings')}>Threat Model Settings</button></li>
                  <li><button onClick={() => scrollToSection('section-saving')}>Saving Your Work</button></li>
                  <li><button onClick={() => scrollToSection('section-shortcuts')}>Keyboard Shortcuts</button></li>
                </ul>
              </nav>

              <h3 id="section-technologies">Components</h3>
              <p>
                Components are the building blocks for your system. There are 2 types of component:
              </p>
              <ul>
                <li><strong>Actors</strong>: External clients and services which
                interact with your system. These include mobile devices, PCs as well as external
                servers.</li>
                <li><strong>Technologies</strong>: Cloud-based, self-hosted and custom infrastructure
                that make up your system. Each technology has a number of threats associated with
                it that combine with others to produce the threat model.</li>
              </ul>

              <h4>Adding Components</h4>
              <p>
                Browse the components palette on the right to find actors, cloud services and
                infrastructure. You can also create custom components, as described in the
                next section. You can either drag and drop a component onto the
                canvas, or double-click to add it to the center.
              </p>

              <h4>Component Properties</h4>
              <p>
                Click a node on the canvas to open its properties panel. The following
                settings are available:
              </p>
              <ul>
                <li>
                  <strong>Display Name</strong> - Custom label for this instance.
                </li>
                <li>
                  <strong>Data Sensitivity</strong> - Classification of data handled by
                  this component: Public, Internal, Confidential, or Restricted. Higher
                  sensitivity increases threat risk scores.
                </li>
                <li>
                  <strong>Network Zone</strong> - Shows which zone the node belongs to
                  (if any). You can remove the node from its zone here.
                </li>
                <li>
                  <strong>Exclude from Threats</strong> - When enabled, this component
                  and its connections are excluded from threat analysis. Use this for
                  components that are out of scope for your threat model.
                </li>
              </ul>

              <h3 id="section-custom-tech">Custom Components</h3>
              <p>
                If the built-in components don't cover a technology in your architecture,
                you can create your own custom component with a tailored set of threats.
              </p>

              <h4>Creating a Custom Component</h4>
              <p>
                Click the <strong>+ Custom</strong> button at the top of the components
                palette to open the creation modal. You can configure the name, description,
                category and assign relevant threats to it.
              </p>
              <p>
                Once created, custom technologies appear in the <strong>Custom</strong> section
                of the components palette and can be dragged onto the canvas like any
                other component.
              </p>

              <h3 id="section-connections">Connections</h3>
              <p>
                Connections are the data flows between components that represent network
                traffic. Connections also have a number of threats that are assigned
                depending on the technologies they are connecting.
              </p>

              <h4>Adding Connections</h4>
              <p>
                To model data flows between components, simply hover over a node to see
                the connection handles, and drag from one handle to another to create
                the connection.
              </p>
              <p>
                <strong>Tip</strong> - You can also double-click a connection to add a
                label describing the data flow.
              </p>

              <h3 id="section-zones">Network Zones</h3>
              <p>
                Network zones represent boundaries in your architecture, such as
                public-facing networks versus private/internal networks. They help visualize
                network segmentation and can reduce risk scores for components in protected zones.
              </p>
              <p>
                 There are 2 types of zone:
              </p>
              <ul>
                <li><strong>Public</strong> - For internet-facing or untrusted zones</li>
                <li><strong>Private</strong> - For internal, segmented, or protected zones</li>
              </ul>

              <h4>Creating Zones</h4>
              <p>
                To create a zone, first click one of the zone buttons in the Network Zones
                toolbox panel (top-left of canvas), then click and drag on the canvas to
                draw the zone.
              </p>

              <h4>Working with Zones</h4>
              <ul>
                <li><strong>Resize</strong> - Select a zone and drag its corner handles to resize</li>
                <li><strong>Move</strong> - Drag the zone header to reposition it</li>
                <li><strong>Add nodes</strong> - Drag technologies into a zone to assign them</li>
                <li><strong>Properties</strong> - Click a zone to open its properties panel</li>
              </ul>

              <h4>Zone Properties</h4>
              <p>
                Click a zone on the canvas to open its properties panel. The following
                settings are available:
              </p>
              <ul>
                <li>
                  <strong>Zone Type</strong> - Indicates if this zone is Public or
                  Private. You can also change the type here.
                </li>
                <li>
                  <strong>Display Name</strong> - Custom label for this zone.
                </li>
                <li>
                  <strong>Network Type</strong> - Set a tag to indicate the
                  type of network this zone represents - e.g. AWS VPC.
                </li>
                <li>
                  <strong>Risk Reduction</strong> - Reduce the risk score of threats
                  for components in this zone. For more information, see the below
                  section on <em>Private Zone Risk Reduction</em>.
                </li>
              </ul>

              <h4>Private Zone Risk Reduction</h4>
              <p>
                Private network zones can apply a risk reduction to threats affecting
                nodes within them. This reflects the reduced exposure of internal systems
                compared to public-facing ones.
              </p>
              <ul>
                <li>By default, private zones apply a 20% risk reduction, but
                this is customizable in each zone's properties panel.</li>
                <li>For connections between nodes, risk reduction
                only applies when <em>both</em> endpoints are in private zones. The lower
                reduction percentage is used if the two zones have different settings.</li>
              </ul>

              <h3 id="section-threats">Viewing Threats</h3>
              <p>
                The threats panel on the left automatically displays security threats
                relevant to your architecture. Click on a component, connection, or
                zone on the canvas to filter the panel to only threats associated with
                that element. Click on an empty area of the canvas to show all threats
                again.
              </p>
              <p>
                Expand a threat to view its full details including:
              </p>
              <ul>
                <li>STRIDE categories</li>
                <li>MITRE ATT&CK technique mappings</li>
                <li>A checklist of recommended security controls</li>
              </ul>

              <h4>Modifying Threat Severity</h4>
              <p>
                Each threat has a default severity (Low, Medium, High, or Critical)
                that contributes to its risk score. You can override this on a
                per-component basis to better reflect the risk in your specific
                environment.
              </p>
              <p>
                To change a severity, expand a threat and use
                the <strong>Severity</strong> dropdown in the Risk Assessment section.
                A reset button appears next to any overridden severity, allowing you
                to restore the default value.
              </p>

              <h3 id="section-risk">Understanding Risk Scores</h3>
              <p>
                Each threat is assigned a risk score (1-16) based on two core factors,
                with optional modifiers that can increase or decrease the final score.
              </p>

              <h4>Base Risk Calculation</h4>
              <div className="risk-scoring-section">

                <div className="risk-formula">
                  <strong>Base Risk = Threat Severity × Data Sensitivity</strong>
                </div>

                <div className="risk-tables">
                  <div className="risk-table">
                    <h4>Threat Severity</h4>
                    <table>
                      <tbody>
                        <tr><td>Critical</td><td>×4</td></tr>
                        <tr><td>High</td><td>×3</td></tr>
                        <tr><td>Medium</td><td>×2</td></tr>
                        <tr><td>Low</td><td>×1</td></tr>
                      </tbody>
                    </table>
                  </div>

                  <div className="risk-table">
                    <h4>Data Sensitivity</h4>
                    <table>
                      <tbody>
                        <tr><td>Restricted</td><td>×4</td></tr>
                        <tr><td>Confidential</td><td>×3</td></tr>
                        <tr><td>Internal</td><td>×2</td></tr>
                        <tr><td>Public</td><td>×1</td></tr>
                      </tbody>
                    </table>
                  </div>

                  <div className="risk-table">
                    <h4>Risk Levels</h4>
                    <table>
                      <tbody>
                        <tr><td className="risk-critical">Critical</td><td>12-16</td></tr>
                        <tr><td className="risk-high">High</td><td>8-11</td></tr>
                        <tr><td className="risk-medium">Medium</td><td>4-7</td></tr>
                        <tr><td className="risk-low">Low</td><td>1-3</td></tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="risk-level-descriptions">
                  <table>
                    <tbody>
                      <tr>
                        <td className="risk-critical">Critical</td>
                        <td>Requires immediate attention. Could enable full system compromise or massive data breach.</td>
                      </tr>
                      <tr>
                        <td className="risk-high">High</td>
                        <td>Address promptly. Significant impact that could enable unauthorized access or theft of data.</td>
                      </tr>
                      <tr>
                        <td className="risk-medium">Medium</td>
                        <td>Plan remediation. Moderate impact that may expose data or enable further attacks.</td>
                      </tr>
                      <tr>
                        <td className="risk-low">Low</td>
                        <td>Address as resources allow. Limited impact, typically availability-focused.</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <h4>Risk Modifiers</h4>
              <p>
                Several factors can modify the final risk score from its base value:
              </p>

              <div className="risk-modifier-section">
                <div className="risk-modifier">
                  <div className="risk-modifier-header">
                    <span className="escalation-badge-example">↑</span>
                    <strong>Downstream Escalation</strong>
                    <span className="modifier-direction increases">Increases Risk</span>
                  </div>
                  <p>
                    Pathway threats (like unauthorized access or privilege escalation) consider
                    connected downstream systems. If a node connects to a higher-sensitivity
                    system, the effective sensitivity is escalated to match.
                  </p>
                  <p className="modifier-example">
                    Example: A web server (Internal) connected to a database (Restricted) will
                    have its pathway threats calculated using Restricted sensitivity.
                  </p>
                </div>

                <div className="risk-modifier">
                  <div className="risk-modifier-header">
                    <span className="zone-badge-example"><Lock size={12} strokeWidth={2.5} /></span>
                    <strong>Private Network Zones</strong>
                    <span className="modifier-direction decreases">Decreases Risk</span>
                  </div>
                  <p>
                    Nodes placed within private network zones receive a risk reduction
                    (default 20%, configurable per zone). This reflects reduced exposure
                    compared to public-facing systems.
                  </p>
                  <p className="modifier-example">
                    Example: A threat with base score 12 in a private zone with 20% reduction
                    becomes 12 × 0.8 = 9.6, rounded to 10.
                  </p>
                </div>

                <div className="risk-modifier">
                  <div className="risk-modifier-header">
                    <span className="pathway-badge-example">↓</span>
                    <strong>Pathway Mitigations</strong>
                    <span className="modifier-direction decreases">Decreases Risk</span>
                  </div>
                  <p>
                    When protective technologies (WAF, DDoS protection, etc.) are positioned
                    upstream in the data flow, they can mitigate threats on downstream nodes.
                    Depending on settings, threats are either removed entirely or reduced by
                    a configurable percentage.
                  </p>
                  <p className="modifier-example">
                    Example: With WAF protection enabled at 50% reduction, an injection attack
                    with base score 12 becomes 12 × 0.5 = 6.
                  </p>
                </div>
              </div>

              <h3 id="section-settings">Model Settings</h3>
              <p>
                Click the <strong>Settings</strong> button (gear icon) in the toolbar to access
                model-wide configuration options. Settings are saved when you export your model
                and restored when you import it.
              </p>

              <h4>Pathway Mitigations</h4>
              <p>
                Pathway mitigations allow protective technologies positioned upstream in the
                data flow to automatically mitigate threats on downstream nodes. This models
                real-world scenarios where security controls like WAFs and DDoS protection
                reduce risk for systems behind them. You can choose to either reduce the risk
                score, or remove the threat entirely.
              </p>

              <h3 id="section-saving">Saving Your Work</h3>
              <p>
                Use the toolbar buttons to manage your threat model. The Import 
                button loads a previously saved JSON model, while the Export
                button opens a menu with several output formats:
              </p>
              <ul>
                <li>
                  <strong>JSON</strong> - Saves the complete threat model, including nodes,
                  connections, zones, severity overrides and model settings. This is the only
                  format that can be re-imported into the tool, so use it whenever you want to
                  continue working on a model later or share it with someone else using this tool.
                </li>
                <li>
                  <strong>PDF Summary</strong> - A concise PDF containing the architecture
                  diagram and a high-level breakdown of threats grouped by risk level.
                </li>
                <li>
                  <strong>PDF Report</strong> - A comprehensive PDF report with the diagram,
                  full threat details, and recommended controls for every active threat.
                </li>
                <li>
                  <strong>Markdown Report</strong> - The same detailed content as the PDF
                  report, formatted as Markdown.
                </li>
                <li>
                  <strong>threatcl (HCL)</strong> - Exports the model as a{' '}
                  <a href="https://threatcl.github.io/" target="_blank" rel="noopener noreferrer">
                    threatcl
                  </a>
                  {' '}HCL file, for use with the threatcl CLI and other HCL-based threat
                  modelling workflows.
                </li>
              </ul>
              <p>
                Only the JSON format preserves the full model state for re-import, so make sure
                to export a JSON copy if you plan to revisit the model later.
              </p>

              <h3 id="section-shortcuts">Keyboard Shortcuts</h3>
              <p>
                Use these keyboard shortcuts to work more efficiently with your threat model.
                On macOS, use <kbd>⌘</kbd> (Command) instead of <kbd>Ctrl</kbd>.
              </p>

              <h4>Selection</h4>
              <table className="shortcuts-table">
                <tbody>
                  <tr>
                    <td><kbd>Click</kbd></td>
                    <td>Select a single node</td>
                  </tr>
                  <tr>
                    <td><kbd>Shift</kbd> + <kbd>Click</kbd></td>
                    <td>Add/remove node from selection</td>
                  </tr>
                  <tr>
                    <td><kbd>Drag</kbd> on canvas</td>
                    <td>Draw selection box to select multiple nodes</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>A</kbd></td>
                    <td>Select all nodes</td>
                  </tr>
                  <tr>
                    <td><kbd>Escape</kbd></td>
                    <td>Deselect all nodes</td>
                  </tr>
                </tbody>
              </table>

              <h4>Clipboard</h4>
              <table className="shortcuts-table">
                <tbody>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>C</kbd></td>
                    <td>Copy selected nodes (and edges between them)</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>V</kbd></td>
                    <td>Paste copied nodes</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>X</kbd></td>
                    <td>Cut selected nodes</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>D</kbd></td>
                    <td>Duplicate selected nodes</td>
                  </tr>
                </tbody>
              </table>

              <h4>Editing</h4>
              <table className="shortcuts-table">
                <tbody>
                  <tr>
                    <td><kbd>Delete</kbd> / <kbd>Backspace</kbd></td>
                    <td>Delete selected nodes</td>
                  </tr>
                  <tr>
                    <td><kbd>Arrow keys</kbd></td>
                    <td>Nudge selected nodes by 10px</td>
                  </tr>
                  <tr>
                    <td><kbd>Shift</kbd> + <kbd>Arrow keys</kbd></td>
                    <td>Nudge selected nodes by 1px (fine positioning)</td>
                  </tr>
                </tbody>
              </table>

              <h4>History</h4>
              <table className="shortcuts-table">
                <tbody>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>Z</kbd></td>
                    <td>Undo last action</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>Y</kbd></td>
                    <td>Redo last undone action</td>
                  </tr>
                  <tr>
                    <td><kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>Z</kbd></td>
                    <td>Redo (alternative)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'about' && (
            <div className="tab-content">
              <h2>About ThreatModelling.io</h2>
              <p>
                ThreatModelling.io is a tool designed to help security
                professionals, developers, and architects create threat models for their
                cloud and infrastructure systems.
              </p>

              <h3>Contact</h3>
              <p>
                Created and maintained by <a href="https://www.linkedin.com/in/jack-nelson-0000/">
                  <strong>Jack Nelson</strong>
              </a>.
              </p>
              <p>
                Have questions, feedback, or want to contribute? Get in touch:
              </p>

              <div className="contact-links">
                <a href="mailto:threatmodelling.io@gmail.com" className="contact-link">
                  <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
                    <path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/>
                  </svg>
                  threatmodelling.io@gmail.com
                </a>
                <a href="https://x.com/threatmodel_io" target="_blank" rel="noopener noreferrer" className="contact-link">
                  <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
                    <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
                  </svg>
                  @threatmodel_io
                </a>
                <a href="https://www.linkedin.com/in/jack-nelson-0000" target="_blank" rel="noopener noreferrer" className="contact-link">
                  <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                  </svg>
                  LinkedIn
                </a>
              </div>


              <h4>Acknowledgements</h4>
              <ul>
                <li>Cloud provider icons courtesy of their respective owners</li>
                <li>
                  Threat data from{' '}
                  <a href="https://github.com/jib1337/threat-model-library" target="_blank" rel="noopener noreferrer">
                    Threat Model Library
                  </a>{' '}
                  v{LIBRARY_VERSION}, © 2026 Jack Nelson, licensed under{' '}
                  <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">
                    CC BY 4.0
                  </a>
                </li>
                <li>
                  MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
                  © 2026 The MITRE Corporation. This work is reproduced and distributed
                  with the permission of The MITRE Corporation.
                </li>
                <li>Thanks to the community for their feedback, suggestions and support!</li>
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
