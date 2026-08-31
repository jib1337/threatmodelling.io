# ThreatModelling.io

An interactive web application for creating cyber security threat models.

## Getting Started

### Desktop App

The desktop app runs entirely offline. Grab the latest Windows/Linux/Mac binary from the releases.

### Running from Repository

```bash
# Clone the repository
git clone https://github.com/jib1337/threatmodelling.io
cd threatmodelling.io

# Install dependencies
npm install

# Start development server
npm run dev
```

The application will be available at `http://localhost:5173`

The technology and threat catalogue is downloaded automatically on first run from the [threat-model-library](https://github.com/jib1337/threat-model-library) releases.

#### Running Desktop App

```bash
npm run electron:dev      # Vite dev server + Electron shell, with HMR
npm run electron:start    # build, then run the shell against dist/
npm run package           # installers for the current platform, into release/
npm run package:mac       # or :win / :linux
```

#### Build for Production

```bash
npm run build
```

#### Working Against an Unreleased Catalogue

Point the app at a local build of the library:

```bash
# in the library repo
npm run build

# in this repo
LIBRARY_PATH=../threat-model-library/dist/library npm run dev
```

#### Pinning a Catalogue Version

Builds take the latest catalogue release by default. To pin one:

```bash
LIBRARY_VERSION=1.2.0 npm run build
```

or commit a `library.lock.json` recording the version and its checksum, which the
fetch script verifies on download:

```json
{ "version": "1.2.0", "sha256": "9f2c…" }
```

## Usage

1. **Add Technologies**: Add technologies to the canvas to build your model
2. **Create Connections**: Connect your technologies to create context
3. **View Threats**: The left sidebar automatically displays relevant threats based on your diagram
4. **Expand Threats**: Click on a threat to see STRIDE tags, MITRE techniques, and controls
5. **Track Mitigations**: Tick the checkbox next to a control once you've implemented it
6. **Export**: Use the toolbar buttons to export your model in various formats

## Architecture

### Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **React Flow** - Diagram canvas
- **html-to-image** - Image export

### Key Files

| File | Purpose |
|------|---------|
| `src/context/ThreatModelContext.tsx` | Global state management for diagram |
| `src/context/ThemeContext.tsx` | Theme (dark/light) management |
| `src/utils/threatResolver.ts` | Resolves threats based on diagram state |
| `src/data/index.ts` | Data loading and lookup functions |
| `src/components/Diagram/DiagramCanvas.tsx` | Main diagram component |
| `src/components/Sidebar/ThreatSidebar.tsx` | Threat display panel |
| `src/components/TechPalette/TechPalette.tsx` | Technology selection panel |

## Contributing

**Adding or correcting a technology, threat or control?** That belongs in the [threat-model-library](https://github.com/jib1337/threat-model-library) repository, which holds all of the catalogue data and documents its schemas.

For changes to the application itself:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run test:run` and `npm run build` to verify no errors
5. Submit a pull request

## License

The application is licensed under the [MIT License](LICENSE).

**The threat catalogue it bundles is licensed separately.** Builds embed the [Threat Model Library](https://github.com/jib1337/threat-model-library) catalogue,
which is © 2026 Jack Nelson under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), and includes MITRE ATT&CK® content reproduced with the permission of The MITRE Corporation.
