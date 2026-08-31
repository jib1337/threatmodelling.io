// Electron main process.

const { app, BrowserWindow, Menu, net, protocol, session, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const DIST = path.join(__dirname, '..', 'dist');
const APP_ORIGIN = 'app://-';
const START_URL = `${APP_ORIGIN}/index.html`;

// Set by npm run electron:dev
const devServerUrl = process.env.VITE_DEV_SERVER_URL || null;

// --- Content Security Policy -------------------------------------------------

const CSP = [
  "default-src 'self'",
  "script-src 'self' https://www.paypalobjects.com",
  "style-src 'self' 'unsafe-inline'",
  // data:/blob: cover html-to-image and jsPDF, which build exports in memory.
  "img-src 'self' data: blob: https://www.paypalobjects.com https://www.paypal.com",
  "font-src 'self' data:",
  "connect-src 'self' data: blob:",
  "worker-src 'self' blob:",
  "frame-src https://www.paypal.com https://www.sandbox.paypal.com",
  "form-action https://www.paypal.com",
  "object-src 'none'",
  "base-uri 'self'",
].join('; ');

const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.xml': 'application/xml; charset=utf-8',
};

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true },
  },
]);

function resolveWithinDist(pathname) {
  const decoded = decodeURIComponent(pathname);
  const resolved = path.resolve(DIST, `.${path.posix.normalize(decoded)}`);
  // path.resolve collapses "..", so anything escaping dist/ is rejected here.
  if (resolved !== DIST && !resolved.startsWith(DIST + path.sep)) return null;
  return resolved;
}

function registerAppProtocol() {
  protocol.handle('app', async request => {
    const { pathname } = new URL(request.url);
    const filePath = resolveWithinDist(pathname === '/' ? '/index.html' : pathname);

    if (!filePath) return new Response('Forbidden', { status: 403 });
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      return new Response('Not found', { status: 404 });
    }

    const response = await net.fetch(pathToFileURL(filePath).toString());
    const headers = new Headers(response.headers);

    const mime = MIME_TYPES[path.extname(filePath).toLowerCase()];
    if (mime) headers.set('Content-Type', mime);
    if (!process.env.TMIO_DISABLE_CSP) headers.set('Content-Security-Policy', CSP);

    return new Response(response.body, { status: response.status, headers });
  });
}

// --- Window state ------------------------------------------------------------

const WINDOW_STATE_FILE = () => path.join(app.getPath('userData'), 'window-state.json');
const DEFAULT_BOUNDS = { width: 1440, height: 900 };

function loadWindowState() {
  try {
    const state = JSON.parse(fs.readFileSync(WINDOW_STATE_FILE(), 'utf8'));
    if (typeof state.width !== 'number' || typeof state.height !== 'number') return DEFAULT_BOUNDS;
    return state;
  } catch {
    return DEFAULT_BOUNDS;
  }
}

function saveWindowState(window) {
  if (window.isDestroyed()) return;
  try {
    const bounds = window.isMaximized() || window.isFullScreen() ? window.getNormalBounds() : window.getBounds();
    fs.writeFileSync(
      WINDOW_STATE_FILE(),
      JSON.stringify({ ...bounds, maximized: window.isMaximized() }),
    );
  } catch {
    // A window position is not worth failing a quit over.
  }
}

// --- Window ------------------------------------------------------------------

function openExternal(url) {
  if (url.startsWith('https://') || url.startsWith('http://') || url.startsWith('mailto:')) {
    shell.openExternal(url);
  }
}

function createWindow() {
  const state = loadWindowState();

  const window = new BrowserWindow({
    ...state,
    minWidth: 900,
    minHeight: 600,
    show: false,
    backgroundColor: '#0d1117',
    ...(process.platform === 'linux'
      ? { icon: path.join(__dirname, '..', 'build', 'icon.png') }
      : {}),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true,
    },
  });

  if (state.maximized) window.maximize();

  window.once('ready-to-show', () => window.show());

  // External links belong in the user's browser
  window.webContents.setWindowOpenHandler(({ url }) => {
    openExternal(url);
    return { action: 'deny' };
  });

  window.webContents.on('will-navigate', (event, url) => {
    const target = new URL(url);
    const current = new URL(window.webContents.getURL());
    if (target.origin === current.origin) return;
    event.preventDefault();
    openExternal(url);
  });

  for (const event of ['resize', 'move', 'close']) {
    window.on(event, () => saveWindowState(window));
  }

  if (devServerUrl) {
    window.loadURL(devServerUrl);
    window.webContents.openDevTools({ mode: 'detach' });
  } else {
    window.loadURL(START_URL);
  }

  return window;
}

// --- Menu --------------------------------------------------------------------

function buildMenu() {
  const isMac = process.platform === 'darwin';
  const editItem = role => ({ role, registerAccelerator: false });

  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: '&File',
      submenu: [isMac ? { role: 'close' } : { role: 'quit' }],
    },
    {
      label: '&Edit',
      submenu: [
        editItem('cut'),
        editItem('copy'),
        editItem('paste'),
        { type: 'separator' },
        editItem('selectAll'),
      ],
    },
    {
      label: '&View',
      submenu: [
        { role: 'reload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    { role: 'windowMenu' },
    {
      role: 'help',
      submenu: [
        {
          label: 'ThreatModelling.io Website',
          click: () => openExternal('https://threatmodelling.io'),
        },
        {
          label: 'Source Code',
          click: () => openExternal('https://github.com/jib1337/threatmodelling.io'),
        },
        {
          label: 'Threat Model Library',
          click: () => openExternal('https://github.com/jib1337/threat-model-library'),
        },
        { type: 'separator' },
        {
          label: 'Report an Issue',
          click: () => openExternal('https://github.com/jib1337/threatmodelling.io/issues'),
        },
      ],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// --- Lifecycle ---------------------------------------------------------------

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    const [window] = BrowserWindow.getAllWindows();
    if (!window) return;
    if (window.isMinimized()) window.restore();
    window.focus();
  });

  app.whenReady().then(() => {
    registerAppProtocol();
    buildMenu();

    session.defaultSession.on('will-download', (_event, item) => {
      item.setSaveDialogOptions({ title: 'Save export', defaultPath: item.getFilename() });
    });

    createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
