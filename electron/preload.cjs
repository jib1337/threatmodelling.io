const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('desktop', {
  isDesktop: true,
  platform: process.platform,
  versions: {
    app: process.env.npm_package_version ?? null,
    electron: process.versions.electron,
    chrome: process.versions.chrome,
  },
});
