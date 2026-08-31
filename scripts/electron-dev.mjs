#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const DEV_URL = 'http://localhost:5173';
const READY_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 300;

const children = [];
let shuttingDown = false;

function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const child of children) child.kill();
  process.exit(code);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

async function waitForServer() {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(DEV_URL, { method: 'HEAD' });
      if (response.ok) return true;
    } catch {
      // Not listening yet.
    }
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return false;
}

const vite = spawn('npx', ['vite', '--port', '5173', '--strictPort'], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
});
children.push(vite);
vite.on('exit', code => shutdown(code ?? 0));

if (!(await waitForServer())) {
  console.error(`[electron-dev] Vite did not answer on ${DEV_URL} within 60s.`);
  shutdown(1);
}

const electron = spawn(require('electron'), ['.'], {
  stdio: 'inherit',
  env: { ...process.env, VITE_DEV_SERVER_URL: DEV_URL },
});
children.push(electron);
electron.on('exit', code => shutdown(code ?? 0));
