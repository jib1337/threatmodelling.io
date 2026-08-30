#!/usr/bin/env node
// Fetches the technology & threat catalogue into src/data/library/, where the
// app imports it from. Runs automatically before dev, build and test.

import { readFileSync, writeFileSync, existsSync, rmSync, mkdirSync, cpSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { tmpdir } from 'os';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = join(ROOT, 'src/data/library');
const LOCK_FILE = join(ROOT, 'library.lock.json');

// An unset workflow input arrives as an empty string, not as undefined.
const env = name => process.env[name]?.trim() || null;

const REPO = env('LIBRARY_REPO') ?? 'jib1337/threat-model-library';
const API = `https://api.github.com/repos/${REPO}`;

const log = msg => console.log(`[library] ${msg}`);
const fail = msg => {
  console.error(`[library] ${msg}`);
  process.exit(1);
};

function installedVersion() {
  const versionFile = join(TARGET, 'VERSION');
  return existsSync(versionFile) ? readFileSync(versionFile, 'utf8').trim() : null;
}

function replaceTarget(populate) {
  const staging = `${TARGET}.staging`;
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });
  try {
    populate(staging);
    rmSync(TARGET, { recursive: true, force: true });
    cpSync(staging, TARGET, { recursive: true });
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

// --- 1. Local directory (developing against an unreleased catalogue) ---

const localPath = env('LIBRARY_PATH');
if (localPath) {
  const source = resolve(ROOT, localPath);
  if (!existsSync(join(source, 'manifest.json'))) {
    fail(
      `LIBRARY_PATH="${localPath}" does not look like a built catalogue ` +
        `(no manifest.json in ${source}).\n` +
        `          Run "npm run build" in the library repository first — the bundle ` +
        `is written to dist/library.`
    );
  }
  replaceTarget(staging => cpSync(source, staging, { recursive: true }));
  log(`linked local catalogue from ${source} (version ${installedVersion() ?? 'unknown'})`);
  process.exit(0);
}

// --- 2-4. Resolve a release version ---

async function fetchJson(url) {
  const headers = { 'user-agent': 'threatmodelling.io', accept: 'application/vnd.github+json' };
  // Lifts the anonymous rate limit in CI, where GITHUB_TOKEN is always present.
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} from ${url}`);
  return res.json();
}

const lock = existsSync(LOCK_FILE) ? JSON.parse(readFileSync(LOCK_FILE, 'utf8')) : null;

const pinnedVersion = env('LIBRARY_VERSION');

let version = pinnedVersion ?? lock?.version ?? null;
let expectedSha = version && version === lock?.version ? lock.sha256 : null;
let source;

if (version) {
  source = pinnedVersion ? 'LIBRARY_VERSION' : 'library.lock.json';
} else {
  source = 'latest release';
  try {
    const release = await fetchJson(`${API}/releases/latest`);
    version = String(release.tag_name).replace(/^v/, '');
  } catch (err) {
    const installed = installedVersion();
    if (installed) {
      log(`could not reach GitHub (${err.message}); keeping installed version ${installed}`);
      process.exit(0);
    }
    fail(
      `could not resolve the latest release of ${REPO}: ${err.message}\n` +
        `          Set LIBRARY_PATH to a local build, or LIBRARY_VERSION to pin a release.`
    );
  }
}

const installed = installedVersion();
if (installed === version) {
  log(`version ${version} already installed (${source})`);
  process.exit(0);
}

// --- Download, verify, extract ---

// Release assets are named after the repository.
const tarball = `${REPO.split('/')[1]}-${version}.tar.gz`;
const base = `https://github.com/${REPO}/releases/download/v${version}`;

log(`fetching ${version} (${source})`);

let archive;
try {
  const res = await fetch(`${base}/${tarball}`, { redirect: 'follow' });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  archive = Buffer.from(await res.arrayBuffer());
} catch (err) {
  fail(`could not download ${tarball}: ${err.message}`);
}

const sha256 = createHash('sha256').update(archive).digest('hex');

if (!expectedSha) {
  // No pinned checksum, so verify against the checksum published with the release.
  try {
    const res = await fetch(`${base}/CHECKSUMS.txt`, { redirect: 'follow' });
    if (res.ok) {
      const line = (await res.text()).split('\n').find(l => l.includes(tarball));
      if (line) expectedSha = line.trim().split(/\s+/)[0];
    }
  } catch {
    // A missing CHECKSUMS.txt is not fatal; the download itself was over TLS.
  }
}

if (expectedSha && expectedSha !== sha256) {
  fail(
    `checksum mismatch for ${tarball}\n` +
      `          expected ${expectedSha}\n` +
      `          received ${sha256}`
  );
}

const tmpArchive = join(tmpdir(), `${tarball}.${process.pid}`);
writeFileSync(tmpArchive, archive);

let extractError = null;
try {
  replaceTarget(staging => {
    try {
      execFileSync('tar', ['-xzf', tmpArchive, '-C', staging], { stdio: 'pipe' });
    } catch (err) {
      if (!existsSync(join(staging, 'manifest.json'))) {
        throw new Error(err.stderr?.toString().trim() || err.message);
      }
      log(`note: ${tarball} contains duplicate entries; extracted bundle is intact`);
    }
  });
} catch (err) {
  extractError = err;
} finally {
  rmSync(tmpArchive, { force: true });
}

if (extractError) fail(`could not extract ${tarball}: ${extractError.message}`);

if (!existsSync(join(TARGET, 'manifest.json'))) {
  fail(`${tarball} did not contain a manifest.json — the bundle looks malformed`);
}

const manifest = JSON.parse(readFileSync(join(TARGET, 'manifest.json'), 'utf8'));
log(
  `installed ${manifest.libraryVersion}: ` +
    `${manifest.providers.reduce((n, p) => n + p.serviceCount, 0)} technologies, ` +
    `${manifest.threatCount} threats` +
    (expectedSha ? ` (sha256 verified)` : '')
);
