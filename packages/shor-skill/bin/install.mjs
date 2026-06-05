#!/usr/bin/env node
/**
 * shor-skill installer
 *
 * Installs the Shor plugin into the local Claude Code plugin registry so that
 * /shor-setup becomes available as a slash-command.
 *
 * Usage:
 *   npx shor-skill          — install
 *   npx shor-skill uninstall — remove
 *   npx shor-skill --dry-run — preview paths, make no changes
 */

import { existsSync, mkdirSync, cpSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PLUGIN_NAME    = 'shor';
const PLUGIN_VERSION = '1.0.0';
const CLAUDE_DIR     = join(homedir(), '.claude');
const MARKETPLACE    = join(CLAUDE_DIR, 'plugins', 'marketplaces', 'local', 'plugins');
const INSTALL_DIR    = join(MARKETPLACE, PLUGIN_NAME);
const REGISTRY_FILE  = join(CLAUDE_DIR, 'plugins', 'installed_plugins.json');
const SOURCE_PLUGIN  = join(__dirname, '..', 'plugin');

const isDryRun   = process.argv.includes('--dry-run');
const isUninstall = process.argv.includes('uninstall');

function log(msg) { console.log(`  ${msg}`); }
function ok(msg)  { console.log(`\x1b[32m✓\x1b[0m ${msg}`); }
function info(msg){ console.log(`\x1b[34mℹ\x1b[0m ${msg}`); }
function warn(msg){ console.log(`\x1b[33m⚠\x1b[0m ${msg}`); }
function fail(msg){ console.error(`\x1b[31m✗\x1b[0m ${msg}`); process.exit(1); }

// ── Registry helpers ─────────────────────────────────────────────────────────

function readRegistry() {
  if (!existsSync(REGISTRY_FILE)) return { version: 2, plugins: {} };
  try { return JSON.parse(readFileSync(REGISTRY_FILE, 'utf8')); }
  catch { return { version: 2, plugins: {} }; }
}

function writeRegistry(data) {
  if (isDryRun) { log(`[dry-run] would write ${REGISTRY_FILE}`); return; }
  writeFileSync(REGISTRY_FILE, JSON.stringify(data, null, 4) + '\n', 'utf8');
}

// ── Install ──────────────────────────────────────────────────────────────────

function install() {
  console.log('\nInstalling Shor Claude Code skill…\n');

  if (!existsSync(join(CLAUDE_DIR, 'plugins'))) {
    fail(
      'Claude Code plugin directory not found at ~/.claude/plugins\n' +
      '  Make sure Claude Code is installed: https://claude.ai/code'
    );
  }

  if (existsSync(INSTALL_DIR)) {
    warn(`Plugin already installed at ${INSTALL_DIR}`);
    info('Re-installing (overwriting)…');
    if (!isDryRun) rmSync(INSTALL_DIR, { recursive: true, force: true });
  }

  log(`Target: ${INSTALL_DIR}`);

  if (!isDryRun) {
    mkdirSync(MARKETPLACE, { recursive: true });
    cpSync(SOURCE_PLUGIN, INSTALL_DIR, { recursive: true });
  } else {
    log(`[dry-run] would copy ${SOURCE_PLUGIN} → ${INSTALL_DIR}`);
  }

  const registry = readRegistry();
  const key = `${PLUGIN_NAME}@local`;
  registry.plugins[key] = [
    {
      scope: 'user',
      installPath: INSTALL_DIR,
      version: PLUGIN_VERSION,
      installedAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
    },
  ];
  writeRegistry(registry);

  console.log('');
  ok('Shor skill installed successfully.');
  console.log('');
  info('The /shor-setup slash-command is now available in Claude Code.');
  info('Restart Claude Code (or reload your session) for the skill to appear.');
  console.log('');
  info('Usage: type /shor-setup in any Claude Code session.');
  console.log('');
}

// ── Uninstall ────────────────────────────────────────────────────────────────

function uninstall() {
  console.log('\nUninstalling Shor Claude Code skill…\n');

  if (!existsSync(INSTALL_DIR)) {
    warn('Plugin is not installed — nothing to remove.');
    return;
  }

  log(`Removing ${INSTALL_DIR}`);
  if (!isDryRun) rmSync(INSTALL_DIR, { recursive: true, force: true });

  const registry = readRegistry();
  const key = `${PLUGIN_NAME}@local`;
  if (registry.plugins[key]) {
    delete registry.plugins[key];
    writeRegistry(registry);
  }

  console.log('');
  ok('Shor skill uninstalled.');
  info('Restart Claude Code for the change to take effect.');
  console.log('');
}

// ── Entry ────────────────────────────────────────────────────────────────────

if (isDryRun) info('Dry-run mode — no files will be written.\n');
isUninstall ? uninstall() : install();
