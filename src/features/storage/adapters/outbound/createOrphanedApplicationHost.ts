import { execFile } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

import type { OrphanedApplicationHost } from '../../../../types/orphanedApplications.js';
import { inspectTreeAsync } from './inspectTreeAsync.js';

/** Create the macOS-only read-only inventory boundary for application ownership evidence. */
export function createOrphanedApplicationHost(home: string): OrphanedApplicationHost {
  return {
    async installedBundleIds() {
      const roots = ['/Applications', join(home, 'Applications')];
      const inventories = await Promise.all([
        ...roots.map(async (root) => await bundleIdsAsync(root)),
        spotlightBundleIdsAsync(),
      ]);
      return [...new Set(inventories.flat())].sort();
    },
    async receiptBundleIds() {
      return await receiptBundleIdsAsync();
    },
    async activeProcessNames() {
      return await activeProcessNamesAsync();
    },
    async cliNames() {
      return await cliNamesAsync();
    },
    async inspectPath(path) {
      return await inspectTreeAsync(path);
    },
  };
}

/** Read package receipts without treating a receipt as proof that an app is uninstalled. */
async function receiptBundleIdsAsync(): Promise<readonly string[]> {
  try {
    const result = await promisify(execFile)('/usr/sbin/pkgutil', ['--pkgs'], {
      timeout: 10_000,
      maxBuffer: 2_000_000,
    });
    return result.stdout
      .split('\n')
      .map((value) => value.trim())
      .filter(Boolean)
      .sort();
  } catch {
    return [];
  }
}

/** Read process executable names to protect currently active application data. */
async function activeProcessNamesAsync(): Promise<readonly string[]> {
  try {
    const result = await promisify(execFile)('/bin/ps', ['-axo', 'comm='], {
      timeout: 10_000,
      maxBuffer: 2_000_000,
    });
    return result.stdout
      .split('\n')
      .map((value) => value.trim().split('/').pop()?.toLowerCase() ?? '')
      .filter(Boolean)
      .sort();
  } catch {
    return [];
  }
}

/** Read Homebrew cask names to avoid treating a non-bundle installation as orphaned. */
async function cliNamesAsync(): Promise<readonly string[]> {
  try {
    const result = await promisify(execFile)('/opt/homebrew/bin/brew', ['list', '--cask'], {
      timeout: 10_000,
      maxBuffer: 2_000_000,
    });
    return result.stdout
      .split('\n')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean)
      .sort();
  } catch {
    return [];
  }
}

/** Query Spotlight when available to include application bundles outside conventional roots. */
async function spotlightBundleIdsAsync(): Promise<readonly string[]> {
  try {
    const result = await promisify(execFile)(
      '/usr/bin/mdfind',
      ["kMDItemContentType == 'com.apple.application-bundle'"],
      { timeout: 10_000, maxBuffer: 2_000_000 },
    );
    return (
      await Promise.all(
        result.stdout
          .split('\n')
          .map((path) => path.trim())
          .filter((path) => path.endsWith('.app'))
          .map(async (path) => await bundleIdAsync(path)),
      )
    ).filter((bundleId): bundleId is string => bundleId !== null);
  } catch {
    return [];
  }
}

/** Read direct application bundles without descending into arbitrary application-owned content. */
async function bundleIdsAsync(root: string): Promise<readonly string[]> {
  try {
    const names = await readdir(root);
    return (
      await Promise.all(
        names
          .filter((name) => name.endsWith('.app'))
          .map(async (name) => await bundleIdAsync(join(root, name))),
      )
    ).filter((bundleId): bundleId is string => bundleId !== null);
  } catch {
    return [];
  }
}

/** Extract a bundle identifier from an application manifest without executing application code. */
async function bundleIdAsync(application: string): Promise<string | null> {
  try {
    const plist = await readFile(join(application, 'Contents', 'Info.plist'), 'utf8');
    const match = /<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/u.exec(plist);
    return match?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}
