import { execFile } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

import type {
  OrphanedApplicationEvidenceSource,
  OrphanedApplicationHost,
} from '../../../../types/orphanedApplications.js';
import { inspectTreeAsync } from './inspectTreeAsync.js';
import { readApplicationBundleIdAsync } from './readApplicationBundleIdAsync.js';

/** Create the macOS-only read-only inventory boundary for application ownership evidence. */
export function createOrphanedApplicationHost(home: string): OrphanedApplicationHost {
  return {
    async installedBundleIds() {
      return await Promise.all([
        bundleIdsAsync('applications', '/Applications'),
        bundleIdsAsync('user-applications', join(home, 'Applications')),
        bundleIdsAsync('system-applications', '/System/Applications'),
        bundleIdsAsync('core-services-applications', '/System/Library/CoreServices/Applications'),
        bundleIdsAsync('network-applications', '/Network/Applications'),
        spotlightBundleIdsAsync(),
      ]);
    },
    async receiptBundleIds() {
      return [await receiptBundleIdsAsync()];
    },
    async activeProcessNames() {
      return [await activeProcessNamesAsync()];
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
async function receiptBundleIdsAsync(): Promise<OrphanedApplicationEvidenceSource> {
  try {
    const result = await promisify(execFile)('/usr/sbin/pkgutil', ['--pkgs'], {
      timeout: 10_000,
      maxBuffer: 2_000_000,
    });
    return availableEvidence('package-receipts', result.stdout.split('\n'));
  } catch {
    return unavailableEvidence('package-receipts');
  }
}

/** Read process executable names to protect currently active application data. */
async function activeProcessNamesAsync(): Promise<OrphanedApplicationEvidenceSource> {
  try {
    const result = await promisify(execFile)('/bin/ps', ['-axo', 'comm='], {
      timeout: 10_000,
      maxBuffer: 2_000_000,
    });
    return availableEvidence(
      'active-processes',
      result.stdout
        .split('\n')
        .map((value) => value.trim().split('/').pop()?.toLowerCase() ?? '')
        .filter(Boolean),
    );
  } catch {
    return unavailableEvidence('active-processes');
  }
}

/** Read Homebrew cask names to avoid treating a non-bundle installation as orphaned. */
async function cliNamesAsync(): Promise<readonly OrphanedApplicationEvidenceSource[]> {
  return await Promise.all([
    brewCaskNamesAsync('homebrew-apple-silicon', '/opt/homebrew/bin/brew'),
    brewCaskNamesAsync('homebrew-intel', '/usr/local/bin/brew'),
  ]);
}

/*** Read cask names from one architecture-specific Homebrew installation. */
async function brewCaskNamesAsync(
  source: string,
  brew: string,
): Promise<OrphanedApplicationEvidenceSource> {
  try {
    const result = await promisify(execFile)(brew, ['list', '--cask'], {
      timeout: 10_000,
      maxBuffer: 2_000_000,
    });
    return availableEvidence(
      source,
      result.stdout
        .split('\n')
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean),
    );
  } catch {
    return unavailableEvidence(source);
  }
}

/** Query Spotlight when available to include application bundles outside conventional roots. */
async function spotlightBundleIdsAsync(): Promise<OrphanedApplicationEvidenceSource> {
  try {
    const result = await promisify(execFile)(
      '/usr/bin/mdfind',
      ["kMDItemContentType == 'com.apple.application-bundle'"],
      { timeout: 10_000, maxBuffer: 2_000_000 },
    );
    return await bundleEvidenceAsync(
      'spotlight',
      result.stdout
        .split('\n')
        .map((path) => path.trim())
        .filter((path) => path.endsWith('.app')),
    );
  } catch {
    return unavailableEvidence('spotlight');
  }
}

/** Read direct application bundles without descending into arbitrary application-owned content. */
async function bundleIdsAsync(
  source: string,
  root: string,
): Promise<OrphanedApplicationEvidenceSource> {
  try {
    const names = await readdir(root);
    return await bundleEvidenceAsync(
      source,
      names.filter((name) => name.endsWith('.app')).map((name) => join(root, name)),
    );
  } catch (error) {
    return isMissingPath(error) ? availableEvidence(source, []) : unavailableEvidence(source);
  }
}

/*** Preserve successful bundle evidence but mark a source incomplete when any bundle manifest fails. */
async function bundleEvidenceAsync(
  source: string,
  applications: readonly string[],
): Promise<OrphanedApplicationEvidenceSource> {
  const bundleIds = await Promise.all(
    applications.map(async (application) => await readApplicationBundleIdAsync(application)),
  );
  const values = bundleIds.filter((bundleId): bundleId is string => bundleId !== null);
  return bundleIds.some((bundleId) => bundleId === null)
    ? unavailableEvidence(source, values)
    : availableEvidence(source, values);
}

/*** Mark a successfully queried source as available and normalize its immutable values. */
function availableEvidence(
  source: string,
  values: readonly string[],
): OrphanedApplicationEvidenceSource {
  return { source, available: true, values: [...new Set(values)].sort() };
}

/*** Mark one source as unavailable instead of confusing a failed query with no evidence. */
function unavailableEvidence(
  source: string,
  values: readonly string[] = [],
): OrphanedApplicationEvidenceSource {
  return { source, available: false, values: [...new Set(values)].sort() };
}

/*** Treat a conventional optional application root as an empty successful inventory. */
function isMissingPath(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}
