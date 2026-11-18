import { lstat, readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type {
  OrphanedApplicationEvidenceSource,
  OrphanedApplicationHost,
  OrphanedApplicationObservation,
} from '../../../types/orphanedApplications.js';

/** Inventory app-owned user data only when its ownership can be evidenced without mutation. */
export async function scanOrphanedApplicationsAsync(
  home: string,
  host: OrphanedApplicationHost,
): Promise<readonly OrphanedApplicationObservation[]> {
  const [installedSources, receiptSources, processSources, cliSources] = await Promise.all([
    host.installedBundleIds(),
    host.receiptBundleIds(),
    host.activeProcessNames(),
    host.cliNames(),
  ]);
  const inventory = {
    host,
    installed: valuesFor(installedSources),
    receipts: valuesFor(receiptSources),
    active: valuesFor(processSources),
    cli: valuesFor(cliSources),
    unavailableSources: [
      ...installedSources,
      ...receiptSources,
      ...processSources,
      ...cliSources,
    ].filter((source) => !source.available),
    evidenceSources: [...installedSources, ...receiptSources, ...processSources, ...cliSources],
    inventoryComplete: [
      ...installedSources,
      ...receiptSources,
      ...processSources,
      ...cliSources,
    ].every((source) => source.available),
  };
  const roots = ownershipRoots(home);
  const entries = await Promise.all(
    roots.map(async (root) => await rootObservationsAsync(root, inventory)),
  );
  return entries.flat().sort((left, right) => left.path.localeCompare(right.path));
}

interface Inventory {
  readonly host: OrphanedApplicationHost;
  readonly installed: ReadonlySet<string>;
  readonly receipts: ReadonlySet<string>;
  readonly active: ReadonlySet<string>;
  readonly cli: ReadonlySet<string>;
  readonly unavailableSources: readonly OrphanedApplicationEvidenceSource[];
  readonly evidenceSources: readonly OrphanedApplicationEvidenceSource[];
  readonly inventoryComplete: boolean;
}
interface OwnershipRoot {
  readonly path: string;
  readonly kind: 'bundle' | 'group' | 'named' | 'hidden';
}

/** List only non-recursive ownership roots; system and shared roots never become cleanup targets. */
function ownershipRoots(home: string): readonly OwnershipRoot[] {
  const library = join(home, 'Library');
  return [
    { path: join(library, 'Application Support'), kind: 'named' },
    { path: join(library, 'Caches'), kind: 'named' },
    { path: join(library, 'Preferences'), kind: 'named' },
    { path: join(library, 'Containers'), kind: 'bundle' },
    { path: join(library, 'Group Containers'), kind: 'group' },
    { path: join(library, 'Saved Application State'), kind: 'bundle' },
    { path: join(library, 'Logs'), kind: 'named' },
    { path: join(library, 'HTTPStorages'), kind: 'bundle' },
    { path: join(library, 'WebKit'), kind: 'named' },
    { path: join(library, 'Application Scripts'), kind: 'bundle' },
    { path: join(library, 'LaunchAgents'), kind: 'bundle' },
    { path: '/Library/Application Support', kind: 'named' },
    { path: '/Library/LaunchAgents', kind: 'bundle' },
    { path: home, kind: 'hidden' },
  ];
}

/** Derive observations from direct children only, refusing links, special files, and unreadable data. */
async function rootObservationsAsync(
  root: OwnershipRoot,
  inventory: Inventory,
): Promise<readonly OrphanedApplicationObservation[]> {
  try {
    const names = (await readdir(root.path)).filter(
      (name) => root.kind !== 'hidden' || name.startsWith('.'),
    );
    const observations = await Promise.all(
      names.map(
        async (name) => await observationAsync(join(root.path, name), name, root.kind, inventory),
      ),
    );
    return observations.filter(
      (observation): observation is OrphanedApplicationObservation => observation !== null,
    );
  } catch {
    return [];
  }
}

/** Reject uncertain paths and describe only app-specific remnants with explicit protection blockers. */
async function observationAsync(
  path: string,
  name: string,
  kind: OwnershipRoot['kind'],
  inventory: Inventory,
): Promise<OrphanedApplicationObservation | null> {
  try {
    const entry = await lstat(path);
    if (!entry.isDirectory() || entry.isSymbolicLink()) return null;
    const manifestBundleId = kind === 'hidden' ? await manifestBundleIdAsync(path) : null;
    const bundleId = bundleIdFor(name, kind, manifestBundleId);
    if (!bundleId) return null;
    const inspection = await inventory.host.inspectPath(path);
    if (inspection.allocatedBytes === null) return null;
    return observationFor(path, name, kind, bundleId, inspection.allocatedBytes, inventory);
  } catch {
    return null;
  }
}

/*** Assemble one report-only observation after filesystem ownership has been verified. */
function observationFor(
  path: string,
  name: string,
  kind: OwnershipRoot['kind'],
  bundleId: string,
  allocatedBytes: number,
  inventory: Inventory,
): OrphanedApplicationObservation | null {
  const blockers = protectionBlockers(bundleId, name, kind, inventory);
  const missing = inventory.inventoryComplete && !inventory.installed.has(bundleId);
  if (!missing && blockers.length === 0) return null;
  return {
    bundleId,
    label: `Possible remnant for ${bundleId}`,
    path,
    allocatedBytes,
    confidence: 'medium',
    evidence: [
      `${allocatedBytes} allocated bytes`,
      `bundle identifier: ${bundleId}`,
      installationEvidence(missing, inventory.inventoryComplete),
    ],
    evidenceAvailability: inventory.evidenceSources.map(({ source, available }) => ({
      source,
      available,
    })),
    blockers:
      blockers.length > 0 ? blockers : ['uninstalled state is not sufficient proof; report-only'],
  };
}

/*** Describe absence only after every ownership evidence source completed successfully. */
function installationEvidence(missing: boolean, inventoryComplete: boolean): string {
  if (missing) return 'matching installed bundle was not found in complete inventory';
  if (inventoryComplete) return 'matching installed bundle was found';
  return 'application ownership inventory is incomplete';
}

/** Accept exact bundle-id roots and manifest-backed hidden configuration, never arbitrary dotdirectories. */
function bundleIdFor(
  name: string,
  kind: OwnershipRoot['kind'],
  manifestBundleId: string | null,
): string | null {
  if (kind === 'hidden') return manifestBundleId;
  if (/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/u.test(name)) return name.replace(/\.savedState$/u, '');
  return null;
}

/** Retain all situations where data may be shared, active, system-owned, or independently installed. */
function protectionBlockers(
  bundleId: string | null,
  name: string,
  kind: OwnershipRoot['kind'],
  inventory: Inventory,
): readonly string[] {
  const processName = (bundleId ?? name).split('.').at(-1)?.toLowerCase() ?? '';
  return [
    ...(kind === 'group' ? ['shared group container'] : []),
    ...(bundleId?.startsWith('com.apple.') ? ['Apple system identifier'] : []),
    ...(bundleId && inventory.installed.has(bundleId) ? ['application bundle is installed'] : []),
    ...(bundleId && inventory.receipts.has(bundleId) ? ['package receipt exists'] : []),
    ...(processName && inventory.active.has(processName) ? ['matching process is active'] : []),
    ...(processName && inventory.cli.has(processName)
      ? ['matching CLI-only installation exists']
      : []),
    ...inventory.unavailableSources.map((source) => `${source.source} evidence is unavailable`),
  ];
}

/*** Gather all normalized values from the independently available evidence sources. */
function valuesFor(sources: readonly OrphanedApplicationEvidenceSource[]): ReadonlySet<string> {
  return new Set(sources.flatMap((source) => source.values));
}

/** Read an app-owned JSON marker, which is required before hidden configuration may be reported. */
async function manifestBundleIdAsync(path: string): Promise<string | null> {
  for (const filename of ['product.json', 'package.json']) {
    try {
      const value = JSON.parse(await readFile(join(path, filename), 'utf8')) as {
        name?: unknown;
        bundleId?: unknown;
      };
      const identifier = typeof value.bundleId === 'string' ? value.bundleId : value.name;
      if (typeof identifier === 'string' && /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/u.test(identifier))
        return identifier;
    } catch {
      // A missing or malformed marker does not establish ownership.
    }
  }
  return null;
}
