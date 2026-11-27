import { access, readdir, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { basename, join } from 'node:path';
import { spawn } from 'node:child_process';

import type {
  DeveloperArtifactInventory,
  DeveloperGitStatus,
  DeveloperInventoryReport,
  DeveloperRootInventory,
  DeveloperTemporaryProject,
  DeveloperToolchain,
  DeveloperWorktree,
} from '../../../../types/developer.js';
import { inspectTreeAsync } from '../../../storage/adapters/outbound/inspectTreeAsync.js';

/*** Collect configured development roots without reading source contents or mutating the host. */
export async function scanDeveloperInventoryAsync(input: {
  readonly roots: readonly string[];
  readonly temporaryRoot?: string;
}): Promise<DeveloperInventoryReport> {
  const roots = await Promise.all(input.roots.map(async (root) => await inspectRootAsync(root)));
  const worktrees = await collectWorktreesAsync(roots);
  const temporaryProjects = await inspectTemporaryProjectsAsync(input.temporaryRoot);
  const toolchains = await Promise.all(['bun', 'node', 'git'].map(async (name) => await versionAsync(name)));
  return {
    roots,
    worktrees,
    temporaryProjects,
    toolchains,
    coverage: [
      'Only explicitly configured roots were inspected.',
      'Git remote publication and worktree evidence are local-only; no fetch was performed.',
      'Temporary paths are candidates only and are never deleted by this report.',
    ],
  };
}

/*** Inspect one root after resolving its identity and access boundary. */
async function inspectRootAsync(root: string): Promise<DeveloperRootInventory> {
  try {
    const path = await realpath(root);
    await access(path, constants.R_OK | constants.X_OK);
    const git = await gitStatusAsync(path);
    return {
      path,
      status: git ? 'available' : 'not-a-repository',
      ...(git ? { git } : {}),
      artifacts: await inspectArtifactsAsync(path),
      ownership: 'configured-root',
      ownershipEvidence: 'explicit command working directory',
    };
  } catch {
    return {
      path: root,
      status: 'inaccessible',
      artifacts: [],
      ownership: 'unknown',
      ownershipEvidence: 'path could not be resolved',
    };
  }
}

/*** Read local Git worktree metadata for accessible configured repositories without contacting a remote. */
async function collectWorktreesAsync(
  roots: readonly DeveloperRootInventory[],
): Promise<readonly DeveloperWorktree[]> {
  const inventories = await Promise.all(
    roots
      .filter((root) => root.status === 'available')
      .map(async (root) => await worktreesForRootAsync(root.path, roots)),
  );
  return inventories.flat();
}

/*** Parse Git's porcelain worktree records into explicit, local safety evidence. */
async function worktreesForRootAsync(
  cwd: string,
  roots: readonly DeveloperRootInventory[],
): Promise<readonly DeveloperWorktree[]> {
  const result = await runCommandAsync('git', ['worktree', 'list', '--porcelain'], cwd);
  if (result.exitCode !== 0) return [];
  const records = result.stdout.trim().split('\n\n').filter((record) => record.length > 0);
  const worktrees = await Promise.all(
    records.map(async (record) => {
      const fields = record.split('\n');
      const path = fields.find((field) => field.startsWith('worktree '))?.slice('worktree '.length);
      if (!path) return null;
      const state = fields.some((field) => field === 'prunable' || field.startsWith('prunable '))
        ? 'prunable'
        : fields.some((field) => field === 'locked' || field.startsWith('locked '))
          ? 'locked'
          : fields.includes('bare')
            ? 'bare'
            : fields.includes('detached')
              ? 'detached'
              : 'attached';
      return {
        path,
        state,
        ownership: roots.some((root) => root.path === path) ? 'matches-configured-root' : 'unknown',
        evidence: 'local git worktree list',
        git: await gitStatusAsync(path),
        activityEvidence: 'unknown',
      };
    }),
  );
  return worktrees.filter((worktree): worktree is DeveloperWorktree => worktree !== null);
}

/*** Count known build artifacts through the existing read-only storage adapter. */
async function inspectArtifactsAsync(root: string): Promise<readonly DeveloperArtifactInventory[]> {
  const definitions = [
    ['node_modules', 'node_modules'],
    ['build', 'dist'],
    ['build', 'build'],
    ['test', 'coverage'],
    ['cache', '.cache'],
  ] as const;
  return await Promise.all(
    definitions.map(async ([kind, name]) => {
      const path = join(root, name);
      const inspection = await inspectTreeAsync(path);
      return {
        kind,
        path,
        allocatedBytes: inspection.allocatedBytes,
        status: inspection.blockers.length === 0 ? 'available' : 'inaccessible',
      };
    }),
  );
}

/*** Read porcelain status and local upstream metadata without contacting remotes. */
async function gitStatusAsync(cwd: string): Promise<DeveloperGitStatus | null> {
  const result = await runCommandAsync('git', ['status', '--porcelain=v1', '--ignored', '--branch'], cwd);
  if (result.exitCode !== 0) return null;
  const lines = result.stdout.split('\n');
  const entries = lines.filter((line) => line.length > 0 && !line.startsWith('##'));
  return {
    dirty: entries.some((line) => !line.startsWith('??') && !line.startsWith('!!')),
    untracked: entries.filter((line) => line.startsWith('??')).length,
    ignored: entries.filter((line) => line.startsWith('!!')).length,
    remotePublication: lines.some((line) => line.startsWith('##') && line.includes('...'))
      ? 'locally-observed'
      : 'unknown',
  };
}

/*** Discover only direct, name-recognized temporary project candidates under an explicit root. */
async function inspectTemporaryProjectsAsync(
  temporaryRoot: string | undefined,
): Promise<readonly DeveloperTemporaryProject[]> {
  if (!temporaryRoot) return [];
  try {
    const paths = await readdir(temporaryRoot, { withFileTypes: true });
    return paths
      .filter((entry) => entry.isDirectory() && basename(entry.name).toLowerCase().includes('codex'))
      .map((entry) => ({ path: join(temporaryRoot, entry.name), owner: 'codex' as const, status: 'candidate' as const }));
  } catch {
    return [{ path: temporaryRoot, owner: 'unknown', status: 'inaccessible' }];
  }
}

/*** Read an installed tool version without making a network request. */
async function versionAsync(name: DeveloperToolchain['name']): Promise<DeveloperToolchain> {
  const result = await runCommandAsync(name, ['--version']);
  return { name, version: result.exitCode === 0 ? result.stdout.trim() || null : null };
}

/*** Execute a fixed local inspection command with no shell interpretation. */
async function runCommandAsync(command: string, args: readonly string[], cwd?: string) {
  return await new Promise<{ readonly exitCode: number; readonly stdout: string }>((resolve) => {
    const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.once('error', () => resolve({ exitCode: 1, stdout: '' }));
    child.once('close', (exitCode) => resolve({ exitCode: exitCode ?? 1, stdout }));
  });
}
