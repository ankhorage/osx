import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { scanDeveloperInventoryAsync } from '../src/features/developer/adapters/outbound/scanDeveloperInventoryAsync.js';

test('reports configured repositories and cache candidates without reading their contents', async () => {
  const root = await mkdtemp(join(tmpdir(), 'osx-developer-'));
  try {
    execFileSync('git', ['init'], { cwd: root });
    execFileSync('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root });
    execFileSync('git', ['config', 'user.name', 'Fixture'], { cwd: root });
    await writeFile(join(root, 'tracked'), 'fixture');
    await writeFile(join(root, '.gitignore'), 'node_modules\n');
    execFileSync('git', ['add', 'tracked', '.gitignore'], { cwd: root });
    execFileSync('git', ['commit', '-m', 'fixture'], { cwd: root });
    const linked = join(root, 'linked-worktree');
    execFileSync('git', ['worktree', 'add', '-b', 'fixture-linked', linked], { cwd: root });
    execFileSync('git', ['worktree', 'lock', '--reason', 'fixture lock', linked], { cwd: root });
    await mkdir(join(root, 'node_modules'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'fixture'), 'cache');
    const report = await scanDeveloperInventoryAsync({ roots: [root] });
    expect(report.roots[0]?.ownership).toBe('configured-root');
    expect(report.roots[0]?.ownershipEvidence).toBe('explicit command working directory');
    expect(report.worktrees).toHaveLength(2);
    expect(report.worktrees.find((worktree) => worktree.path === linked)?.state).toBe('locked');
    expect(report.worktrees.every((worktree) => worktree.git?.untracked === 0)).toBe(true);
    expect(report.worktrees.every((worktree) => worktree.activityEvidence === 'unknown')).toBe(true);
    expect(report.roots[0]?.artifacts.find((artifact) => artifact.kind === 'node_modules')?.status).toBe('available');
    expect(report.coverage).toContain('Only explicitly configured roots were inspected.');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
