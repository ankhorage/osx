import { afterEach, expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm, symlink, writeFile, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectTreeAsync } from '../src/features/storage/adapters/outbound/inspectTreeAsync.js';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'osx-storage-'));
  roots.push(root);
  return root;
}

test('measures allocated storage for an ordinary tree', async () => {
  const root = await fixture();
  await mkdir(join(root, 'nested'));
  await writeFile(join(root, 'nested', 'data'), 'test');
  const result = await inspectTreeAsync(root);
  expect(result.allocatedBytes).toBeGreaterThan(0);
  expect(result.blockers).toEqual([]);
  expect(result.fingerprint).not.toBeNull();
});

test('rejects symlinks without following their targets', async () => {
  const root = await fixture();
  await symlink('/etc', join(root, 'link'));
  const result = await inspectTreeAsync(root);
  expect(result.allocatedBytes).toBeNull();
  expect(result.blockers).toContain('symbolic link');
});

test('reports hard-linked files as unsafe', async () => {
  const root = await fixture();
  await writeFile(join(root, 'one'), 'test');
  await link(join(root, 'one'), join(root, 'two'));
  expect((await inspectTreeAsync(root)).blockers).toContain('hard-linked file');
});

test('reports missing roots as unavailable', async () => {
  const root = await fixture();
  expect(await inspectTreeAsync(join(root, 'missing'))).toEqual({
    allocatedBytes: null,
    blockers: ['ENOENT'],
    fingerprint: null,
  });
});

test('does not inspect through a linked parent directory', async () => {
  const root = await fixture();
  await mkdir(join(root, 'outside'));
  await mkdir(join(root, 'outside', 'cache'));
  await symlink(join(root, 'outside'), join(root, 'linked'));
  const result = await inspectTreeAsync(join(root, 'linked', 'cache'));
  expect(result.allocatedBytes).toBeNull();
  expect(result.blockers).toContain('symbolic link in path');
});
