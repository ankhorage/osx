import { describe, expect, test } from 'bun:test';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import type {
  StorageCandidate,
  StorageDecisions,
  StorageOperations,
} from '../src/types/storage.js';

const candidates: StorageCandidate[] = [
  { id: 'a', label: 'a', estimatedBytes: 12, risk: 'safe', reason: '', fingerprint: '1' },
  { id: 'b', label: 'b', estimatedBytes: 34, risk: 'safe', reason: '', fingerprint: '2' },
  { id: 'c', label: 'c', estimatedBytes: 56, risk: 'report-only', reason: '', fingerprint: '3' },
];

describe('cleanup approval boundary', () => {
  test('collects all decisions and approval before any revalidation or mutation', async () => {
    const events: string[] = [];
    const operations: StorageOperations = {
      scan: async () => candidates,
      revalidate: async (item) => {
        events.push(`validate:${item.id}`);
        return item.id === 'a';
      },
      execute: async (item) => {
        events.push(`execute:${item.id}`);
      },
      availableBytes: async () => 100,
    };
    const decisions: StorageDecisions = {
      select: async (item) => {
        events.push(`select:${item.id}`);
        return true;
      },
      approve: async () => {
        events.push('approve');
        return true;
      },
    };
    const result = await cleanStorageAsync(operations, decisions);
    expect(events).toEqual([
      'select:a',
      'select:b',
      'approve',
      'validate:a',
      'execute:a',
      'validate:b',
    ]);
    expect(result.outcomes.map((outcome) => outcome.status)).toEqual(['cleaned', 'changed']);
  });

  test('refusal and dry run never execute', async () => {
    const operations: StorageOperations = {
      scan: async () => candidates,
      revalidate: async () => {
        throw new Error('unexpected validation');
      },
      execute: async () => {
        throw new Error('unexpected mutation');
      },
      availableBytes: async () => {
        throw new Error('unexpected disk measurement');
      },
    };
    const decisions: StorageDecisions = { select: async () => true, approve: async () => false };
    expect((await cleanStorageAsync(operations, decisions)).approved).toBe(false);
    expect(
      (await cleanStorageAsync(operations, { ...decisions, approve: async () => true }, true))
        .outcomes,
    ).toEqual([]);
  });
});

test('a failed selection aborts without validation or execution', async () => {
  const events: string[] = [];
  const operations: StorageOperations = {
    scan: async () => candidates,
    revalidate: async () => {
      events.push('validate');
      return true;
    },
    execute: async () => {
      events.push('execute');
    },
    availableBytes: async () => 1,
  };
  const decisions: StorageDecisions = {
    select: async (item) => {
      if (item.id === 'b') throw new Error('interrupted');
      return true;
    },
    approve: async () => {
      events.push('approve');
      return true;
    },
  };
  await expect(cleanStorageAsync(operations, decisions)).rejects.toThrow('interrupted');
  expect(events).toEqual([]);
});

test('one failure does not hide the outcome of another approved candidate', async () => {
  const operations: StorageOperations = {
    scan: async () => candidates,
    revalidate: async () => true,
    execute: async (item) => {
      if (item.id === 'a') throw new Error('denied');
    },
    availableBytes: async () => 100,
  };
  const decisions: StorageDecisions = { select: async () => true, approve: async () => true };
  const result = await cleanStorageAsync(operations, decisions);
  expect(result.outcomes).toEqual([
    { id: 'a', status: 'failed', error: 'denied' },
    { id: 'b', status: 'cleaned' },
  ]);
});
