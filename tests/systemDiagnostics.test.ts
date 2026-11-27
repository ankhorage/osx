import { expect, test } from 'bun:test';

import { collectSystemDiagnosticsAsync } from '../src/features/system-diagnostics/application/collectSystemDiagnosticsAsync.js';

test('system health retains unavailable evidence without assigning a health conclusion', async () => {
  const report = await collectSystemDiagnosticsAsync(
    {
      platform: 'darwin',
      runAsync: async (command) =>
        command[0] === 'memory_pressure'
          ? { exitCode: 0, output: 'System-wide memory free percentage: 45%', status: 'available' }
          : { exitCode: 1, output: 'Operation not permitted', status: 'permission-denied' },
    },
    'health',
  );

  expect(report.evidence).toEqual([
    expect.objectContaining({
      name: 'memory pressure',
      output: expect.stringContaining('45%'),
      status: 'available',
    }),
    expect.objectContaining({
      name: 'swap usage',
      note: expect.any(String),
      output: null,
      status: 'permission-denied',
    }),
    expect.objectContaining({
      name: 'root filesystem capacity',
      note: expect.any(String),
      output: null,
      status: 'permission-denied',
    }),
  ]);
});

test('process diagnostics retain only aggregate crash metadata', async () => {
  const report = await collectSystemDiagnosticsAsync(
    {
      platform: 'darwin',
      runAsync: async (command) =>
        command[0] === 'log'
          ? {
              exitCode: 0,
              output:
                '2026-11-27 08:00:00+0000 process[1] crash contains private text\n2026-11-27 09:00:00+0000 process[2] crash',
              status: 'available',
            }
          : { exitCode: 1, output: '', status: 'failed' },
    },
    'processes',
  );

  expect(report.evidence.find(({ name }) => name === 'crash report metadata')).toEqual(
    expect.objectContaining({
      output: JSON.stringify({
        firstObservedAt: '2026-11-27 08:00:00+0000',
        lastObservedAt: '2026-11-27 09:00:00+0000',
        observedEventCount: 2,
      }),
      status: 'available',
    }),
  );
});
