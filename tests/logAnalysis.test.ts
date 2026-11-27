import { expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { analyzeLogFileAsync } from '../src/features/log-analysis/adapters/outbound/analyzeLogFileAsync.js';
import { analyzeLogText } from '../src/features/log-analysis/application/analyzeLogText.js';

test('groups repeated structured records, redacts evidence, and leaves multiline text explicitly unparsed', () => {
  const report = analyzeLogText(
    [
      '{"timestamp":"2026-11-26T00:00:00Z","process":"kernel","subsystem":"com.apple.test","level":"Error","eventMessage":"failed at /Users/alice/private.txt id 12345"}',
      '{"timestamp":"2026-11-26T00:01:00Z","process":"kernel","subsystem":"com.apple.test","level":"Error","eventMessage":"failed at /Users/alice/private.txt id 67890"}',
      'continuation without a compact record',
      '2026-11-26 00:02:00 WindowServer <Notice> text contains error but is not an error level',
    ].join('\n'),
    { scope: 'file' },
  );
  expect(report.coverage).toMatchObject({ parsedEvents: 3, unparsedRecords: 1 });
  expect(report.signatures[0]).toMatchObject({
    count: 2,
    severity: 'error',
    representativeEvidence: expect.not.stringContaining('alice'),
  });
  expect(
    report.signatures.find((signature) => signature.processes.includes('WindowServer')),
  ).toMatchObject({ severity: 'notice' });
});

test('does not merge an identical message across Apple severity levels', () => {
  const report = analyzeLogText(
    [
      '{"timestamp":"2026-11-26T00:00:00Z","process":"kernel","level":"Error","eventMessage":"same message"}',
      '{"timestamp":"2026-11-26T00:01:00Z","process":"kernel","level":"Fault","eventMessage":"same message"}',
    ].join('\n'),
    { scope: 'file' },
  );
  expect(report.signatures).toHaveLength(2);
  expect(report.signatures.map((signature) => signature.severity).sort()).toEqual(['error', 'fault']);
});

test('selects only explicit security evidence when requested', () => {
  const report = analyzeLogText(
    [
      '{"timestamp":"2026-11-26T00:00:00Z","process":"kernel","subsystem":"com.apple.security","level":"Error","eventMessage":"TCC denied access"}',
      '{"timestamp":"2026-11-26T00:01:00Z","process":"WindowServer","level":"Error","eventMessage":"unrelated rendering error"}',
    ].join('\n'),
    { scope: 'file', securityFiltered: true },
  );
  expect(report.coverage).toMatchObject({ securityFiltered: true, parsedEvents: 1 });
  expect(report.signatures).toHaveLength(1);
  expect(report.signatures[0]).toMatchObject({ processes: ['kernel'] });
});

test('streams a file across chunk boundaries without retaining raw records', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'osx-log-analysis-'));
  const path = join(directory, 'logs.ndjson');
  await writeFile(
    path,
    [
      '{"timestamp":"2026-11-26T00:00:00Z","process":"kernel","level":"Fault","eventMessage":"repeat 101"}',
      '{"timestamp":"2026-11-26T00:01:00Z","process":"kernel","level":"Fault","eventMessage":"repeat 202"}',
    ].join('\n'),
  );
  try {
    const report = await analyzeLogFileAsync(path, { scope: 'file' });
    expect(report.coverage).toMatchObject({ parsedEvents: 2, unparsedRecords: 0 });
    expect(report.signatures).toHaveLength(1);
    expect(report.signatures[0]).toMatchObject({ count: 2, severity: 'fault' });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
