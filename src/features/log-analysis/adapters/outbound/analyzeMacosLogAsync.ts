import { analyzeLogStreamAsync } from './analyzeLogStreamAsync.js';
import type { LogAnalysisReport } from '../../../../types/logAnalysis.js';

/*** Run macOS's documented log utility and analyze its bounded JSON output without buffering raw logs. */
export async function analyzeMacosLogAsync(
  scope: 'boot' | '24h',
  securityFiltered: boolean,
): Promise<LogAnalysisReport> {
  if (process.platform !== 'darwin') throw new Error('Host log collection is available only on macOS.');
  const process = Bun.spawn({
    cmd: ['log', 'show', '--style', 'json', '--last', scope],
    stdout: 'pipe',
    stderr: 'pipe',
  });
  try {
    const [report] = await Promise.all([
      analyzeLogStreamAsync(process.stdout, {
        scope,
        securityFiltered,
        source: 'macos-log',
      }),
      drainStderrAsync(process.stderr, process),
    ]);
    if ((await process.exited) !== 0) throw new Error('macOS log command did not complete successfully.');
    return report;
  } catch (error) {
    process.kill();
    throw error;
  }
}

/*** Drain diagnostic stderr concurrently with a strict discard-only budget to prevent pipe deadlock. */
async function drainStderrAsync(
  source: ReadableStream<Uint8Array>,
  process: ReturnType<typeof Bun.spawn>,
): Promise<void> {
  const reader = source.getReader();
  const maximumBytes = 1_000_000;
  let bytes = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) return;
      bytes += next.value.byteLength;
      if (bytes > maximumBytes) {
        process.kill();
        await reader.cancel();
        throw new Error('macOS log diagnostic output exceeded the 1 MB safety limit.');
      }
    }
  } finally {
    reader.releaseLock();
  }
}
