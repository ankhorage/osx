import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { analyzeLogFileAsync } from '../../../features/log-analysis/adapters/outbound/analyzeLogFileAsync.js';
import { analyzeMacosLogAsync } from '../../../features/log-analysis/adapters/outbound/analyzeMacosLogAsync.js';
import type { LogAnalysisReport } from '../../../types/logAnalysis.js';

/*** Analyze a bounded local unified-log scope without retaining or transmitting raw host logs. */
export async function analyze(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  const options = parseOptions(request.argv);
  if (!options) {
    request.context.writeStderr(
      'Usage: ankh osx logs analyze --last boot|24h | --file <path> [--security] [--json]\n',
    );
    return { exitCode: 1 };
  }
  try {
    const report = options.file
      ? await analyzeLogFileAsync(options.file, { scope: 'file', securityFiltered: options.security })
      : await analyzeMacosLogAsync(options.scope as 'boot' | '24h', options.security);
    request.context.writeStdout(
      options.json ? `${JSON.stringify(report, null, 2)}\n` : render(report),
    );
    return { exitCode: 0 };
  } catch (error) {
    request.context.writeStderr(
      `Log analysis failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return { exitCode: 1 };
  }
}

interface Options {
  readonly scope: 'boot' | '24h' | 'file';
  readonly file?: string;
  readonly security: boolean;
  readonly json: boolean;
}

/*** Parse a deliberately small mutually exclusive command surface. */
function parseOptions(argv: readonly string[]): Options | null {
  const tokens = [...argv];
  const fileIndex = tokens.indexOf('--file');
  const lastIndex = tokens.indexOf('--last');
  const file = fileIndex >= 0 ? tokens[fileIndex + 1] : undefined;
  const last = lastIndex >= 0 ? tokens[lastIndex + 1] : undefined;
  const expected = [
    ...(file ? ['--file', file] : last === 'boot' || last === '24h' ? ['--last', last] : []),
    ...(tokens.includes('--security') ? ['--security'] : []),
    ...(tokens.includes('--json') ? ['--json'] : []),
  ];
  if (
    (!file && !last) ||
    (file && last) ||
    tokens.length !== expected.length ||
    expected.some((token) => tokens.filter((item) => item === token).length !== 1)
  )
    return null;
  return {
    scope: file ? 'file' : (last as 'boot' | '24h'),
    ...(file ? { file } : {}),
    security: tokens.includes('--security'),
    json: tokens.includes('--json'),
  };
}

/*** Render compact, redacted human output while JSON remains the stable machine boundary. */
function render(report: LogAnalysisReport): string {
  return `${report.signatures
    .map((signature) => `${signature.count} ${signature.severity} ${signature.signature}`)
    .join('\n')}\nUnparsed records: ${report.coverage.unparsedRecords}\n`;
}
