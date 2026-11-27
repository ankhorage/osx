import { createReadStream } from 'node:fs';
import { Readable } from 'node:stream';

import { analyzeLogStreamAsync } from './analyzeLogStreamAsync.js';
import type { LogAnalysisReport } from '../../../../types/logAnalysis.js';

/*** Stream a local exported log file line by line, retaining only normalized aggregate evidence. */
export async function analyzeLogFileAsync(
  path: string,
  options: {
    readonly scope: 'file';
    readonly securityFiltered?: boolean;
  },
): Promise<LogAnalysisReport> {
  return await analyzeLogStreamAsync(Readable.toWeb(createReadStream(path)), {
    ...options,
    source: 'file',
  });
}
