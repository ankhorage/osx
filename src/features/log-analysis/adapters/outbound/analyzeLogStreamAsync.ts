import { analyzeLogText } from '../../application/analyzeLogText.js';
import type { LogAnalysisReport, LogAnalysisSignature } from '../../../../types/logAnalysis.js';

/*** Consume a UTF-8 local-log stream with a hard byte budget and retain only normalized aggregate evidence. */
export async function analyzeLogStreamAsync(
  source: ReadableStream<Uint8Array>,
  options: {
    readonly scope: 'boot' | '24h' | 'file';
    readonly securityFiltered?: boolean;
    readonly source: 'macos-log' | 'file';
    readonly maximumBytes?: number;
  },
): Promise<LogAnalysisReport> {
  const reader = source.getReader();
  const decoder = new TextDecoder();
  const maximumBytes = options.maximumBytes ?? 25_000_000;
  let bytes = 0;
  let pending = '';
  let report = emptyReport(options);
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.byteLength;
      if (bytes > maximumBytes) throw new Error('Log input exceeded the 25 MB analysis limit.');
      const records = `${pending}${decoder.decode(next.value, { stream: true })}`.split(/\r?\n/u);
      pending = records.pop() ?? '';
      report = mergeReports(report, analyzeLogText(records.join('\n'), options));
    }
    const trailing = `${pending}${decoder.decode()}`;
    return trailing.length === 0
      ? report
      : mergeReports(report, analyzeLogText(trailing, options));
  } finally {
    reader.releaseLock();
  }
}

/*** Create the zero-record report used before any source chunk is consumed. */
function emptyReport(options: {
  readonly scope: 'boot' | '24h' | 'file';
  readonly securityFiltered?: boolean;
  readonly source: 'macos-log' | 'file';
}): LogAnalysisReport {
  return {
    schemaVersion: 1,
    coverage: {
      scope: options.scope,
      securityFiltered: options.securityFiltered === true,
      source: options.source,
      parsedEvents: 0,
      unparsedRecords: 0,
    },
    signatures: [],
  };
}

/*** Combine line batches without preserving raw records or changing representative evidence. */
function mergeReports(left: LogAnalysisReport, right: LogAnalysisReport): LogAnalysisReport {
  const signatures = new Map(left.signatures.map((signature) => [signatureKey(signature), signature]));
  for (const signature of right.signatures) {
    const key = signatureKey(signature);
    signatures.set(key, mergeSignature(signatures.get(key), signature));
  }
  return {
    schemaVersion: 1,
    coverage: {
      ...left.coverage,
      parsedEvents: left.coverage.parsedEvents + right.coverage.parsedEvents,
      unparsedRecords: left.coverage.unparsedRecords + right.coverage.unparsedRecords,
    },
    signatures: [...signatures.values()].sort(
      (first, second) => second.count - first.count || first.signature.localeCompare(second.signature),
    ),
  };
}

/*** Prevent stream-batch merging across otherwise identical signatures with distinct severity evidence. */
function signatureKey(signature: LogAnalysisSignature): string {
  return JSON.stringify([signature.signature, signature.severity, signature.appleLevel]);
}

/*** Merge one signature's safe aggregate fields across adjacent stream batches. */
function mergeSignature(
  left: LogAnalysisSignature | undefined,
  right: LogAnalysisSignature,
): LogAnalysisSignature {
  if (!left) return right;
  return {
    ...left,
    count: left.count + right.count,
    processes: unique([...left.processes, ...right.processes]),
    subsystems: unique([...left.subsystems, ...right.subsystems]),
    firstTimestamp: earliest(left.firstTimestamp, right.firstTimestamp),
    lastTimestamp: latest(left.lastTimestamp, right.lastTimestamp),
  };
}

/*** Preserve unknown timestamps while selecting the earliest known timestamp. */
function earliest(left: string | null, right: string | null): string | null {
  if (!left) return right;
  if (!right) return left;
  return left < right ? left : right;
}

/*** Preserve unknown timestamps while selecting the latest known timestamp. */
function latest(left: string | null, right: string | null): string | null {
  if (!left) return right;
  if (!right) return left;
  return left > right ? left : right;
}

/*** Sort aggregate labels to keep streaming and non-streaming report output deterministic. */
function unique(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}
