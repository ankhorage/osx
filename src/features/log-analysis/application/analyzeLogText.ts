import type { LogAnalysisEvent, LogAnalysisReport, LogAnalysisSignature } from '../../../types/logAnalysis.js';

/*** Normalize compact text or JSON/NDJSON log records into a privacy-safe reusable report. */
export function analyzeLogText(
  input: string,
  options: {
    readonly scope: 'boot' | '24h' | 'file';
    readonly securityFiltered?: boolean;
    readonly source?: 'macos-log' | 'file';
  },
): LogAnalysisReport {
  const records = input.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  const parsed = records.map(parseRecord).filter((event): event is LogAnalysisEvent => event !== null);
  const selected = options.securityFiltered ? parsed.filter(isSecurityEvent) : parsed;
  return reportFor(selected, records.length - parsed.length, options);
}

/*** Select events with explicit security-relevant subsystem or message evidence when requested. */
function isSecurityEvent(event: LogAnalysisEvent): boolean {
  return /\b(amfi|auth(?:entication|orization)?|biometric|filevault|keystore|privacy|sandbox|security|sep|tcc)\b/iu.test(
    `${event.subsystem ?? ''} ${event.message}`,
  );
}

/*** Create a stable aggregate report from already parsed records, including explicit coverage gaps. */
function reportFor(
  events: readonly LogAnalysisEvent[],
  unparsedRecords: number,
  options: {
    readonly scope: 'boot' | '24h' | 'file';
    readonly securityFiltered?: boolean;
    readonly source?: 'macos-log' | 'file';
  },
): LogAnalysisReport {
  const groups = new Map<string, LogAnalysisEvent[]>();
  for (const event of events) {
    const signature = signatureFor(event.message);
    const key = JSON.stringify([signature, event.severity, event.appleLevel]);
    groups.set(key, [...(groups.get(key) ?? []), event]);
  }
  return {
    schemaVersion: 1,
    coverage: {
      scope: options.scope,
      securityFiltered: options.securityFiltered === true,
      source: options.source ?? 'file',
      parsedEvents: events.length,
      unparsedRecords,
    },
    signatures: [...groups.entries()]
    .map(([, members]) => groupFor(signatureFor(members[0]?.message ?? ''), members))
      .sort((left, right) => right.count - left.count || left.signature.localeCompare(right.signature)),
  };
}

/*** Parse one structured log record first, then a deliberately conservative compact-text form. */
function parseRecord(record: string): LogAnalysisEvent | null {
  try {
    const value = JSON.parse(record) as Record<string, unknown>;
    return eventFor(
      stringValue(value.timestamp ?? value.time),
      stringValue(value.process ?? value.processName),
      stringValue(value.subsystem),
      stringValue(value.level ?? value.messageType),
      stringValue(value.eventMessage ?? value.message),
    );
  } catch {
    const match = /^(?<time>\d{4}-\d{2}-\d{2}(?:\s+\S+)?)\s+(?<process>[\w.-]+)(?:\[\d+\])?\s+(?:<(?<level>[^>]+)>\s*)?(?<message>.+)$/u.exec(
      record,
    );
    return match?.groups
      ? eventFor(
          match.groups.time,
          match.groups.process,
          null,
          match.groups.level ?? null,
          match.groups.message,
        )
      : null;
  }
}

/*** Reject incomplete records rather than manufacturing fields from arbitrary message text. */
function eventFor(
  timestamp: string | null,
  process: string | null,
  subsystem: string | null,
  appleLevel: string | null,
  message: string | null,
): LogAnalysisEvent | null {
  if (!message) return null;
  return {
    timestamp,
    process,
    subsystem,
    appleLevel,
    severity: severityFor(appleLevel),
    message: redact(message),
  };
}

/*** Preserve Apple's level independently; message words such as "error" never change severity. */
function severityFor(level: string | null): LogAnalysisEvent['severity'] {
  const normalized = level?.toLowerCase() ?? '';
  if (normalized.includes('fault')) return 'fault';
  if (normalized.includes('error')) return 'error';
  if (normalized.includes('notice')) return 'notice';
  if (normalized.includes('info') || normalized.includes('debug')) return 'info';
  return 'unknown';
}

/*** Remove volatile identifiers before grouping, so repetition is useful without retaining host data. */
function signatureFor(message: string): string {
  return redact(message)
    .replaceAll(/\b\d{2,}\b/gu, '<number>')
    .replaceAll(/[0-9a-f]{8,}/giu, '<identifier>');
}

/*** Redact path-like and URL-like values from the one retained representative evidence string. */
function redact(value: string): string {
  return value
    .replaceAll(/(?:file:\/\/|https?:\/\/)[^\s]+/gu, '<redacted-url>')
    .replaceAll(/(?<!\w)\/(?:[^\s/]+\/)+[^\s]*/gu, '<redacted-path>');
}

/*** Convert one normalized group into serializable evidence without retaining raw record arrays. */
function groupFor(signature: string, members: readonly LogAnalysisEvent[]): LogAnalysisSignature {
  const first = members[0];
  if (!first) throw new Error('Log signature group cannot be empty.');
  const timestamps = members
    .map((member) => member.timestamp)
    .filter((value): value is string => value !== null)
    .sort();
  return {
    signature,
    severity: first.severity,
    appleLevel: first.appleLevel,
    count: members.length,
    processes: unique(members.map((member) => member.process)),
    subsystems: unique(members.map((member) => member.subsystem)),
    firstTimestamp: timestamps[0] ?? null,
    lastTimestamp: timestamps.at(-1) ?? null,
    representativeEvidence: first.message,
  };
}

/*** Return deterministic non-null source labels for report consumers. */
function unique(values: readonly (string | null)[]): readonly string[] {
  return [...new Set(values.filter((value): value is string => value !== null))].sort();
}

/*** Coerce only actual strings from structured records; arrays and objects remain explicitly unparsed. */
function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}
