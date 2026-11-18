import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { filterSecurityAuditReport } from '../../../features/security-audit/application/filterSecurityAuditReport.js';
import { serializeSecurityAuditReport } from '../../../features/security-audit/application/serializeSecurityAuditReport.js';
import { createDefaultSecurityAuditReport } from '../../../features/security-audit/composition/createDefaultSecurityAuditReport.js';
import type { SecurityAuditReport, SecurityAuditResult } from '../../../types/securityAudit.js';

/*** Run the read-only security audit as deterministic JSON or an explicitly skippable guided review. */
export async function audit(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  const options = parseAuditOptions(request.argv);
  if (options === undefined) {
    request.context.writeStderr(
      'Usage: ankh osx security audit [--layer <1..7> | --category <id>] [--non-interactive --json]\n',
    );
    return { exitCode: 1 };
  }
  const report = filterReport(createDefaultSecurityAuditReport(), options);
  if (options.nonInteractive) {
    request.context.writeStdout(serializeSecurityAuditReport(report));
    return { exitCode: 0 };
  }
  const { interaction } = request.context;
  if (!interaction?.interactive) {
    request.context.writeStderr(
      'Interactive audit requires a terminal; use --non-interactive --json.\n',
    );
    return { exitCode: 1 };
  }
  return runGuidedAudit(request, report, interaction);
}

interface AuditOptions {
  readonly nonInteractive: boolean;
  readonly layer?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  readonly category?: string;
}

/** Parse the small fixed flag surface without accepting ambiguous or partial machine-output modes. */
function parseAuditOptions(argv: readonly string[]): AuditOptions | undefined {
  const tokens = [...argv];
  const nonInteractive = tokens.filter((token) => token === '--non-interactive').length === 1;
  const json = tokens.filter((token) => token === '--json').length === 1;
  if (
    tokens.filter((token) => token === '--non-interactive').length > 1 ||
    tokens.filter((token) => token === '--json').length > 1
  )
    return undefined;
  const filter = parseFilter(tokens);
  if (filter === undefined || nonInteractive !== json) return undefined;
  return { nonInteractive, ...filter };
}

/** Parse at most one explicit audit scope and reject duplicate, incomplete, or unknown flag values. */
function parseFilter(tokens: readonly string[]): Omit<AuditOptions, 'nonInteractive'> | undefined {
  const layerValue = getFlagValue(tokens, '--layer');
  const category = getFlagValue(tokens, '--category');
  if (hasInvalidScope(layerValue, category)) return undefined;
  const scopeLayerValue = layerValue ?? undefined;
  const scopeCategory = category ?? undefined;
  const layer = scopeLayerValue === undefined ? undefined : parseLayer(scopeLayerValue);
  if (scopeLayerValue !== undefined && layer === undefined) return undefined;
  if (scopeCategory !== undefined && !isCategory(scopeCategory)) return undefined;
  const expected = [
    ...tokens.filter((token) => token === '--non-interactive' || token === '--json'),
    ...(layer === undefined ? [] : ['--layer', scopeLayerValue ?? '']),
    ...(scopeCategory === undefined ? [] : ['--category', scopeCategory]),
  ];
  if (!hasExactTokens(tokens, expected)) return undefined;
  return {
    ...(layer === undefined ? {} : { layer }),
    ...(scopeCategory === undefined ? {} : { category: scopeCategory }),
  };
}

/** Reject incomplete, repeated, or contradictory scope options before interpreting their values. */
function hasInvalidScope(
  layerValue: string | null | undefined,
  category: string | null | undefined,
): boolean {
  return (
    layerValue === null || category === null || (layerValue !== undefined && category !== undefined)
  );
}

/** Read one flag value and distinguish an absent flag from repeated or incomplete flag syntax. */
function getFlagValue(
  tokens: readonly string[],
  flag: '--layer' | '--category',
): string | null | undefined {
  const indices = tokens.flatMap((token, index) => (token === flag ? [index] : []));
  if (indices.length === 0) return undefined;
  if (indices.length !== 1) return null;
  return tokens[(indices[0] ?? -1) + 1] ?? null;
}

/** Require exactly the permitted flags and values so duplicate or unrelated input cannot be ignored. */
function hasExactTokens(tokens: readonly string[], expected: readonly string[]): boolean {
  return (
    tokens.length === expected.length &&
    expected.every((token) => tokens.filter((item) => item === token).length === 1)
  );
}

/** Accept only OSI layer values represented by the fixed portable catalog. */
function parseLayer(value: string | undefined): 1 | 2 | 3 | 4 | 5 | 6 | 7 | undefined {
  if (
    value === '1' ||
    value === '2' ||
    value === '3' ||
    value === '4' ||
    value === '5' ||
    value === '6' ||
    value === '7'
  )
    return Number(value) as 1 | 2 | 3 | 4 | 5 | 6 | 7;
  return undefined;
}

/** Limit filtering to canonical cross-layer theme identifiers rather than arbitrary control IDs. */
function isCategory(value: string | undefined): value is string {
  return (
    value !== undefined &&
    createDefaultSecurityAuditReport().results.some(
      (result) =>
        result.control.primaryCategory.kind === 'cross-layer' &&
        result.control.primaryCategory.theme === value,
    )
  );
}

/** Apply a requested chapter filter before rendering so coverage remains truthful for the selected scope. */
function filterReport(report: SecurityAuditReport, options: AuditOptions): SecurityAuditReport {
  if (options.layer !== undefined)
    return filterSecurityAuditReport(
      report,
      (result) =>
        result.control.primaryCategory.kind === 'osi' &&
        result.control.primaryCategory.layer === options.layer,
    );
  if (options.category !== undefined)
    return filterSecurityAuditReport(
      report,
      (result) =>
        result.control.primaryCategory.kind === 'cross-layer' &&
        result.control.primaryCategory.theme === options.category,
    );
  return report;
}

/** Render each selected chapter only after confirmation; declining skips it and input loss aborts without persistence. */
async function runGuidedAudit(
  request: AnkhCommandExecutionRequest,
  report: SecurityAuditReport,
  interaction: NonNullable<AnkhCommandExecutionRequest['context']['interaction']>,
): Promise<{ exitCode: number }> {
  const chapters = groupChapters(report.results);
  for (const [index, chapter] of chapters.entries()) {
    request.context.writeStdout(`\n[${index + 1}/${chapters.length}] ${chapter.title}\n`);
    const confirmation = await interaction.confirm(
      `Inspect ${chapter.title}? Declining skips this chapter and saves nothing.`,
    );
    if (confirmation === 'unavailable') {
      request.context.writeStderr(
        'Audit cancelled: interactive input became unavailable; no report was saved.\n',
      );
      return { exitCode: 130 };
    }
    if (confirmation === 'declined') {
      request.context.writeStdout(`Skipped ${chapter.title}; no result is treated as secure.\n`);
      continue;
    }
    for (const result of chapter.results)
      renderResult(result, (text) => request.context.writeStdout(text));
  }
  request.context.writeStdout(
    '\nAudit complete. This read-only run saved no report and does not declare the host secure.\n',
  );
  return { exitCode: 0 };
}

/** Group ordered results into OSI chapters followed by the separate host-security chapter. */
function groupChapters(
  results: readonly SecurityAuditResult[],
): readonly { readonly title: string; readonly results: readonly SecurityAuditResult[] }[] {
  const osi = [1, 2, 3, 4, 5, 6, 7] as const;
  const chapters = osi.flatMap((layer) => {
    const chapterResults = results.filter(
      (result) =>
        result.control.primaryCategory.kind === 'osi' &&
        result.control.primaryCategory.layer === layer,
    );
    return chapterResults.length === 0
      ? []
      : [{ title: `OSI layer ${layer}`, results: chapterResults }];
  });
  const crossLayer = results.filter(
    (result) => result.control.primaryCategory.kind === 'cross-layer',
  );
  return crossLayer.length === 0
    ? chapters
    : [...chapters, { title: 'Cross-layer host security', results: crossLayer }];
}

/** Render evidence state and guidance without collapsing absent coverage into an overall security claim. */
function renderResult(result: SecurityAuditResult, write: (text: string) => void): void {
  write(`\n${result.control.id}: ${result.control.title}\n`);
  write(`${result.control.description}\n`);
  write(
    `Coverage: ${result.coverage}; outcome: ${result.outcome}; severity: ${result.severity}; confidence: ${result.confidence}.\n`,
  );
  write(
    `Evidence: ${result.evidence.length === 0 ? result.baseline.status.replaceAll('-', ' ') : result.evidence.map((item) => item.summary).join('; ')}.\n`,
  );
  write(`Recommendation: ${result.recommendation.manualRemediation}\n`);
}
