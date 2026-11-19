import type {
  SecurityAuditControl,
  SecurityAuditObservation,
  SecurityAuditReport,
} from '../../../types/securityAudit.js';
import { collectDefaultSecurityNetworkAsync } from '../../security-network/composition/collectDefaultSecurityNetworkAsync.js';
import { collectMacosSecurityPostureObservationsAsync } from '../../security-posture/composition/collectMacosSecurityPostureObservationsAsync.js';
import { collectMacosHostSecurityObservationsAsync } from '../adapters/outbound/collectMacosHostSecurityObservations.js';
import { collectMacosPhysicalAndLinkObservationsAsync } from '../adapters/outbound/collectMacosPhysicalAndLinkObservations.js';
import { createMacosSecurityAuditCommandRunner } from '../adapters/outbound/createMacosSecurityAuditCommandRunner.js';
import { createSecurityNetworkAuditObservations } from '../application/createSecurityNetworkAuditObservations.js';
import { runSecurityAudit } from '../application/runSecurityAudit.js';
import { createSecurityAuditCatalog } from '../domain/createSecurityAuditCatalog.js';
import { createSecurityAuditProfile } from '../domain/createSecurityAuditProfile.js';

/** Compose all passive macOS collectors for the host-aware CLI pathway without changing the portable default report. */
export async function createMacosSecurityAuditReportAsync(
  input: {
    readonly controlIds?: ReadonlySet<string>;
    readonly collectors?: Partial<SecurityAuditCollectorPorts>;
    readonly now?: () => string;
    readonly collectionTimeoutMilliseconds?: number;
  } = {},
): Promise<SecurityAuditReport> {
  const profile = createSecurityAuditProfile();
  const collectedAt = input.now?.() ?? new Date().toISOString();
  const controls = selectedControls(input.controlIds);
  const runner = (input.collectors?.createRunner ?? createMacosSecurityAuditCommandRunner)();
  const cancellation = createCollectionCancellation(input.collectionTimeoutMilliseconds);
  try {
    return await collectReportAsync(
      controls,
      profile,
      collectedAt,
      runner,
      input.collectors,
      cancellation.signal,
    );
  } finally {
    cancellation.dispose();
  }
}

/** Collect scoped evidence sequentially under one deadline, retaining only work completed before cancellation. */
async function collectReportAsync(
  controls: readonly SecurityAuditControl[],
  profile: ReturnType<typeof createSecurityAuditProfile>,
  collectedAt: string,
  runner: ReturnType<typeof createMacosSecurityAuditCommandRunner>,
  collectors: Partial<SecurityAuditCollectorPorts> | undefined,
  signal: AbortSignal,
): Promise<SecurityAuditReport> {
  if (runner.platform !== 'darwin')
    return runSecurityAudit(controls, profile, [
      ...(await collectPhysicalAndLinkAsync(
        controls,
        runner,
        profile,
        collectedAt,
        collectors,
        signal,
      )),
      ...(await collectHostAsync(controls, runner, profile, collectedAt, collectors, signal)),
    ]);
  const physicalAndLink = await collectPhysicalAndLinkAsync(
    controls,
    runner,
    profile,
    collectedAt,
    collectors,
    signal,
  );
  const networkEvidence = signal.aborted
    ? undefined
    : await collectNetwork(controls, collectors, signal);
  const postureObservations = signal.aborted
    ? []
    : await collectPosture(controls, profile, collectedAt, collectors, signal);
  const host = signal.aborted
    ? []
    : await collectHostAsync(controls, runner, profile, collectedAt, collectors, signal);
  return runSecurityAudit(controls, profile, [
    ...physicalAndLink,
    ...networkObservations(networkEvidence, profile, controls),
    ...postureObservations,
    ...host,
  ]);
}

interface SecurityAuditCollectorPorts {
  readonly createRunner: typeof createMacosSecurityAuditCommandRunner;
  readonly collectPhysicalAndLink: typeof collectMacosPhysicalAndLinkObservationsAsync;
  readonly collectHost: typeof collectMacosHostSecurityObservationsAsync;
  readonly collectNetwork: typeof collectDefaultSecurityNetworkAsync;
  readonly collectPosture: typeof collectMacosSecurityPostureObservationsAsync;
}

/** Select only requested controls before any host collector is allowed to execute. */
function selectedControls(
  controlIds: ReadonlySet<string> | undefined,
): readonly SecurityAuditControl[] {
  return createSecurityAuditCatalog().filter((control) => controlIds?.has(control.id) ?? true);
}

/** Run the L1/L2 adapter only when its chapter is in scope. */
async function collectPhysicalAndLinkAsync(
  controls: readonly SecurityAuditControl[],
  runner: ReturnType<typeof createMacosSecurityAuditCommandRunner>,
  profile: ReturnType<typeof createSecurityAuditProfile>,
  collectedAt: string,
  collectors: Partial<SecurityAuditCollectorPorts> | undefined,
  signal: AbortSignal,
): Promise<readonly SecurityAuditObservation[]> {
  if (!hasLayer(controls, 1) && !hasLayer(controls, 2)) return [];
  return (collectors?.collectPhysicalAndLink ?? collectMacosPhysicalAndLinkObservationsAsync)({
    runner,
    profile,
    collectedAt,
    signal,
  });
}

/** Run only cross-layer source commands whose controls are requested. */
async function collectHostAsync(
  controls: readonly SecurityAuditControl[],
  runner: ReturnType<typeof createMacosSecurityAuditCommandRunner>,
  profile: ReturnType<typeof createSecurityAuditProfile>,
  collectedAt: string,
  collectors: Partial<SecurityAuditCollectorPorts> | undefined,
  signal: AbortSignal,
): Promise<readonly SecurityAuditObservation[]> {
  const controlIds = new Set(controls.map((control) => control.id));
  if (!controls.some((control) => control.primaryCategory.kind === 'cross-layer')) return [];
  return (collectors?.collectHost ?? collectMacosHostSecurityObservationsAsync)({
    runner,
    profile,
    collectedAt,
    controlIds,
    signal,
  });
}

/** Run only requested L3/L4 commands. */
async function collectNetwork(
  controls: readonly SecurityAuditControl[],
  collectors: Partial<SecurityAuditCollectorPorts> | undefined,
  signal: AbortSignal,
) {
  const layers = new Set(([3, 4] as const).filter((layer) => hasLayer(controls, layer)));
  return layers.size === 0
    ? undefined
    : (collectors?.collectNetwork ?? collectDefaultSecurityNetworkAsync)(layers, { signal });
}

/** Run only requested L5/L7 collectors. */
async function collectPosture(
  controls: readonly SecurityAuditControl[],
  profile: ReturnType<typeof createSecurityAuditProfile>,
  collectedAt: string,
  collectors: Partial<SecurityAuditCollectorPorts> | undefined,
  signal: AbortSignal,
): Promise<readonly SecurityAuditObservation[]> {
  const controlIds = new Set(controls.map((control) => control.id));
  if (!([5, 6, 7] as const).some((layer) => hasLayer(controls, layer))) return [];
  return (collectors?.collectPosture ?? collectMacosSecurityPostureObservationsAsync)(
    profile,
    collectedAt,
    { controlIds, signal },
  );
}

/** Create one aggregate deadline which prevents later collectors and cancels every started process. */
function createCollectionCancellation(timeoutMilliseconds = 30_000): {
  readonly signal: AbortSignal;
  readonly dispose: () => void;
} {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMilliseconds);
  return { signal: controller.signal, dispose: () => clearTimeout(timer) };
}

/** Adapt only selected L3/L4 observation records to the scoped engine input. */
function networkObservations(
  evidence: Awaited<ReturnType<typeof collectDefaultSecurityNetworkAsync>> | undefined,
  profile: ReturnType<typeof createSecurityAuditProfile>,
  controls: readonly SecurityAuditControl[],
): readonly SecurityAuditObservation[] {
  if (!evidence) return [];
  const controlIds = new Set(controls.map((control) => control.id));
  return createSecurityNetworkAuditObservations(evidence, profile).filter((observation) =>
    controlIds.has(observation.controlId),
  );
}

/** Match an OSI chapter without allowing collectors to infer an unrelated scope. */
function hasLayer(
  controls: readonly SecurityAuditControl[],
  layer: 1 | 2 | 3 | 4 | 5 | 6 | 7,
): boolean {
  return controls.some(
    (control) => control.primaryCategory.kind === 'osi' && control.primaryCategory.layer === layer,
  );
}
