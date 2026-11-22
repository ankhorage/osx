import { expect, test } from 'bun:test';

import { audit } from '../src/cli/commands/security/audit.js';
import {
  createDefaultSecurityAuditReport,
  createMacosSecurityAuditReportAsync,
  createSecurityAuditCatalog,
  createSecurityAuditProfile,
  runSecurityAudit,
} from '../src/index.js';

test('guided audit calls injected collection only after confirmation and never after skip or abort', async () => {
  const calls: ReadonlySet<string>[] = [];
  const createReportAsync = async (controlIds: ReadonlySet<string>) => {
    calls.push(controlIds);
    return selectedReport(controlIds);
  };
  const skipped = await audit(request([], ['declined']), { createReportAsync });
  expect(skipped.exitCode).toBe(0);
  expect(calls).toHaveLength(0);

  const aborted = await audit(request([], ['unavailable']), {
    createReportAsync,
  });
  expect(aborted.exitCode).toBe(130);
  expect(calls).toHaveLength(0);

  const confirmed = await audit(request(['--layer', '4'], ['confirmed']), {
    createReportAsync,
  });
  expect(confirmed.exitCode).toBe(0);
  expect(calls).toHaveLength(1);
  expect([...(calls[0] ?? [])]).toEqual(['osi4-service-exposure']);
});

test('a terminal-less guided request does not invoke a report or host collector', async () => {
  let called = false;
  const result = await audit(request([], [], false), {
    createReportAsync: async () => {
      called = true;
      return createDefaultSecurityAuditReport();
    },
  });
  expect(result.exitCode).toBe(1);
  expect(called).toBe(false);
});

test('non-interactive JSON retains validated partial L3 measurements without claiming a pass', async () => {
  const output: string[] = [];
  const result = await audit(
    {
      argv: ['--layer', '3', '--non-interactive', '--json'],
      context: {
        writeStdout: (value) => output.push(value),
        writeStderr: () => undefined,
      },
    },
    { createReportAsync: async () => partialLayer3Report() },
  );
  const report = JSON.parse(output.join('')) as {
    readonly results: readonly {
      readonly outcome: string;
      readonly coverage: string;
      readonly evidence: readonly { readonly facts: readonly { readonly id: string }[] }[];
    }[];
  };

  expect(result.exitCode).toBe(0);
  expect(report.results).toHaveLength(1);
  expect(report.results[0]).toMatchObject({
    outcome: 'unknown',
    coverage: 'incomplete',
    evidence: [{ facts: [{ id: 'ipv4-forwarding-disabled' }] }],
  });
});

test('scoped composition calls only the matching injected collectors and retains actual evidence', async () => {
  const calls: string[] = [];
  const report = await createMacosSecurityAuditReportAsync({
    controlIds: new Set(['cross-layer-network-trust']),
    now: () => '2026-11-18T00:00:00.000Z',
    collectors: {
      createRunner: () => ({
        platform: 'darwin',
        runAsync: async () => ({ kind: 'missing' as const }),
      }),
      collectPhysicalAndLink: async () => {
        calls.push('physical');
        return [];
      },
      collectNetwork: async () => {
        calls.push('network');
        return unavailableNetworkEvidence();
      },
      collectPosture: async () => {
        calls.push('posture');
        return [];
      },
      collectHost: async (input) => {
        calls.push('host');
        return [observation(input.profile, input.collectedAt, 'cross-layer-network-trust')];
      },
    },
  });
  expect(calls).toEqual(['host']);
  expect(report.results).toHaveLength(1);
  expect(report.results[0]).toMatchObject({ outcome: 'unknown', coverage: 'implemented' });
  expect(report.results[0]?.evidence).toHaveLength(1);
});

test('one deadline aborts the started collector, prevents later collectors, and retains completed evidence', async () => {
  const calls: string[] = [];
  let aborts = 0;
  const report = await createMacosSecurityAuditReportAsync({
    controlIds: new Set(['osi1-physical-interface-inventory', 'osi3-routing-and-filtering']),
    now: () => '2026-11-18T00:00:00.000Z',
    collectionTimeoutMilliseconds: 20,
    collectors: {
      createRunner: () => ({
        platform: 'darwin',
        runAsync: async () => ({ kind: 'missing' as const }),
      }),
      collectPhysicalAndLink: async (input) => {
        calls.push('physical');
        return [observation(input.profile, input.collectedAt, 'osi1-physical-interface-inventory')];
      },
      collectNetwork: async (_layers, input) => {
        calls.push('network');
        if (!input?.signal) throw new Error('Composition did not provide a cancellation signal.');
        await abort(input.signal, () => {
          aborts += 1;
        });
        return unavailableNetworkEvidence();
      },
      collectPosture: async () => {
        calls.push('posture');
        return [];
      },
      collectHost: async () => {
        calls.push('host');
        return [];
      },
    },
  });
  expect(aborts).toBe(1);
  expect(calls).toEqual(['physical', 'network']);
  expect(
    report.results.find((result) => result.control.id === 'osi1-physical-interface-inventory'),
  ).toMatchObject({
    outcome: 'unknown',
    evidence: [expect.objectContaining({ id: 'osi1-physical-interface-inventory-evidence' })],
  });
  expect(
    report.results.find((result) => result.control.id === 'osi3-routing-and-filtering'),
  ).toMatchObject({
    outcome: 'unknown',
    coverage: 'incomplete',
  });
});

/** Build a CLI request with deterministic prompts and no ambient host access. */
function request(
  argv: readonly string[],
  confirmations: readonly ('confirmed' | 'declined' | 'unavailable')[],
  interactive = true,
): Parameters<typeof audit>[0] {
  let next = 0;
  return {
    argv,
    context: {
      interaction: {
        interactive,
        confirm: async () => confirmations[next++] ?? 'declined',
      },
      writeStdout: () => undefined,
      writeStderr: () => undefined,
    },
  };
}

/** Select report results without manufacturing evidence at the CLI seam. */
function selectedReport(controlIds: ReadonlySet<string>) {
  const report = createDefaultSecurityAuditReport();
  return {
    ...report,
    results: report.results.filter((result) => controlIds.has(result.control.id)),
  };
}

/** Build engine-validated partial evidence so the CLI test cannot manufacture an evaluated outcome. */
function partialLayer3Report() {
  const profile = createSecurityAuditProfile();
  return runSecurityAudit(createSecurityAuditCatalog(), profile, [
    {
      controlId: 'osi3-routing-and-filtering',
      applicability: 'unknown',
      access: 'incomplete',
      evidence: [
        {
          id: 'layer3-forwarding-summary',
          sourceId: 'macos-network:ipv4-forwarding',
          controlId: 'osi3-routing-and-filtering',
          profileId: profile.id,
          baselineVersion: profile.baseline,
          kind: 'macos-passive-network-summary',
          summary: 'Redacted forwarding metadata was observed locally.',
          collectedAt: '2026-11-18T00:00:00.000Z',
          redacted: true,
          facts: [{ id: 'ipv4-forwarding-disabled', value: true }],
        },
      ],
      sources: [
        {
          id: 'macos-network:ipv4-forwarding',
          state: 'completed',
          evidenceIds: ['layer3-forwarding-summary'],
        },
      ],
    },
  ]);
}

/** Resolve only when the composition-wide abort reaches the injected collector. */
async function abort(signal: AbortSignal | undefined, onAbort: () => void): Promise<void> {
  if (signal?.aborted) {
    onAbort();
    return;
  }
  await new Promise<void>((resolve) =>
    signal?.addEventListener(
      'abort',
      () => {
        onAbort();
        resolve();
      },
      { once: true },
    ),
  );
}

/** Supply a fully redacted observation without a baseline so evidence must stay unknown and visible. */
function observation(
  profile: { readonly id: string; readonly baseline: string },
  collectedAt: string,
  controlId: string,
) {
  return {
    controlId,
    applicability: 'applicable' as const,
    access: 'available' as const,
    evidence: [
      {
        id: `${controlId}-evidence`,
        sourceId: 'test:collector',
        controlId,
        profileId: profile.id,
        baselineVersion: profile.baseline,
        kind: 'test',
        summary: 'A redacted collector completed before the audit deadline.',
        collectedAt,
        redacted: true as const,
        facts: [{ id: 'collector-completed', value: true }],
      },
    ],
    sources: [
      { id: 'test:collector', state: 'completed' as const, evidenceIds: [`${controlId}-evidence`] },
    ],
  };
}

/** Provide unavailable L3/L4 inputs so the deadline test cannot manufacture network facts. */
function unavailableNetworkEvidence() {
  return {
    collectedAt: '2026-11-18T00:00:00.000Z',
    layer3: {
      interfacesAvailability: 'timeout' as const,
      interfaceCount: 'unknown' as const,
      ipv4AddressCount: 'unknown' as const,
      ipv6AddressCount: 'unknown' as const,
      ipv4RoutesAvailability: 'timeout' as const,
      ipv4DefaultGatewayObserved: 'unknown' as const,
      ipv6RoutesAvailability: 'timeout' as const,
      ipv6DefaultGatewayObserved: 'unknown' as const,
      ipv4ForwardingAvailability: 'timeout' as const,
      ipv4Forwarding: 'unknown' as const,
      ipv6ForwardingAvailability: 'timeout' as const,
      ipv6Forwarding: 'unknown' as const,
      vpnServicesAvailability: 'timeout' as const,
      vpnServiceCount: 'unknown' as const,
      networkExtensionsAvailability: 'timeout' as const,
      networkExtensionCount: 'unknown' as const,
    },
    packetFilter: {
      status: 'unknown' as const,
      statusAvailability: 'timeout' as const,
      rulesAvailability: 'timeout' as const,
      readableRuleCount: 'unknown' as const,
      anchorsAvailability: 'timeout' as const,
      readableAnchorCount: 'unknown' as const,
      protectionEffect: 'not-established' as const,
    },
    layer4: {
      tcpListenersAvailability: 'timeout' as const,
      tcpLoopbackListenerCount: 'unknown' as const,
      tcpNonLoopbackListenerCount: 'unknown' as const,
      udpBindingsAvailability: 'timeout' as const,
      udpLoopbackBindingCount: 'unknown' as const,
      udpNonLoopbackBindingCount: 'unknown' as const,
      processAttribution: 'not-established' as const,
      quic: 'unknown' as const,
    },
    applicationFirewall: {
      globalStateAvailability: 'timeout' as const,
      globalState: 'unknown' as const,
      stealthModeAvailability: 'timeout' as const,
      stealthMode: 'unknown' as const,
      protectionEffect: 'not-established' as const,
    },
    protectionLimitations: [],
  };
}
