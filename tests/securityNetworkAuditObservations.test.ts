import { expect, test } from 'bun:test';

import {
  createSecurityNetworkAuditObservations,
  createSecurityAuditProfile,
} from '../src/index.js';
import type { SecurityNetworkEvidence } from '../src/index.js';

const profile = createSecurityAuditProfile();

test('adapts complete L3 and L4 evidence with distinct source provenance and no endpoint data', () => {
  const observations = createSecurityNetworkAuditObservations(completeEvidence(), profile);

  expect(observations).toHaveLength(2);
  expect(observations).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        controlId: 'osi3-routing-and-filtering',
        access: 'available',
        applicability: 'applicable',
      }),
      expect.objectContaining({
        controlId: 'osi4-service-exposure',
        access: 'available',
        applicability: 'applicable',
      }),
    ]),
  );
  expect(JSON.stringify(observations)).not.toMatch(/192\.0\.2|example\.com|listener-name/i);
});

test('keeps successful partial sources visible while permission-blocked sources remain unknown', () => {
  const partial = createSecurityNetworkAuditObservations(
    {
      ...completeEvidence(),
      layer3: { ...completeEvidence().layer3, ipv4RoutesAvailability: 'timeout' },
    },
    profile,
  );
  const blocked = createSecurityNetworkAuditObservations(permissionBlockedEvidence(), profile);

  expect(partial[0]).toMatchObject({
    controlId: 'osi3-routing-and-filtering',
    applicability: 'unknown',
    access: 'incomplete',
    evidence: [expect.objectContaining({ id: 'osi3-routing-and-filtering-network-summary' })],
  });
  expect(blocked).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        access: 'permission-blocked',
        applicability: 'unknown',
        evidence: [],
      }),
    ]),
  );
});

/** Construct complete redacted evidence with no raw host values. */
function completeEvidence(): SecurityNetworkEvidence {
  return {
    collectedAt: '2026-11-18T00:00:00.000Z',
    layer3: {
      interfacesAvailability: 'available',
      interfaceCount: 2,
      ipv4AddressCount: 1,
      ipv6AddressCount: 1,
      ipv4RoutesAvailability: 'available',
      ipv4DefaultGatewayObserved: true,
      ipv6RoutesAvailability: 'available',
      ipv6DefaultGatewayObserved: true,
      ipv4ForwardingAvailability: 'available',
      ipv4Forwarding: 'disabled',
      ipv6ForwardingAvailability: 'available',
      ipv6Forwarding: 'disabled',
      vpnServicesAvailability: 'available',
      vpnServiceCount: 0,
      networkExtensionsAvailability: 'available',
      networkExtensionCount: 0,
    },
    packetFilter: {
      status: 'enabled',
      statusAvailability: 'available',
      rulesAvailability: 'available',
      readableRuleCount: 1,
      anchorsAvailability: 'available',
      readableAnchorCount: 1,
      protectionEffect: 'not-established',
    },
    layer4: {
      tcpListenersAvailability: 'available',
      tcpLoopbackListenerCount: 1,
      tcpNonLoopbackListenerCount: 0,
      udpBindingsAvailability: 'available',
      udpLoopbackBindingCount: 0,
      udpNonLoopbackBindingCount: 0,
      processAttribution: 'not-established',
      quic: 'unknown',
    },
    applicationFirewall: {
      globalStateAvailability: 'available',
      globalState: 'enabled',
      stealthModeAvailability: 'available',
      stealthMode: 'enabled',
      protectionEffect: 'not-established',
    },
    protectionLimitations: [],
  };
}

/** Make each required source inaccessible to exercise the fail-closed access state. */
function permissionBlockedEvidence(): SecurityNetworkEvidence {
  const evidence = completeEvidence();
  return {
    ...evidence,
    layer3: Object.fromEntries(
      Object.entries(evidence.layer3).map(([key, value]) =>
        key.endsWith('Availability') ? [key, 'permission-denied'] : [key, value],
      ),
    ) as SecurityNetworkEvidence['layer3'],
    packetFilter: Object.fromEntries(
      Object.entries(evidence.packetFilter).map(([key, value]) =>
        key.endsWith('Availability') ? [key, 'permission-denied'] : [key, value],
      ),
    ) as SecurityNetworkEvidence['packetFilter'],
    layer4: Object.fromEntries(
      Object.entries(evidence.layer4).map(([key, value]) =>
        key.endsWith('Availability') ? [key, 'permission-denied'] : [key, value],
      ),
    ) as SecurityNetworkEvidence['layer4'],
    applicationFirewall: Object.fromEntries(
      Object.entries(evidence.applicationFirewall).map(([key, value]) =>
        key.endsWith('Availability') ? [key, 'permission-denied'] : [key, value],
      ),
    ) as SecurityNetworkEvidence['applicationFirewall'],
  };
}
