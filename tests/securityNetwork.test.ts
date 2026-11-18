import { expect, test } from 'bun:test';

import { executeSecurityNetworkCommandAsync } from '../src/features/security-network/adapters/outbound/executeSecurityNetworkCommandAsync.js';
import { collectSecurityNetworkAsync } from '../src/index.js';
import type { SecurityNetworkCommandResult, SecurityNetworkHost } from '../src/index.js';

test('collects IPv4, IPv6, routing, tunnel, and pf evidence without retaining sensitive network values', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'ifconfig -a': `en0: flags=1\n\tinet 192.0.2.7\n\tinet6 2001:db8::7\nutun3: flags=1\n\tinet6 fe80::3`,
      'netstat -rn -f inet': 'default 192.0.2.1 UGSc',
      'netstat -rn -f inet6': 'default fe80::1%en0 UGSc',
      'sysctl -n net.inet.ip.forwarding': '0',
      'sysctl -n net.inet6.ip6.forwarding': '1',
      'scutil --nc list': '* (Connected) ABCD VPN\n  (Disconnected) EFGH VPN',
      'systemextensionsctl list': 'ABC com.example.NetworkExtension\nABC com.example.Other',
      'pfctl -s info': 'Status: Enabled for 0 days',
      'pfctl -sr': 'block drop in all\npass out all keep state',
      'pfctl -s Anchors': 'com.example.filter',
    }),
  );

  expect(evidence.layer3).toMatchObject({
    interfacesAvailability: 'available',
    interfaceCount: 2,
    ipv4AddressCount: 1,
    ipv6AddressCount: 2,
    ipv4DefaultGatewayObserved: true,
    ipv6DefaultGatewayObserved: true,
    ipv4Forwarding: 'disabled',
    ipv6Forwarding: 'enabled',
    vpnServiceCount: 2,
    networkExtensionCount: 1,
  });
  expect(evidence.packetFilter).toMatchObject({
    status: 'enabled',
    readableRuleCount: 2,
    readableAnchorCount: 1,
    protectionEffect: 'not-established',
  });
  expect(JSON.stringify(evidence)).not.toContain('192.0.2.7');
  expect(JSON.stringify(evidence)).not.toContain('2001:db8');
  expect(JSON.stringify(evidence)).not.toContain('com.example');
});

test('keeps pf and ALF distinct and reports permission-denied pf sources without a protection claim', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'pfctl -s info': result('operation not permitted', 1, 'permission-denied'),
      'pfctl -sr': result('permission denied', 1, 'permission-denied'),
      'pfctl -s Anchors': result('permission denied', 1, 'permission-denied'),
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate':
        'Firewall is enabled. (State = 1)',
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode': 'Stealth mode enabled',
    }),
  );

  expect(evidence.packetFilter).toMatchObject({
    status: 'unknown',
    statusAvailability: 'permission-denied',
    rulesAvailability: 'permission-denied',
    anchorsAvailability: 'permission-denied',
    readableRuleCount: 'unknown',
    protectionEffect: 'not-established',
  });
  expect(evidence.applicationFirewall).toEqual({
    globalStateAvailability: 'available',
    globalState: 'enabled',
    stealthModeAvailability: 'available',
    stealthMode: 'enabled',
    protectionEffect: 'not-established',
  });
  expect(evidence.protectionLimitations).toContain(
    'pf packet filtering and Apple Application Firewall are separate controls with different scope.',
  );
});

test('classifies IPv4 127/8 and IPv6 ::1 bindings without claiming remote reachability or process attribution', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'lsof -nP -iTCP -sTCP:LISTEN': `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nprivate-server 123 alice TCP 127.0.0.0:3000 (LISTEN)\nprivate-server 124 alice TCP 127.255.255.255:3001 (LISTEN)\nprivate-server 125 alice TCP [::1]:3002 (LISTEN)\nprivate-server 126 alice TCP *:443 (LISTEN)`,
      'lsof -nP -iUDP': `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nprivate-server 127 alice UDP 127.0.0.2:5353\nprivate-server 128 alice UDP [::1]:5354\nprivate-server 129 alice UDP *:5355`,
    }),
  );

  expect(evidence.layer4).toEqual({
    tcpListenersAvailability: 'available',
    tcpLoopbackListenerCount: 3,
    tcpNonLoopbackListenerCount: 1,
    udpBindingsAvailability: 'available',
    udpLoopbackBindingCount: 2,
    udpNonLoopbackBindingCount: 1,
    processAttribution: 'not-established',
    quic: 'unknown',
  });
  expect(JSON.stringify(evidence)).not.toContain('private-server');
  expect(JSON.stringify(evidence)).not.toContain('alice');
  expect(JSON.stringify(evidence)).not.toContain('3000');
});

test('keeps unavailable, partial, and timed-out sources distinct from zero observations', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'ifconfig -a': result('permission denied', 1, 'permission-denied'),
      'netstat -rn -f inet': result('', null, 'timeout'),
      'netstat -rn -f inet6': 'default fe80::1%en0 UGSc',
      'lsof -nP -iTCP -sTCP:LISTEN': result('not found', 127, 'unsupported'),
      'lsof -nP -iUDP': 'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME',
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate': result(
        '',
        null,
        'timeout',
      ),
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode': 'Stealth mode enabled',
    }),
  );

  expect(evidence.layer3).toMatchObject({
    interfacesAvailability: 'permission-denied',
    interfaceCount: 'unknown',
    ipv4AddressCount: 'unknown',
    ipv6AddressCount: 'unknown',
    ipv4RoutesAvailability: 'timeout',
    ipv4DefaultGatewayObserved: 'unknown',
    ipv6RoutesAvailability: 'available',
    ipv6DefaultGatewayObserved: true,
  });
  expect(evidence.layer4).toMatchObject({
    tcpListenersAvailability: 'unsupported',
    tcpLoopbackListenerCount: 'unknown',
    tcpNonLoopbackListenerCount: 'unknown',
    udpBindingsAvailability: 'available',
    udpLoopbackBindingCount: 0,
    udpNonLoopbackBindingCount: 0,
  });
  expect(evidence.applicationFirewall).toEqual({
    globalStateAvailability: 'timeout',
    globalState: 'unknown',
    stealthModeAvailability: 'available',
    stealthMode: 'enabled',
    protectionEffect: 'not-established',
  });
});

test('kills a hanging host command at its timeout', async () => {
  const outcome = await executeSecurityNetworkCommandAsync(['/bin/sh', '-c', 'sleep 2'], {
    timeoutMs: 20,
  });
  expect(outcome).toMatchObject({ exitCode: expect.any(Number), status: 'timeout' });
});

test('kills a noisy host command after the shared output cap', async () => {
  const outcome = await executeSecurityNetworkCommandAsync(
    ['/bin/sh', '-c', 'while :; do printf 1234567890; done'],
    { outputLimitBytes: 128 },
  );
  expect(outcome).toMatchObject({ status: 'output-limited' });
  expect(new TextEncoder().encode(outcome.stdout).byteLength).toBeLessThanOrEqual(128);
});

test('reports an unavailable executable as unsupported instead of a zero observation', async () => {
  const outcome = await executeSecurityNetworkCommandAsync([
    '/definitely-unavailable-security-command',
  ]);
  expect(outcome).toMatchObject({ exitCode: null, status: 'unsupported' });
});

/** Create a deterministic, no-side-effect host fixture for all collector commands. */
function host(
  overrides: Readonly<Record<string, string | SecurityNetworkCommandResult>>,
): SecurityNetworkHost {
  return {
    executeAsync: async (command) => {
      const value = overrides[command.join(' ')] ?? '';
      return typeof value === 'string' ? result(value) : value;
    },
    now: () => '2026-11-18T00:00:00.000Z',
  };
}

/** Create an explicit bounded local-command result fixture. */
function result(
  stdout: string,
  exitCode: number | null = 0,
  status: SecurityNetworkCommandResult['status'] = 'completed',
): SecurityNetworkCommandResult {
  return { exitCode, stdout, status };
}
