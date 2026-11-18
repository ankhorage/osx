import { expect, test } from 'bun:test';

import { collectSecurityNetworkAsync } from '../src/index.js';
import type { SecurityNetworkCommandResult, SecurityNetworkHost } from '../src/index.js';

test('collects IPv4, IPv6, routing, tunnel, and pf evidence without retaining sensitive network values', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'ifconfig -a': `en0: flags=1\n\tinet 192.0.2.7 netmask 0xffffff00\n\tinet6 2001:db8::7 prefixlen 64\nutun3: flags=1\n\tinet6 fe80::3 prefixlen 64`,
      'netstat -rn -f inet': 'default 192.0.2.1 UGSc\n192.0.2/24 link#4',
      'netstat -rn -f inet6': 'default fe80::1%en0 UGSc\n::1 ::1',
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

test('keeps pf and ALF distinct and reports unreadable pf sources without a protection claim', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'pfctl -s info': result('operation not permitted', 1),
      'pfctl -sr': result('permission denied', 1),
      'pfctl -s Anchors': result('permission denied', 1),
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate':
        'Firewall is enabled. (State = 1)',
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode': 'Stealth mode enabled',
    }),
  );

  expect(evidence.packetFilter).toMatchObject({
    status: 'unknown',
    statusAvailability: 'permission-blocked',
    rulesAvailability: 'permission-blocked',
    anchorsAvailability: 'permission-blocked',
    protectionEffect: 'not-established',
  });
  expect(evidence.applicationFirewall).toEqual({
    globalState: 'enabled',
    stealthMode: 'enabled',
    availability: 'available',
    protectionEffect: 'not-established',
  });
  expect(evidence.protectionLimitations).toContain(
    'pf packet filtering and Apple Application Firewall are separate controls with different scope.',
  );
});

test('classifies loopback and externally reachable bindings without disclosing process metadata', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'lsof -nP -iTCP -sTCP:LISTEN': `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nprivate-server 123 alice 1u IPv4 0x0 0t0 TCP 127.0.0.1:3000 (LISTEN)\nprivate-server 124 alice 1u IPv6 0x0 0t0 TCP *:443 (LISTEN)`,
      'lsof -nP -iUDP':
        'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nprivate-server 125 alice 1u IPv6 0x0 0t0 UDP [::1]:5353\nprivate-server 126 alice 1u IPv4 0x0 0t0 UDP *:5353',
    }),
  );

  expect(evidence.layer4).toEqual({
    tcpLoopbackListenerCount: 1,
    tcpExternallyReachableListenerCount: 1,
    udpLoopbackBindingCount: 1,
    udpExternallyReachableBindingCount: 1,
    processAttribution: 'available',
    quic: 'unknown',
  });
  expect(JSON.stringify(evidence)).not.toContain('private-server');
  expect(JSON.stringify(evidence)).not.toContain('alice');
  expect(JSON.stringify(evidence)).not.toContain('3000');
});

test('fails closed on unavailable socket and ALF sources while keeping QUIC unknown', async () => {
  const evidence = await collectSecurityNetworkAsync(
    host({
      'lsof -nP -iTCP -sTCP:LISTEN': result('lsof: unavailable', 127),
      'lsof -nP -iUDP': result('lsof: unavailable', 127),
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate': result('not found', 127),
      '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode': result('not found', 127),
    }),
  );

  expect(evidence.layer4).toMatchObject({
    tcpExternallyReachableListenerCount: 0,
    udpExternallyReachableBindingCount: 0,
    processAttribution: 'unavailable',
    quic: 'unknown',
  });
  expect(evidence.applicationFirewall).toMatchObject({
    globalState: 'unknown',
    stealthMode: 'unknown',
    availability: 'unavailable',
  });
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

/** Create an explicit local-command result fixture. */
function result(stdout: string, exitCode = 0): SecurityNetworkCommandResult {
  return { exitCode, stdout };
}
