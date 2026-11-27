import type {
  SecurityNetworkEvidenceAvailability,
  SecurityNetworkLayer3Evidence,
  SecurityNetworkObserved,
  SecurityNetworkPacketFilterEvidence,
  SecurityNetworkSetting,
} from '../../../types/securityNetwork.js';
import type { SecurityNetworkCommandResult } from '../ports/securityNetworkHost.js';

/*** Convert raw, local Layer 3 command output into address-free routing and packet-filter evidence. */
export function createLayer3Evidence(
  interfaces: SecurityNetworkCommandResult,
  ipv4Routes: SecurityNetworkCommandResult,
  ipv6Routes: SecurityNetworkCommandResult,
  ipv4Forwarding: SecurityNetworkCommandResult,
  ipv6Forwarding: SecurityNetworkCommandResult,
  dns: SecurityNetworkCommandResult,
  proxy: SecurityNetworkCommandResult,
  vpnServices: SecurityNetworkCommandResult,
  networkExtensions: SecurityNetworkCommandResult,
  packetFilterStatus: SecurityNetworkCommandResult,
  packetFilterRules: SecurityNetworkCommandResult,
  packetFilterAnchors: SecurityNetworkCommandResult,
): {
  readonly layer3: SecurityNetworkLayer3Evidence;
  readonly packetFilter: SecurityNetworkPacketFilterEvidence;
} {
  return {
    layer3: createLayer3Measurements(
      interfaces,
      ipv4Routes,
      ipv6Routes,
      ipv4Forwarding,
      ipv6Forwarding,
      dns,
      proxy,
      vpnServices,
      networkExtensions,
    ),
    packetFilter: {
      status: parsePacketFilterStatus(packetFilterStatus),
      statusAvailability: availability(packetFilterStatus),
      rulesAvailability: availability(packetFilterRules),
      readableRuleCount: measured(packetFilterRules, (result) => countReadableLines(result.stdout)),
      anchorsAvailability: availability(packetFilterAnchors),
      readableAnchorCount: measured(packetFilterAnchors, (result) =>
        countReadableLines(result.stdout),
      ),
      protectionEffect: 'not-established',
    },
  };
}

/** Assemble only successful Layer 3 measurements, keeping each unavailable source separately visible. */
function createLayer3Measurements(
  interfaces: SecurityNetworkCommandResult,
  ipv4Routes: SecurityNetworkCommandResult,
  ipv6Routes: SecurityNetworkCommandResult,
  ipv4Forwarding: SecurityNetworkCommandResult,
  ipv6Forwarding: SecurityNetworkCommandResult,
  dns: SecurityNetworkCommandResult,
  proxy: SecurityNetworkCommandResult,
  vpnServices: SecurityNetworkCommandResult,
  networkExtensions: SecurityNetworkCommandResult,
): SecurityNetworkLayer3Evidence {
  return {
    interfacesAvailability: availability(interfaces),
    interfaceCount: measured(interfaces, (result) => countMatches(result.stdout, /^[^\s][^:]*:/gm)),
    ipv4AddressCount: measured(interfaces, (result) =>
      countMatches(result.stdout, /^\s*inet\s+/gm),
    ),
    ipv6AddressCount: measured(interfaces, (result) =>
      countMatches(result.stdout, /^\s*inet6\s+/gm),
    ),
    ipv4RoutesAvailability: availability(ipv4Routes),
    ipv4DefaultGatewayObserved: measured(ipv4Routes, (result) => hasDefaultRoute(result.stdout)),
    ipv6RoutesAvailability: availability(ipv6Routes),
    ipv6DefaultGatewayObserved: measured(ipv6Routes, (result) => hasDefaultRoute(result.stdout)),
    ipv4ForwardingAvailability: availability(ipv4Forwarding),
    ipv4Forwarding: parseForwarding(ipv4Forwarding),
    ipv6ForwardingAvailability: availability(ipv6Forwarding),
    ipv6Forwarding: parseForwarding(ipv6Forwarding),
    dnsAvailability: availability(dns),
    dnsResolverCount: measured(dns, (result) =>
      countMatches(result.stdout, /^resolver #\d+/gim),
    ),
    proxyAvailability: availability(proxy),
    webProxy: parseProxySetting(proxy, 'HTTPEnable'),
    secureWebProxy: parseProxySetting(proxy, 'HTTPSEnable'),
    vpnServicesAvailability: availability(vpnServices),
    vpnServiceCount: measured(vpnServices, (result) => countServiceLines(result.stdout)),
    networkExtensionsAvailability: availability(networkExtensions),
    networkExtensionCount: measured(networkExtensions, (result) =>
      countNetworkExtensions(result.stdout),
    ),
  };
}

/** Preserve the actual zero measurement only when the source completed successfully. */
function measured<Value>(
  result: SecurityNetworkCommandResult,
  measurement: (result: SecurityNetworkCommandResult) => Value,
): SecurityNetworkObserved<Value> {
  return result.status === 'completed' ? measurement(result) : 'unknown';
}

/** Count an address-free pattern without retaining interface identities or address values. */
function countMatches(output: string, pattern: RegExp): number {
  return output.match(pattern)?.length ?? 0;
}

/** Detect the route-table default marker without exposing a gateway or route. */
function hasDefaultRoute(output: string): boolean {
  return /^default\s+/m.test(output);
}

/** Interpret the public sysctl forwarding flag conservatively. */
function parseForwarding(result: SecurityNetworkCommandResult): SecurityNetworkSetting {
  if (result.status !== 'completed') return 'unknown';
  if (result.stdout.trim() === '1') return 'enabled';
  if (result.stdout.trim() === '0') return 'disabled';
  return 'unknown';
}

/*** Interpret only explicit proxy enable flags, without retaining proxy hostnames or ports. */
function parseProxySetting(
  result: SecurityNetworkCommandResult,
  key: 'HTTPEnable' | 'HTTPSEnable',
): SecurityNetworkSetting {
  if (result.status !== 'completed') return 'unknown';
  if (new RegExp(`${key}\\s*:\\s*1\\b`, 'i').test(result.stdout)) return 'enabled';
  if (new RegExp(`${key}\\s*:\\s*0\\b`, 'i').test(result.stdout)) return 'disabled';
  return 'unknown';
}

/** Count configured VPN services while omitting their names and connection identifiers. */
function countServiceLines(output: string): number {
  return output.split('\n').filter((line) => /^\*?\s*\([^)]*\)/.test(line)).length;
}

/** Count only the generic NetworkExtension marker, never bundle or team identifiers. */
function countNetworkExtensions(output: string): number {
  return output.split('\n').filter((line) => /networkextension/i.test(line)).length;
}

/** Derive a privacy-safe source availability state from the bounded local command outcome. */
function availability(result: SecurityNetworkCommandResult): SecurityNetworkEvidenceAvailability {
  return result.status === 'completed' ? 'available' : result.status;
}

/** Read the pf enabled marker without treating its existence as firewall effectiveness. */
function parsePacketFilterStatus(result: SecurityNetworkCommandResult): SecurityNetworkSetting {
  if (result.status !== 'completed') return 'unknown';
  if (/^status:\s+enabled\b/im.test(result.stdout)) return 'enabled';
  if (/^status:\s+disabled\b/im.test(result.stdout)) return 'disabled';
  return 'unknown';
}

/** Count readable non-comment pf records without returning rule text or anchor names. */
function countReadableLines(output: string): number {
  return output.split('\n').filter((line) => line.trim() !== '' && !line.trim().startsWith('#'))
    .length;
}
