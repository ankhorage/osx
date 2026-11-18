import type {
  SecurityNetworkApplicationFirewallEvidence,
  SecurityNetworkEvidenceAvailability,
  SecurityNetworkLayer4Evidence,
  SecurityNetworkSetting,
} from '../../../types/securityNetwork.js';
import type { SecurityNetworkCommandResult } from '../ports/securityNetworkHost.js';

/*** Convert local socket and Apple Application Firewall output into redacted Layer 4 evidence. */
export function createLayer4Evidence(
  tcpListeners: SecurityNetworkCommandResult,
  udpBindings: SecurityNetworkCommandResult,
  applicationFirewall: SecurityNetworkCommandResult,
  stealthMode: SecurityNetworkCommandResult,
): {
  readonly layer4: SecurityNetworkLayer4Evidence;
  readonly applicationFirewall: SecurityNetworkApplicationFirewallEvidence;
} {
  const tcp = countBindings(tcpListeners, 'TCP');
  const udp = countBindings(udpBindings, 'UDP');

  return {
    layer4: {
      tcpLoopbackListenerCount: tcp.loopback,
      tcpExternallyReachableListenerCount: tcp.external,
      udpLoopbackBindingCount: udp.loopback,
      udpExternallyReachableBindingCount: udp.external,
      processAttribution: sourceAvailability(tcpListeners, udpBindings),
      quic: 'unknown',
    },
    applicationFirewall: {
      globalState: parseApplicationFirewallSetting(applicationFirewall),
      stealthMode: parseApplicationFirewallSetting(stealthMode),
      availability: sourceAvailability(applicationFirewall, stealthMode),
      protectionEffect: 'not-established',
    },
  };
}

/** Classify socket bindings without retaining endpoints, ports, process names, PIDs, users, or paths. */
function countBindings(
  result: SecurityNetworkCommandResult,
  protocol: 'TCP' | 'UDP',
): { readonly loopback: number; readonly external: number } {
  if (result.exitCode !== 0) return { loopback: 0, external: 0 };
  return result.stdout.split('\n').reduce(
    (counts, line) => {
      if (!new RegExp(`\\b${protocol}\\b`).test(line)) return counts;
      return isLoopbackBinding(line)
        ? { ...counts, loopback: counts.loopback + 1 }
        : { ...counts, external: counts.external + 1 };
    },
    { loopback: 0, external: 0 },
  );
}

/** Recognize the loopback literals in lsof socket rows. */
function isLoopbackBinding(line: string): boolean {
  return /(?:127\.0\.0\.1|\[::1\]|localhost)(?::|\s|$)/i.test(line);
}

/** Determine whether all required local sources were available without exposing command output. */
function sourceAvailability(
  ...results: readonly SecurityNetworkCommandResult[]
): SecurityNetworkEvidenceAvailability {
  if (results.every((result) => result.exitCode === 0)) return 'available';
  return results.some((result) =>
    /operation not permitted|permission denied|not permitted/i.test(result.stdout),
  )
    ? 'permission-blocked'
    : 'unavailable';
}

/** Interpret the supported ALF state text conservatively. */
function parseApplicationFirewallSetting(
  result: SecurityNetworkCommandResult,
): SecurityNetworkSetting {
  if (result.exitCode !== 0) return 'unknown';
  if (/\b(enabled|state\s*=\s*1)\b/i.test(result.stdout)) return 'enabled';
  if (/\b(disabled|state\s*=\s*0)\b/i.test(result.stdout)) return 'disabled';
  return 'unknown';
}
