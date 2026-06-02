/**
 * Low-level network address checks shared by the egress guardrail
 * (LAUNCH-SPEC §5.6, §3.3; ADR-022). Pure, dependency-free, no I/O.
 *
 * The blocked ranges are the SSRF-critical ones an autonomous agent must never
 * reach: the cloud metadata endpoint and RFC-1918 / loopback / link-local /
 * unique-local internal ranges. gVisor also blocks `169.254.169.254` at the
 * sandbox boundary; this is the defense-in-depth layer in code.
 */

/** The GCP/AWS/Azure link-local metadata endpoint — always blocked. */
export const METADATA_IP = '169.254.169.254';

/** Hostnames that resolve to the metadata service — blocked by name too. */
export const METADATA_HOSTNAMES: readonly string[] = ['metadata.google.internal', 'metadata'] as const;

interface Cidr {
  readonly base: number;
  readonly bits: number;
}

/** IPv4 internal/loopback/link-local ranges (CIDR). */
const BLOCKED_V4_CIDRS: readonly string[] = [
  '0.0.0.0/8', // "this host"
  '10.0.0.0/8', // RFC-1918 private
  '100.64.0.0/10', // CGNAT
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local (incl. metadata)
  '172.16.0.0/12', // RFC-1918 private
  '192.0.0.0/24', // IETF protocol assignments
  '192.168.0.0/16', // RFC-1918 private
  '198.18.0.0/15', // benchmarking
];

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number.parseInt(p, 10);
    if (o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

function parseCidr(cidr: string): Cidr | null {
  const [ip, bitsRaw] = cidr.split('/');
  if (ip === undefined || bitsRaw === undefined) return null;
  const base = ipv4ToInt(ip);
  const bits = Number.parseInt(bitsRaw, 10);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  return { base, bits };
}

const BLOCKED_V4: readonly Cidr[] = BLOCKED_V4_CIDRS.map(parseCidr).filter((c): c is Cidr => c !== null);

function inCidr(ipInt: number, cidr: Cidr): boolean {
  if (cidr.bits === 0) return true;
  const mask = cidr.bits === 32 ? 0xffffffff : (~((1 << (32 - cidr.bits)) - 1) >>> 0) >>> 0;
  return (ipInt & mask) === (cidr.base & mask);
}

/** True when an IPv4 literal falls in a blocked internal/loopback range. */
export function isBlockedIpv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  return BLOCKED_V4.some((c) => inCidr(n, c));
}

/** True when an IPv6 literal is loopback / link-local / ULA / v4-mapped-internal. */
export function isBlockedIpv6(ip: string): boolean {
  const v = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (v === '::1' || v === '::') return true; // loopback / unspecified
  if (v.startsWith('fe80:') || v.startsWith('fc') || v.startsWith('fd')) return true; // link-local / ULA
  const mapped = v.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped && mapped[1]) return isBlockedIpv4(mapped[1]);
  return false;
}

/** True when a host literal is the metadata endpoint or an internal IP. */
export function isBlockedHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (h === METADATA_IP) return true;
  if (METADATA_HOSTNAMES.includes(h)) return true;
  if (isBlockedIpv4(h)) return true;
  if (h.includes(':') && isBlockedIpv6(h)) return true;
  return false;
}
