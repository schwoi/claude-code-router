/**
 * Shared SSRF guards for outbound requests whose target is influenced by
 * untrusted input (route scripts, model tool output, etc.).
 *
 * Resolves the target host and rejects private, loopback, link-local, CGNAT and
 * cloud-metadata addresses so a request cannot be pointed at internal services
 * such as 169.254.169.254 or 127.0.0.1:<port>.
 */
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

function normalizeHostname(value: string): string {
  return value.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function normalizeIpAddress(value: string): string {
  return normalizeHostname(value).split("%", 1)[0];
}

export function isRestrictedIpAddress(value: string): boolean {
  const address = normalizeIpAddress(value);
  if (isIP(address) === 4) {
    const octets = address.split(".").map(Number);
    const [first, second] = octets;
    return first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && (second === 0 || second === 168)) ||
      (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0) ||
      first >= 224;
  }
  if (isIP(address) === 6) {
    return address === "::" ||
      address === "::1" ||
      address.startsWith("::ffff:") ||
      /^(?:fc|fd)/.test(address) ||
      /^fe[89ab]/.test(address) ||
      address.startsWith("ff") ||
      address.startsWith("2001:db8:");
  }
  return true;
}

export function isLoopbackIpAddress(value: string): boolean {
  const address = normalizeIpAddress(value);
  return address === "::1" || (isIP(address) === 4 && address.startsWith("127."));
}

async function resolveHostAddresses(hostname: string): Promise<string[]> {
  // URL.hostname brackets IPv6 literals (e.g. "[::1]"); strip them before the
  // isIP check so literals are classified directly instead of hitting DNS.
  const literal = normalizeIpAddress(hostname);
  if (isIP(literal)) {
    return [literal];
  }
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  const unique = [...new Set(addresses.map((item) => normalizeIpAddress(item.address)).filter(Boolean))];
  if (!unique.length) {
    throw new Error(`Host "${hostname}" could not be resolved.`);
  }
  return unique;
}

/**
 * Throw when the URL's host resolves to any restricted address. The caller must
 * use `redirect: "manual"` so a redirect cannot bypass this check.
 *
 * `allowLoopback` permits 127.0.0.0/8 and ::1 (e.g. a local model endpoint used
 * as a routing input) while still blocking the higher-value SSRF targets:
 * link-local (cloud metadata 169.254.169.254), RFC1918, CGNAT and multicast.
 */
export async function assertPublicFetchTarget(
  rawUrl: string,
  options: { allowLoopback?: boolean } = {}
): Promise<void> {
  const url = new URL(rawUrl);
  const addresses = await resolveHostAddresses(url.hostname);
  const blocked = addresses.some((address) =>
    isRestrictedIpAddress(address) && !(options.allowLoopback && isLoopbackIpAddress(address)));
  if (blocked) {
    throw new Error("Requests to private, link-local, or metadata addresses are not allowed.");
  }
}
