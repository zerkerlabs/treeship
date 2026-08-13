/**
 * Guarded fetch for caller-supplied receipt URLs.
 *
 * # Why this exists
 *
 * `verify()` accepts a URL and fetched it directly. In a browser that is
 * unremarkable — the origin model already constrains it. On a server it is
 * server-side request forgery: an application that passes an
 * agent-controlled URL to `verify()` could be made to fetch
 * `http://169.254.169.254/latest/meta-data/`, `http://localhost:6379`, or any
 * other address reachable from the host but not from the caller, and to read
 * an unbounded response body while doing it.
 *
 * The receipt-fetching path is meant to retrieve a public artifact from a
 * Hub. Nothing about that requires reaching a private address.
 *
 * # What each control actually buys, and what it does not
 *
 * Stated precisely, because partial SSRF defenses are routinely described as
 * complete ones:
 *
 * - **Literal address checks** stop the direct attempt (`http://127.0.0.1`,
 *   `http://[::1]`, `http://169.254.169.254`). They do nothing about a
 *   hostname that resolves to a private address.
 * - **Resolving the hostname and checking every returned address** closes the
 *   naive DNS case. It does *not* close DNS rebinding: the name can resolve
 *   again, differently, when the socket is actually opened. Closing that
 *   requires pinning the checked IP at connect time via a custom
 *   agent/lookup, which `fetch` does not expose. Documented rather than
 *   silently assumed.
 * - **`redirect: "error"`** matters more than it looks. Without it every
 *   address check is bypassable by a public URL that 302s to a private one,
 *   because the redirect is followed *after* the check.
 * - **A body cap** bounds memory. A verification input is a receipt, tens of
 *   kilobytes; anything far larger is not a receipt.
 * - **A timeout** bounds a request held open forever by a slow endpoint.
 *
 * So this is a substantial reduction, not an airtight boundary. An
 * application handling genuinely untrusted URLs should also egress-filter at
 * the network layer.
 */

/** Receipts are small. 5 MB is far above a real one and far below a problem. */
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const TIMEOUT_MS = 10_000;

/**
 * Hostnames that name the local machine or a metadata service directly.
 * Lowercased comparison; `.localhost` is reserved for loopback by RFC 6761,
 * and the cloud metadata names resolve to link-local addresses.
 */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
]);

function isBlockedHostname(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (BLOCKED_HOSTNAMES.has(h)) return true;
  // RFC 6761: anything under .localhost is loopback. RFC 6762/6763 and common
  // private suffixes are not internet-routable either.
  return (
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".home.arpa")
  );
}

/** Strip an IPv6 bracket form and any zone id: `[::1%eth0]` -> `::1`. */
function normalizeIpLiteral(host: string): string {
  let h = host;
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  const zone = h.indexOf("%");
  if (zone !== -1) h = h.slice(0, zone);
  return h.toLowerCase();
}

/**
 * Whether an IP literal is private, loopback, link-local, or otherwise not a
 * public internet address.
 *
 * Returns false for anything that is not an IP literal — callers must treat
 * "not an IP" as "unknown", never as "public".
 */
export function isPrivateAddress(raw: string): boolean {
  const host = normalizeIpLiteral(raw);

  // IPv4, including the decimal-dotted form inside IPv4-mapped IPv6.
  const v4 = host.match(/^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if ([a, b, Number(v4[3]), Number(v4[4])].some((n) => n > 255)) return true; // malformed → refuse
    if (a === 0) return true; // "this network"
    if (a === 10) return true; // RFC 1918
    if (a === 127) return true; // loopback
    if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
    if (a === 192 && b === 168) return true; // RFC 1918
    if (a === 100 && b >= 64 && b <= 127) return true; // RFC 6598 CGNAT
    if (a === 192 && b === 0) return true; // RFC 6890 special-purpose
    if (a >= 224) return true; // multicast + reserved
    return false;
  }

  // IPv6.
  if (host.includes(":")) {
    if (host === "::" || host === "::1") return true; // unspecified, loopback
    if (host.startsWith("fe80")) return true; // link-local
    if (/^f[cd]/.test(host)) return true; // unique local fc00::/7
    if (host.startsWith("ff")) return true; // multicast

    // IPv4-mapped, hex form. `new URL()` canonicalizes
    // `[::ffff:127.0.0.1]` to `[::ffff:7f00:1]`, so the dotted-quad branch
    // above never sees it -- the literal check would pass and loopback would
    // be reachable. Decode the embedded v4 address and re-test it.
    const mapped = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mapped) {
      const hi = parseInt(mapped[1], 16);
      const lo = parseInt(mapped[2], 16);
      const dotted = [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join(".");
      return isPrivateAddress(dotted);
    }
    return false;
  }

  return false;
}

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeUrlError";
  }
}

/**
 * Validate a URL before fetching it. Throws `UnsafeUrlError` when the target
 * is not a plausible public receipt endpoint.
 *
 * Exported so both this SDK and the MCP bridge apply the same rule, and so
 * the shared vectors can test it directly.
 */
export function assertFetchableUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError(`not a valid URL: ${raw}`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    // file:, data:, gopher: and friends are not receipt endpoints, and file:
    // in particular turns a "fetch a receipt" call into an arbitrary read.
    throw new UnsafeUrlError(`refusing to fetch ${url.protocol}// — only http and https`);
  }

  if (url.username || url.password) {
    // Credentials in a receipt URL are either a mistake or an attempt to
    // reach something that needs them. Either way, not a public artifact.
    throw new UnsafeUrlError("refusing to fetch a URL carrying embedded credentials");
  }

  const host = url.hostname;
  if (!host) throw new UnsafeUrlError("URL has no host");
  if (isBlockedHostname(host)) {
    throw new UnsafeUrlError(`refusing to fetch a local or internal hostname: ${host}`);
  }
  if (isPrivateAddress(host)) {
    throw new UnsafeUrlError(`refusing to fetch a private or loopback address: ${host}`);
  }

  return url;
}

/**
 * Resolve a hostname and confirm every address is public.
 *
 * Node only. Skipped in browsers, where `node:dns` does not exist and the
 * origin model already constrains the request. Returns silently when
 * resolution is unavailable — this is defense in depth on top of
 * `assertFetchableUrl`, not the only check.
 */
async function assertResolvesPublic(hostname: string): Promise<void> {
  // Already an IP literal: `assertFetchableUrl` checked it, nothing to resolve.
  if (isPrivateAddress(hostname) || /^[\d.]+$/.test(hostname) || hostname.includes(":")) return;

  type LookupFn = (h: string, o: { all: true }) => Promise<Array<{ address: string }>>;
  let lookup: LookupFn;
  try {
    const dns = await import(/* webpackIgnore: true */ "node:dns/promises");
    lookup = dns.lookup as unknown as LookupFn;
  } catch {
    return; // not Node; literal checks stand alone
  }

  let addrs: Array<{ address: string }>;
  try {
    addrs = await lookup(hostname, { all: true });
  } catch {
    // Let fetch produce the real network error rather than inventing one.
    return;
  }
  for (const { address } of addrs) {
    if (isPrivateAddress(address)) {
      throw new UnsafeUrlError(
        `refusing to fetch ${hostname}: it resolves to the private address ${address}`,
      );
    }
  }
}

/**
 * Fetch a receipt URL with SSRF, redirect, size and time bounds applied.
 *
 * Returns the body as text.
 */
export async function safeFetchText(raw: string): Promise<string> {
  const url = assertFetchableUrl(raw);
  await assertResolvesPublic(url.hostname);

  const res = await fetch(url, {
    headers: { accept: "application/json" },
    // Without this, every check above is bypassable by a public URL that
    // redirects to a private one — the redirect is followed after the check.
    redirect: "error",
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });

  if (!res.ok) {
    throw new Error(`fetch ${url.toString()} returned HTTP ${res.status}`);
  }

  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) {
    throw new UnsafeUrlError(
      `receipt body declares ${declared} bytes, over the ${MAX_BODY_BYTES} limit`,
    );
  }

  // content-length is a claim; enforce the cap against the bytes that arrive.
  const body = res.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new UnsafeUrlError(
          `receipt body exceeded the ${MAX_BODY_BYTES} byte limit mid-stream`,
        );
      }
      chunks.push(value);
    }
  }
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(joined);
}
