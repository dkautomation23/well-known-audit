/**
 * Fetching a URL that belongs to a domain someone else typed in.
 *
 * Everything this tool requests - `/.well-known/security.txt`,
 * `/robots.txt`, and ten more - is a path we built ourselves onto the
 * domain the operator named. The domain itself is the operator's choice.
 * What is NOT the operator's choice is where a server's redirect sends us
 * next: that is data from a stranger, and it is checked every time, the
 * same way `ucp-audit` checks it (see `isPublicUrl` and `followed` there).
 */

export interface Fetcher {
  get(url: string): Promise<{ status: number; contentType: string; body: string; redirected: boolean }>;
}

export const USER_AGENT = "well-known-audit (+https://github.com/dkautomation23/well-known-audit)";

/**
 * Hosts this tool refuses to request, whatever a domain or a redirect says.
 *
 * This walks up to sites this tool's operator does not own. Run from inside a
 * company network, a redirect to `http://169.254.169.254/` or
 * `http://localhost:8080/admin` would make the operator's own machine fetch
 * it - a request-forgery primitive an audit tool has no business offering.
 */
const PRIVATE_HOST =
  /^(localhost|.*\.localhost|127\.|10\.|192\.168\.|169\.254\.|0\.|::1$|\[::1\]|fc00:|fe80:|172\.(1[6-9]|2\d|3[01])\.)/i;

export function isPublicUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return false;
  const host = url.hostname.toLowerCase();
  if (PRIVATE_HOST.test(host)) return false;
  // A bare name with no dot cannot be a public host, and may be an internal one.
  if (!host.includes(".") && !host.includes(":")) return false;
  return true;
}

/** 5 MB. None of the files this tool checks are legitimately anywhere near this. */
export const MAX_BODY_BYTES = 5 * 1024 * 1024;

/** How many hops a server may send us on before we stop. */
const MAX_REDIRECTS = 5;

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/**
 * Follows redirects ourselves, checking every hop.
 *
 * `redirect: "follow"` hands the decision to whoever answers: a domain's own
 * address passes the public-address check, and its 302 to `http://127.0.0.1`
 * or a cloud metadata service is then followed without anyone asking.
 * Checking the URL we were given and letting the answer take us anywhere is
 * not a check.
 */
async function followed(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<{ response: Response; redirected: boolean }> {
  let current = url;
  let redirected = false;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const response = await fetch(current, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!REDIRECT_STATUS.has(response.status)) return { response, redirected };

    const location = response.headers.get("location");
    if (!location) return { response, redirected };

    const next = new URL(location, current).toString();
    if (!isPublicUrl(next)) {
      throw new Error(
        `${current} redirects to ${next}, which is not a public address; refusing to follow it`,
      );
    }
    await response.body?.cancel();
    current = next;
    redirected = true;
  }

  throw new Error(`${url} sent more than ${MAX_REDIRECTS} redirects; giving up`);
}

/**
 * Reads at most `limit` bytes and stops.
 *
 * `response.text()` reads whatever is sent before anyone can object, so a
 * size check that runs afterwards protects nothing: the memory is already
 * spent. None of the files this tool reads are meant to be large, so hitting
 * the cap is itself evidence that the URL is not what it claims to be.
 */
async function readCapped(response: Response, limit: number, url: string): Promise<string> {
  const body = response.body;
  if (!body) return "";

  const decoder = new TextDecoder();
  const reader = body.getReader();
  let text = "";
  let bytes = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) {
        await reader.cancel();
        throw new Error(`${url} returned more than ${limit} bytes; refusing to read further`);
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }

  return text + decoder.decode();
}

export function httpFetcher(timeoutMs: number): Fetcher {
  return {
    async get(url) {
      const { response, redirected } = await followed(
        url,
        { headers: { accept: "text/plain, application/json;q=0.9, */*;q=0.8", "user-agent": USER_AGENT } },
        timeoutMs,
      );
      return {
        status: response.status,
        contentType: response.headers.get("content-type") ?? "",
        body: await readCapped(response, MAX_BODY_BYTES, url),
        redirected,
      };
    },
  };
}

/**
 * Why a single request could not be completed, coarse enough to decide how
 * seriously to take it.
 *
 * `private` and `too-large` and `redirect-loop` are all things WE decided,
 * deterministically, about how the server behaved - that is a fact about the
 * target, not about the network being flaky, so it is judged as a blocker.
 * `network` covers DNS, TLS, timeouts and everything else transient, which is
 * reported but never treated as proof that a file is broken.
 */
export type FetchErrorClass = "private" | "too-large" | "redirect-loop" | "network";

export function classifyFetchError(message: string): FetchErrorClass {
  if (message.includes("not a public address")) return "private";
  if (message.includes("refusing to read further")) return "too-large";
  if (message.includes("redirects; giving up")) return "redirect-loop";
  return "network";
}

/** The outcome of one request, successful or not - never throws. */
export interface FetchOutcome {
  url: string;
  /** True once an HTTP response arrived, whatever its status. */
  reached: boolean;
  status: number;
  redirected: boolean;
  contentType: string;
  body: string;
  bytes: number;
  error?: string;
  errorClass?: FetchErrorClass;
}

/** `Fetcher.get`, but every failure becomes data instead of an exception. */
export async function safeGet(fetcher: Fetcher, url: string): Promise<FetchOutcome> {
  try {
    const result = await fetcher.get(url);
    return {
      url,
      reached: true,
      status: result.status,
      redirected: result.redirected,
      contentType: result.contentType,
      body: result.body,
      bytes: Buffer.byteLength(result.body, "utf8"),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      url,
      reached: false,
      status: 0,
      redirected: false,
      contentType: "",
      body: "",
      bytes: 0,
      error: message,
      errorClass: classifyFetchError(message),
    };
  }
}

/**
 * Runs `fn` over `items`, at most `limit` at once, with a pause between
 * batches.
 *
 * This one domain answers up to thirteen requests in one run. Firing them
 * all at once is indistinguishable from something worth blocking; a fixed,
 * low concurrency and a pause is what makes an audit tool a polite visitor
 * rather than a small denial-of-service.
 */
export async function runLimited<T, R>(
  items: readonly T[],
  limit: number,
  delayMs: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  for (let start = 0; start < items.length; start += limit) {
    const batch = items.slice(start, start + limit);
    const batchResults = await Promise.all(batch.map((item) => fn(item)));
    for (let i = 0; i < batchResults.length; i += 1) results[start + i] = batchResults[i]!;
    if (delayMs > 0 && start + limit < items.length) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  return results;
}
