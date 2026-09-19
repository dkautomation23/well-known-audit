/**
 * Turning the text of a well-known file into the handful of facts each check
 * needs. Nothing here fetches anything or judges anything - a parser that
 * also decides severity cannot be tested against a fixture without also
 * pinning down what the tool thinks of it.
 *
 * Every parser here is tolerant on purpose: a real file in the wild that has
 * a stray blank field or an extra colon is not this tool's problem to reject,
 * only to read past. Whether the fields that DO matter are present and sane
 * is a question for checks.ts, not for these functions.
 */

export interface SecurityTxtFields {
  contacts: string[];
  expiresValues: string[];
  encryption?: string;
  policy?: string;
  canonical: string[];
  preferredLanguagesValues: string[];
  acknowledgments?: string;
  /** Any `Field: value` line, recognised or not - evidence the body is trying to be a security.txt at all. */
  fieldLineCount: number;
}

const FIELD_LINE = /^([A-Za-z][A-Za-z-]*)\s*:\s*(.*)$/;

export function parseSecurityTxt(body: string): SecurityTxtFields {
  const fields: SecurityTxtFields = {
    contacts: [],
    expiresValues: [],
    canonical: [],
    preferredLanguagesValues: [],
    fieldLineCount: 0,
  };

  for (const rawLine of body.split(/\r\n|\r|\n/)) {
    const line = rawLine.trim();
    // A PGP-armoured file wraps the fields in "-----BEGIN ..." banners and a
    // "Hash:" header; skipping lines that cannot be a field is enough to read
    // past that wrapper without having to understand it.
    if (!line || line.startsWith("#") || line.startsWith("-----")) continue;
    const match = FIELD_LINE.exec(line);
    if (!match) continue;
    const field = match[1]!.toLowerCase();
    const value = match[2]!.trim();
    fields.fieldLineCount += 1;

    switch (field) {
      case "contact":
        fields.contacts.push(value);
        break;
      case "expires":
        fields.expiresValues.push(value);
        break;
      case "encryption":
        fields.encryption ??= value;
        break;
      case "policy":
        fields.policy ??= value;
        break;
      case "canonical":
        fields.canonical.push(value);
        break;
      case "preferred-languages":
        fields.preferredLanguagesValues.push(value);
        break;
      case "acknowledgments":
      case "acknowledgements":
        fields.acknowledgments ??= value;
        break;
      default:
        break; // Hiring, CSAF, Hash and anything vendor-specific: not this tool's business.
    }
  }
  return fields;
}

export interface RobotsTxtInfo {
  sitemaps: string[];
  disallowsEverything: boolean;
}

interface RobotsRecord {
  agents: string[];
  disallow: string[];
  allow: string[];
}

const DIRECTIVE_LINE = /^([A-Za-z-]+)\s*:\s*(.*)$/;

/**
 * A "record" in robots.txt is one or more consecutive `User-agent` lines
 * followed by the rules that apply to them; a `User-agent` line seen after a
 * rule line starts a new record rather than extending the current one. That
 * is what makes two separate `User-agent: *` blocks in the same file two
 * different records instead of one.
 */
export function parseRobotsTxt(body: string): RobotsTxtInfo {
  const sitemaps: string[] = [];
  const records: RobotsRecord[] = [];
  let current: RobotsRecord | null = null;
  let lastWasAgent = false;

  for (const rawLine of body.split(/\r\n|\r|\n/)) {
    const line = rawLine.split("#")[0]!.trim();
    if (!line) continue;
    const match = DIRECTIVE_LINE.exec(line);
    if (!match) continue;
    const field = match[1]!.toLowerCase();
    const value = match[2]!.trim();

    if (field === "user-agent") {
      if (!current || !lastWasAgent) {
        current = { agents: [], disallow: [], allow: [] };
        records.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
    } else if (field === "disallow") {
      current?.disallow.push(value);
      lastWasAgent = false;
    } else if (field === "allow") {
      current?.allow.push(value);
      lastWasAgent = false;
    } else if (field === "sitemap") {
      if (value) sitemaps.push(value);
    }
  }

  // "Blocks everything" means a `*` record disallows the whole site with
  // nothing carved back out - a narrower Allow anywhere in the same record
  // is an exception, however small, so it is not a full block any more.
  const disallowsEverything = records.some(
    (record) =>
      record.agents.includes("*") &&
      record.disallow.includes("/") &&
      !record.allow.some((path) => path.trim().length > 0),
  );

  return { sitemaps, disallowsEverything };
}

export interface MtaStsFields {
  version?: string;
  mode?: string;
  mx: string[];
  maxAge?: string;
}

/** RFC 8461's policy file: plain `key: value` lines, `mx` repeatable. */
export function parseMtaSts(body: string): MtaStsFields {
  const fields: MtaStsFields = { mx: [] };
  for (const rawLine of body.split(/\r\n|\r|\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([A-Za-z_]+)\s*:\s*(.*)$/.exec(line);
    if (!match) continue;
    const key = match[1]!.toLowerCase();
    const value = match[2]!.trim();
    if (key === "version") fields.version ??= value;
    else if (key === "mode") fields.mode ??= value;
    else if (key === "mx") fields.mx.push(value);
    else if (key === "max_age") fields.maxAge ??= value;
  }
  return fields;
}

/** Markdown links, `[text](url)` - llms.txt's whole content is a list of these. */
const MARKDOWN_LINK = /\[[^\]\n]*]\([^)\s]+[^)]*\)/g;

export function countLlmsLinks(body: string): number {
  return [...body.matchAll(MARKDOWN_LINK)].length;
}

/**
 * Whether this looks like a browser page rather than the plain-text or JSON
 * file it was requested as.
 *
 * The recurring real-world mistake this catches: a static host with SPA
 * fallback routing answers every unmatched path with `index.html` and a 200,
 * so a file that was never published still "exists" as far as a status code
 * is concerned. Checking the shape of the response is the only way to tell.
 */
export function looksLikeHtml(body: string, contentType: string): boolean {
  if (contentType.toLowerCase().includes("html")) return true;
  return /^\s*<(!doctype html|html)\b/i.test(body.slice(0, 512));
}

export type JsonParseResult = { ok: true; value: unknown } | { ok: false; error: string };

export function safeJsonParse(body: string): JsonParseResult {
  try {
    return { ok: true, value: JSON.parse(body) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** RFC 9116 fields such as Contact and Encryption are required to be URIs. */
const URI_SHAPED = /^[a-zA-Z][a-zA-Z0-9+.-]*:\S/;

export function looksLikeUri(value: string): boolean {
  return URI_SHAPED.test(value);
}
