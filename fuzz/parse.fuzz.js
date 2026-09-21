/**
 * Every one of these parsers is handed a file written by someone else, on a
 * host we do not control, over the network. Bytes we did not choose are the
 * whole job, so the property worth checking is not "the answer is right" - it
 * is "the parser returns rather than throws", because an exception here ends
 * an audit of five hundred domains at domain forty.
 *
 * The suite covers the cases I thought of. This covers the ones I did not.
 */
import {
  countLlmsLinks,
  isPlainObject,
  looksLikeHtml,
  looksLikeUri,
  parseMtaSts,
  parseRobotsTxt,
  parseSecurityTxt,
  safeJsonParse,
} from "../dist/src/parse.js";

export function fuzz(data) {
  const body = data.toString("utf8");

  const security = parseSecurityTxt(body);
  if (!Array.isArray(security.expiresValues)) {
    throw new Error("parseSecurityTxt must always return arrays");
  }
  if (security.fieldLineCount < 0) {
    throw new Error(`negative field count: ${security.fieldLineCount}`);
  }

  const robots = parseRobotsTxt(body);
  if (!Array.isArray(robots.sitemaps)) {
    throw new Error("parseRobotsTxt must always return a list of sitemaps");
  }
  if (typeof robots.disallowsEverything !== "boolean") {
    throw new Error("disallowsEverything must be decided, not undefined");
  }

  const mta = parseMtaSts(body);
  if (!Array.isArray(mta.mx)) {
    throw new Error("parseMtaSts must always return a list of mx entries");
  }

  const links = countLlmsLinks(body);
  if (!Number.isInteger(links) || links < 0) {
    throw new Error(`link count is not a count: ${links}`);
  }

  // safeJsonParse promises never to throw: that is its entire reason to exist.
  const parsed = safeJsonParse(body);
  if (parsed.ok) isPlainObject(parsed.value);

  looksLikeHtml(body, body.slice(0, 40));
  looksLikeUri(body.slice(0, 200));
}
