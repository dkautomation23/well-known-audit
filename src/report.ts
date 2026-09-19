/**
 * Printing the result one line per file, because that is the unit the
 * operator thinks in: "is security.txt okay", not "here are all blockers,
 * then all warnings". A file with more than one finding gets more than one
 * line, worst first.
 */

import { countByLevel, type Level, type TargetResult } from "./checks.js";

const MARK: Record<Level, string> = { blocker: "BLOCK", warning: "warn", note: "note" };
const LEVEL_ORDER: Level[] = ["blocker", "warning", "note"];
const BAR = "-".repeat(74);
const LABEL_WIDTH = 28;
const MARK_WIDTH = 5;
const TEXT_COLUMN = 2 + MARK_WIDTH + 2 + LABEL_WIDTH + 2;

export interface Context {
  domain: string;
  checkedAt: string;
  timeoutMs: number;
}

function row(mark: string, label: string, text: string): string {
  return `  ${mark.padEnd(MARK_WIDTH)}  ${label.padEnd(LABEL_WIDTH)}  ${text}`;
}

function indented(text: string): string {
  return `${" ".repeat(TEXT_COLUMN)}${text}`;
}

export function renderConsole(results: TargetResult[], context: Context): string {
  const lines: string[] = [];
  lines.push(BAR);
  lines.push(`WELL-KNOWN AUDIT - ${context.domain}`);
  lines.push(BAR);
  lines.push(`checked   ${context.checkedAt}   timeout ${context.timeoutMs}ms`);
  lines.push("");

  for (const result of results) {
    if (result.findings.length === 0) {
      lines.push(row("ok", result.label, result.summary));
      continue;
    }
    const sorted = [...result.findings].sort(
      (a, b) => LEVEL_ORDER.indexOf(a.level) - LEVEL_ORDER.indexOf(b.level),
    );
    for (const finding of sorted) {
      lines.push(row(MARK[finding.level], result.label, finding.title));
      if (finding.detail) lines.push(indented(finding.detail));
      if (finding.fix) lines.push(indented(`-> ${finding.fix}`));
    }
  }

  lines.push("");
  const counts = countByLevel(results.flatMap((result) => result.findings));
  lines.push(`${counts.blocker} blocker(s), ${counts.warning} warning(s), ${counts.note} note(s)`);
  return lines.join("\n");
}

export function renderJson(results: TargetResult[], context: Context): string {
  const findings = results.flatMap((result) => result.findings);
  return `${JSON.stringify(
    {
      domain: context.domain,
      checkedAt: context.checkedAt,
      timeoutMs: context.timeoutMs,
      targets: results.map((result) => ({
        id: result.id,
        label: result.label,
        urls: result.urls,
        summary: result.summary,
        findings: result.findings,
      })),
      summary: countByLevel(findings),
    },
    null,
    2,
  )}\n`;
}
