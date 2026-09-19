#!/usr/bin/env node
/**
 * The entry point. `cli.ts` holds `run`, so the tests can call it without a
 * process.
 *
 * `process.exitCode` rather than `process.exit()`: killing the process while
 * a keep-alive socket from `fetch` is still open makes libuv assert on
 * Windows and the shell sees 127 instead of the code this tool meant to
 * return. Setting the code and letting the loop drain gives the same exit
 * status without the crash.
 */

import { run } from "./cli.js";

run(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  },
);
