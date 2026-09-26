/**
 * Module — smoke tests.
 */

import { start, execute, validate } from "../src/index";

let passed = 0;
let failed = 0;

function assert(label: string, condition: boolean): void {
  if (condition) { console.log(`  ✅ ${label}`); passed++; }
  else           { console.error(`  ❌ ${label}`); failed++; }
}

assert("start is a function",    typeof start    === "function");
assert("execute is a function",  typeof execute  === "function");
assert("validate is a function", typeof validate === "function");
assert("validate(1) === true",   validate(1)     === true);
assert("validate(undefined) === false", validate(undefined) === false);
assert("execute runs without throwing", (() => {
  try { execute(); return true; } catch { return false; }
})());

console.log(`\n${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exit(1);
