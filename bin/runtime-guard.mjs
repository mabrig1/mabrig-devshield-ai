#!/usr/bin/env node
import { runRuntimeGuardFromEnv } from '../src/runtime-guard.mjs';

try {
  const result = await runRuntimeGuardFromEnv();
  if (result?.disabled) {
    console.log('MABRIG DevShield Runtime Guard is disabled.');
  } else {
    const summary = result.report.summary;
    console.log(`Runtime Guard: ${result.report.state}; blocked=${summary.blocked}/${summary.total}; block-rate=${summary.blockRate}%`);
    if (result.shouldFail) process.exitCode = 2;
  }
} catch (error) {
  console.error(`::error title=DevShield Runtime Guard::${error?.message || String(error)}`);
  process.exitCode = 2;
}
