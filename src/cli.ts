#!/usr/bin/env node
import { resolve } from 'node:path';
import { checkBuild } from './check.js';

const [command, dirArg] = process.argv.slice(2);

if (command !== 'check') {
  console.log('Usage: astro-secure check [dist/client]');
  process.exit(command ? 1 : 0);
}

const dir = resolve(dirArg ?? 'dist/client');
const { errors, warnings } = await checkBuild(dir);

for (const w of warnings) console.warn(`⚠ ${w}`);
for (const e of errors) console.error(`✖ ${e}`);

if (errors.length) {
  console.error(`\nastro-secure check failed: ${errors.length} error(s).`);
  process.exit(1);
}
console.log(`✔ astro-secure check passed (${warnings.length} warning(s)).`);
