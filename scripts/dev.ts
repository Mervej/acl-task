import * as path from 'path';
import * as dotenv from 'dotenv';

// Spawned services inherit process.env, so loading .env here (rather than in
// each service's main.ts) is enough to reach all of them.
dotenv.config({ path: path.resolve(__dirname, '../.env') });

import { spawn } from 'child_process';

const SERVICES = [
  'gateway', 'access-control', 'user-management', 'expense-management',
  'payroll', 'reporting', 'workflow', 'notification', 'invoice-management', 'audit',
];

for (const service of SERVICES) {
  const child = spawn('npm', ['run', 'start', '--workspace', `packages/${service}`], {
    stdio: 'pipe',
    shell: true,
  });
  const prefix = `[${service}]`;
  child.stdout.on('data', (chunk) => process.stdout.write(`${prefix} ${chunk}`));
  child.stderr.on('data', (chunk) => process.stderr.write(`${prefix} ${chunk}`));
  child.on('exit', (code) => console.log(`${prefix} exited with code ${code}`));
}
