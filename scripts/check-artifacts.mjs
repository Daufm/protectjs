import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageRules = [
  { name: 'security-contracts', allowed: new Set(['dist', 'README.md', 'LICENSE']) },
  { name: 'sdk-node', allowed: new Set(['dist', 'README.md', 'LICENSE']) },
];

for (const rule of packageRules) {
  const packageRoot = resolve(root, 'packages', rule.name);
  const packageJson = JSON.parse(readFileSync(resolve(packageRoot, 'package.json'), 'utf8'));
  assert.deepEqual(new Set(packageJson.files), rule.allowed);
  assert.equal(packageJson.license, 'Apache-2.0');
  assert.equal(packageJson.private, undefined);
  assert.equal(existsSync(resolve(packageRoot, 'dist')), true);
  assert.equal(existsSync(resolve(packageRoot, 'LICENSE')), true);
  const packOutput = execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: packageRoot,
    encoding: 'utf8',
  });
  const files = JSON.parse(packOutput)[0].files.map(({ path }) => path);
  assert.equal(
    files.some((path) => path.startsWith('dist/')),
    true,
  );
  assert.equal(
    files.some((path) => path.startsWith('src/')),
    false,
  );
  assert.equal(
    files.some((path) => path.startsWith('test/')),
    false,
  );
  assert.equal(files.includes('README.md'), true);
  assert.equal(files.includes('LICENSE'), true);
}

console.log('Package artifact boundaries are valid.');
