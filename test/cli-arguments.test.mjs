import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/devshield.mjs', import.meta.url));

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    timeout: 15000,
  });
}

test('rejects typoed options instead of quietly using a weaker default', () => {
  const result = run('--fail-onn', 'medium');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown option: --fail-onn/);
});

test('rejects unsupported options with no value', () => {
  const result = run('--securty-graph');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown option/);
});

test('rejects a missing value instead of running with defaults', () => {
  const result = run('--fail-on');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Missing value for --fail-on/);
});

test('does not consume the next option as an option value', () => {
  const result = run('--fail-on', '--repository');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Missing value for --fail-on/);
});

test('rejects invalid severity and policy enum values before scanning', () => {
  for (const [option, value] of [
    ['--fail-on', 'severe'],
    ['--security-graph', 'maybe'],
    ['--regression-gate', 'offf'],
    ['--scope', 'changed-only'],
  ]) {
    const result = run(option, value);
    assert.equal(result.status, 2, `${option}=${value}`);
    assert.match(result.stderr, /Invalid value/);
  }
});

test('accepts documented options and preserves the help path', () => {
  const result = run('--scope', 'changed-lines', '--fail-on', 'medium',
    '--regression-gate', 'enforce', '--security-graph', 'auto', '--help');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /MABRIG DevShield AI local scanner/);
});

test('accepts existing shortcut flags unchanged', () => {
  const result = run('--strict', '--repository', '--no-sarif', '--help');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--no-sarif/);
});
