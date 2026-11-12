import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { importReachabilitySarif } from '../src/reachability-evidence.mjs';

const step = (file, line) => ({ location: { physicalLocation: { artifactLocation: { uri: file }, region: { startLine: line } } } });
const makeSarif = (name, steps) => ({
  version: '2.1.0',
  runs: [{ tool: { driver: { name, rules: [{ id: 'js/sql-injection', properties: { 'security-severity': '8.1' } }] } },
    results: [{ ruleId: 'js/sql-injection', codeFlows: [{ threadFlows: [{ locations: steps }] }] }] }]
});

test('imports concrete CodeQL dataflow with stable fingerprint, no code snippets', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reach-'));
  try {
    fs.writeFileSync(path.join(root, 'app.js'), 'const x = req.query.q;\nconst sql = x;\ndb.query(sql);\n');
    const sarif = makeSarif('CodeQL', [step('app.js', 1), step('app.js', 2), step('app.js', 3)]);
    const first = importReachabilitySarif(sarif, { workspace: root });
    const again = importReachabilitySarif(sarif, { workspace: root });
    assert.deepEqual(first, again);
    assert.equal(first.findings.length, 1);
    assert.equal(first.findings[0].severity, 'high');
    assert.equal(first.findings[0].pathSteps, 3);
    assert.equal(JSON.stringify(first).includes('db.query(sql)'), false);
  } finally { fs.rmSync(root, { force: true, recursive: true }); }
});

test('rejects untrusted engine claims, missing codeflows, traversal and symlink escapes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reach-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-'));
  try {
    fs.writeFileSync(path.join(root, 'ok.py'), 'x = 1\ny = 2\n');
    fs.writeFileSync(path.join(outside, 'bad.py'), 'x = 1\ny = 2\n');
    fs.symlinkSync(path.join(outside, 'bad.py'), path.join(root, 'link.py'));
    for (const [engine, location] of [
      ['RegexpScanner', 'ok.py'], ['CodeQL', '../outside/bad.py'],
      ['CodeQL', 'link.py'], ['CodeQL', 'missing.go'], ['CodeQL', '%2e%2e/bad.py']
    ]) {
      const report = importReachabilitySarif(makeSarif(engine, [step(location, 1), step(location, 2)]), { workspace: root });
      assert.equal(report.findings.length, 0, engine + '/' + location);
    }
    const report = importReachabilitySarif(makeSarif('CodeQL', []), { workspace: root });
    assert.equal(report.findings.length, 0);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
    fs.rmSync(outside, { force: true, recursive: true });
  }
});
