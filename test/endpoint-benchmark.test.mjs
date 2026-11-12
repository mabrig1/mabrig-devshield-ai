import assert from 'node:assert/strict';
import test from 'node:test';
import { cases, runSyntheticBenchmark, markdownReport } from '../benchmark/endpoint-synthetic.mjs';

test('synthetic benchmark exercises safe positives, ordinary files, and incomplete cases', () => {
  const result = runSyntheticBenchmark({ repeats: 2 });
  assert.equal(result.type, 'synthetic-rule-regression-only');
  assert.equal(result.vendorComparisonPerformed, false);
  assert.equal(result.malwareDetectionRateMeasured, false);
  assert.equal(result.realMalwareSamplesUsed, false);
  assert.equal(result.clamAvEngineTested, false);
  assert.equal(result.fixtures, cases.length);
  assert.equal(result.passed, cases.length,
    'unexpected fixture failures: ' + JSON.stringify(result.failed));
  assert.equal(result.failed.length, 0);
  assert.equal(result.results.filter(x => x.expectation === 'finding').length, 7);
  assert.equal(result.results.filter(x => x.expectation === 'no-indicators').length, 2);
  assert.equal(result.results.filter(x => x.expectation === 'incomplete').length, 1);
  for (const item of result.results) {
    assert.ok(Number.isFinite(item.medianMilliseconds));
    assert.ok(item.medianMilliseconds >= 0);
    assert.equal(typeof item.complete, 'boolean');
  }
  const md = markdownReport(result);
  assert.match(md, /NOT detection rate/);
  assert.match(md, /Median ms/);
  assert.doesNotMatch(md, /ghp_XXXXXXXXXX/, 'never export dummy secret material');
  assert.doesNotMatch(JSON.stringify(result), /ghp_XXXXXXXXXX/);
});

test('benchmark is bounded and only generates inert fixture data', () => {
  assert.throws(() => runSyntheticBenchmark({ repeats: 0 }), /repeats must be/);
  assert.throws(() => runSyntheticBenchmark({ repeats: 100 }), /repeats must be/);
  assert.equal(cases.some(x => x.id === 'eicar'), false);
  assert.equal(cases.some(x => x.bytes.toString().includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')), false);
  assert.equal(cases.some(x => x.id.includes('real-malware')), false);
});
