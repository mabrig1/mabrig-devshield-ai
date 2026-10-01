#!/usr/bin/env node
import { recommendHumanControl } from '../src/human-control-boundary.mjs';

const result = recommendHumanControl({
  privilege: 'high',
  reversibility: 'low',
  externalSideEffects: true,
  credentialAccess: true,
  blastRadiusNodes: 24,
  uncertainty: 0.45,
  evidenceQuality: 0.82,
  highestFindingSeverity: 'high',
  regressionDecision: 'warn'
});

process.stdout.write(JSON.stringify(result, null, 2) + '\n');
