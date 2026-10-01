import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanLegalCompliance } from '../src/legal-compliance.mjs';

test('flags missing baseline legal documents',()=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'devshield-legal-'));
 fs.writeFileSync(path.join(d,'package.json'),'{}');
 const r=scanLegalCompliance(d);
 assert.ok(r.findings.some(f=>f.id==='LEGAL001'));
 assert.ok(r.findings.some(f=>f.id==='LEGAL002'));
 assert.ok(r.findings.some(f=>f.id==='LEGAL003'));
});

test('flags high-stakes claims and marks output advisory',()=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'devshield-legal-'));
 for(const f of ['LICENSE','PRIVACY.md','TERMS.md']) fs.writeFileSync(path.join(d,f),'baseline');
 fs.writeFileSync(path.join(d,'README.md'),'AI medical diagnosis and treatment platform');
 const r=scanLegalCompliance(d);
 assert.ok(r.findings.some(f=>f.id==='LEGAL010' && f.severity==='high'));
 assert.ok(r.findings.every(f=>f.advisory===true));
});
