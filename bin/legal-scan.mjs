#!/usr/bin/env node
import { scanLegalCompliance } from '../src/legal-compliance.mjs';
const root=process.argv[2] || '.';
const result=scanLegalCompliance(root);
console.log(JSON.stringify(result,null,2));
process.exit(result.summary.high ? 2 : 0);
