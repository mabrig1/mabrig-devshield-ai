#!/usr/bin/env node
// Defensive, evidence-first threat intelligence collector. Node 20+, no dependencies.
import { writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const API = 'https://api.osv.dev/v1/querybatch';
const GITHUB = 'https://api.github.com/advisories?per_page=100&type=reviewed';
const TIMEOUT = 15000;
async function json(url, options={}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(TIMEOUT), headers: { 'Accept': 'application/json', 'User-Agent': 'mabrig-devshield-threat-intel/1.0', ...options.headers } });
  if (!response.ok) throw new Error('HTTP '+response.status+' from '+new URL(url).host);
  const raw = await response.text();
  if (raw.length > 2_000_000) throw new Error('Response exceeds size limit');
  return JSON.parse(raw);
}
function severity(a) {
  const s=(a.severity || '').toLowerCase();
  return ['critical','high','medium','low'].includes(s)?s:'unknown';
}
function advisory(a) {
  return { id:a.ghsa_id, cve:a.cve_id||null, summary:String(a.summary||'').slice(0,400), severity:severity(a), published_at:a.published_at, updated_at:a.updated_at, url:a.html_url, ecosystems:[...new Set((a.vulnerabilities||[]).map(v=>v.package?.ecosystem).filter(Boolean))].sort() };
}
async function main(){
  const result={schema:1,generated_at:new Date().toISOString(),status:'unknown',sources:{},advisories:[],errors:[]};
  try {
    const data=await json(GITHUB,{headers:{'X-GitHub-Api-Version':'2022-11-28'}});
    if(!Array.isArray(data)) throw new Error('Unexpected GitHub response');
    result.advisories=data.filter(a=>a && a.ghsa_id && a.html_url).map(advisory).sort((a,b)=>a.id.localeCompare(b.id));
    result.sources.github={status:'ok',count:result.advisories.length,scope:'first 100 reviewed advisories, not exhaustive'};
  }catch(e){result.sources.github={status:'error'};result.errors.push(String(e.message));}
  // Query OSV only for explicitly configured package/version pairs; never install packages.
  const packages=JSON.parse(process.env.DEVSHIELD_WATCH_PACKAGES||'[]');
  if (!Array.isArray(packages) || packages.length>100 || packages.some(p=>!p || typeof p.name!=='string' || typeof p.version!=='string' || !['npm','PyPI'].includes(p.ecosystem))) throw new Error('Invalid DEVSHIELD_WATCH_PACKAGES');
  if(packages.length){
    try{
      const data=await json(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({queries:packages.map(p=>({package:{name:p.name,ecosystem:p.ecosystem},version:p.version}))})});
      if(!Array.isArray(data.results)||data.results.length!==packages.length)throw new Error('Invalid OSV response');
      result.sources.osv={status:'ok',count:packages.length};
      result.package_findings=packages.map((p,i)=>({package:p,ids:(data.results[i].vulns||[]).map(v=>v.id).filter(Boolean).sort()}));
    }catch(e){result.sources.osv={status:'error'};result.errors.push(String(e.message));}
  }
  result.status=result.errors.length?'partial':'ok';
  const stable=JSON.stringify(result.advisories.map(a=>[a.id,a.updated_at]));
  result.snapshot_sha256=createHash('sha256').update(stable).digest('hex');
  await mkdir('reports',{recursive:true});
  await writeFile('reports/threat-intel-latest.json',JSON.stringify(result,null,2)+'\n');
  console.log('Threat intelligence:',result.status,'advisories:',result.advisories.length);
  if(result.errors.length){console.error(result.errors.join('\n'));process.exitCode=1;}
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
