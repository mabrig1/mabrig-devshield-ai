import fs from 'node:fs';
import path from 'node:path';

const EXISTS = p => fs.existsSync(path.resolve(p));
const read = p => { try { return fs.readFileSync(path.resolve(p),'utf8'); } catch { return ''; } };

export function scanLegalCompliance(root='.') {
  const findings=[];
  const add=(id,severity,title,evidence,remediation,category='legal-compliance') =>
    findings.push({id,severity,title,category,evidence,remediation,advisory:true});

  const hasAny = names => names.some(n=>EXISTS(path.join(root,n)));
  if(!hasAny(['LICENSE','LICENSE.md','LICENSE.txt'])) add('LEGAL001','high','Missing software licence','No root LICENSE file detected.','Add an appropriate licence and verify ownership/third-party obligations.');
  if(!hasAny(['PRIVACY.md','PRIVACY_POLICY.md','privacy.md'])) add('LEGAL002','medium','Privacy notice not detected','No repository privacy notice detected.','Document data collected, purpose, retention, processors, user rights and contact route.');
  if(!hasAny(['TERMS.md','TERMS_OF_SERVICE.md','terms.md'])) add('LEGAL003','medium','Terms of service not detected','No repository terms document detected.','Add terms appropriate to the product, jurisdiction and commercial model.');

  const pkgPath=path.join(root,'package.json');
  if(EXISTS(pkgPath)){
    try {
      const pkg=JSON.parse(read(pkgPath));
      if(!pkg.license && !hasAny(['LICENSE','LICENSE.md','LICENSE.txt'])) add('LEGAL004','medium','Package licence metadata missing','package.json has no license field.','Declare the package licence consistently with the repository licence.');
    } catch { /* other scanners handle malformed manifests */ }
  }

  const candidates=['README.md','TERMS.md','PRIVACY.md','package.json'].filter(f=>EXISTS(path.join(root,f)));
  const corpus=candidates.map(f=>read(path.join(root,f))).join('\n').toLowerCase();
  const highStakes=[
    ['LEGAL010',/diagnos(e|is|tic)|medical advice|treat(ment)?/, 'Health/medical claims detected'],
    ['LEGAL011',/guaranteed returns?|investment advice|profit guarantee/, 'Financial claims detected'],
    ['LEGAL012',/legal advice|attorney|lawyer/, 'Legal-service claims detected'],
    ['LEGAL013',/children|minor|under 13|under 18/, 'Children/minor-related processing detected']
  ];
  for(const [id,re,title] of highStakes) if(re.test(corpus)) add(id,'high',title,'High-stakes language appears in repository-facing documents.','Review applicable sector rules, disclosures, consent and professional/regulatory requirements.');

  const ai=/\b(ai|artificial intelligence|llm|machine learning|openai|anthropic|gemini)\b/.test(corpus);
  if(ai && !/ai.{0,30}(disclos|generated|assist)|automated decision|model provider/.test(corpus))
    add('LEGAL020','low','AI disclosure review recommended','AI-related functionality is referenced but an AI-use disclosure was not detected.','Document material AI use, limitations, human oversight and relevant data sent to model providers.');

  return {
    schemaVersion:'1.0',
    scanner:'DevShield Legal & Compliance Shield',
    disclaimer:'Automated risk spotting only; not legal advice or a determination of compliance.',
    findings,
    summary:{
      total:findings.length,
      high:findings.filter(f=>f.severity==='high').length,
      medium:findings.filter(f=>f.severity==='medium').length,
      low:findings.filter(f=>f.severity==='low').length
    }
  };
}
