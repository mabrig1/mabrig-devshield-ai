// Small, offline-in-browser heuristic preview. No network requests, telemetry or uploads.
// The full deterministic engine is the Node CLI in the GitHub repository.
const pick = id => document.getElementById(id);
const fileBox = pick('scan-files');
const snippet = pick('code-input');
const scanButton = pick('scan-button');
const resetButton = pick('reset-button');
const exportButton = pick('export-button');
const findingsBox = pick('findings');
const summaryBox = pick('result-summary');
const statusBox = pick('scan-status');
let lastReport = null;

const rules = [
  {
    id: 'powershell-encoded-command',
    severity: 'high',
    pattern: /\b(?:powershell|pwsh)(?:\.exe)?[^\r\n]{0,180}-(?:enc|encodedcommand)\b/i,
    message: 'Encoded PowerShell execution indicator detected.',
    remediation: 'Inspect the encoded command in an isolated environment without executing it.'
  },
  {
    id: 'shell-download-and-execute',
    severity: 'critical',
    pattern: /\b(?:curl|wget)\b[^\r\n|]{0,180}\|\s*(?:sudo\s+)?(?:sh|bash)\b/i,
    message: 'Remote content appears to be piped directly into a shell.',
    remediation: 'Download and independently verify the artifact before execution.'
  },
  {
    id: 'powershell-download-and-execute',
    severity: 'critical',
    pattern: /\b(?:iwr|invoke-webrequest)\b[^\r\n|]{0,180}\|\s*(?:iex|invoke-expression)\b/i,
    message: 'PowerShell download-to-execute behavior detected.',
    remediation: 'Remove this execution chain and verify the origin of the script.'
  },
  {
    id: 'msbuild-prebuild-script',
    severity: 'high',
    pattern: /<PreBuildEvent>[\s\S]{0,1200}\b(?:powershell|pwsh|mshta|certutil)\b/i,
    message: 'A Visual Studio pre-build event invokes a scripting utility.',
    remediation: 'Review or disable the build hook before compiling the project.'
  },
  {
    id: 'python-decoded-execution',
    severity: 'critical',
    pattern: /\bexec\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|zlib\.decompress)\s*\(/,
    message: 'Python code appears to execute a decoded payload.',
    remediation: 'Treat the decoded content as untrusted data; do not execute it.'
  },
  {
    id: 'github-access-token',
    severity: 'critical',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
    message: 'A possible GitHub credential appears in the selected material.',
    remediation: 'Revoke or rotate the credential if genuine; use protected secrets.'
  },
  {
    id: 'ai-provider-token',
    severity: 'critical',
    pattern: /\bsk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{20,}\b/,
    message: 'A possible AI provider credential appears in the selected material.',
    remediation: 'Revoke or rotate the key if genuine. Never place it in source code.'
  },
  {
    id: 'private-key-material',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    message: 'Private key material appears in the selected material.',
    remediation: 'Revoke or rotate the key and keep it in a secret manager.'
  }
];
const maxFiles = 30;
const maxBytes = 256 * 1024;

function addText(parent, tag, value, className = '') {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  parent.append(element);
  return element;
}
function previewScan(name, source) {
  const findings = [];
  for (const rule of rules) {
    const m = rule.pattern.exec(source);
    if (!m) continue;
    const line = 1 + source.slice(0, m.index).split('\n').length - 1;
    findings.push({
      rule: rule.id, severity: rule.severity, file: name, line,
      message: rule.message, remediation: rule.remediation
    });
  }
  if (/^package\.json$/i.test(name) || /\/package\.json$/i.test(name)) {
    try {
      const manifest = JSON.parse(source);
      const scripts = manifest?.scripts;
      if (scripts && typeof scripts === 'object') {
        for (const hook of ['preinstall','install','postinstall','prepare','prepack']) {
          const command = scripts[hook];
          if (typeof command !== 'string') continue;
          if (/(?:\bcurl\b|\bwget\b)[^\r\n|]{0,120}\|\s*(?:sh|bash)\b/i.test(command)) {
            findings.push({
              rule: 'lifecycle-download-and-execute', severity: 'critical',
              file: name, line: 1,
              message: 'The ' + hook + ' package hook appears to download and run remote code.',
              remediation: 'Review dependency lifecycle hooks without installing this package.'
            });
          }
        }
      }
    } catch {
      // Other parsers validate malformed manifests; this preview makes no claims about them.
    }
  }
  return findings;
}
function showReport(report) {
  findingsBox.replaceChildren();
  if (!report) {
    addText(findingsBox, 'span', '◇', 'big');
    addText(findingsBox, 'h4', 'No scan has been run');
    addText(findingsBox, 'p', 'Paste code or choose local text files, then select Run local preview.');
    findingsBox.className = 'result-empty';
    summaryBox.textContent = 'Awaiting input';
    statusBox.textContent = 'No files or code leave this browser.';
    exportButton.disabled = true;
    return;
  }
  findingsBox.className = '';
  summaryBox.textContent = report.findings.length + ' indicator(s) · ' + report.filesReviewed + ' item(s) reviewed';
  statusBox.textContent = report.incomplete
    ? 'Incomplete: some items were too large, unsupported, or skipped.'
    : 'Completed heuristic preview. Zero findings does not mean safe.';
  exportButton.disabled = false;
  if (!report.findings.length) {
    addText(findingsBox, 'h4', 'No matching indicators observed');
    addText(findingsBox, 'p', 'This is a limited browser preview, not a malware verdict or full DevShield scan.', 'muted');
    return;
  }
  for (const finding of report.findings.slice(0, 40)) {
    const node = document.createElement('div');
    node.className = 'result-line';
    addText(node, 'span', finding.severity.toUpperCase(), 'severity ' + finding.severity);
    addText(node, 'b', finding.rule);
    addText(node, 'p', finding.message);
    addText(node, 'small', finding.file + ':' + finding.line);
    findingsBox.append(node);
  }
  if (report.findings.length > 40) addText(findingsBox, 'p', 'Additional results are included in the exported JSON.', 'muted');
}
async function runPreview() {
  const files = Array.from(fileBox.files || []);
  const code = snippet.value;
  if (!code.trim() && files.length === 0) {
    summaryBox.textContent = 'Add code or choose text files first.';
    snippet.focus();
    return;
  }
  scanButton.disabled = true;
  scanButton.textContent = 'Reviewing locally…';
  try {
    const findings = [];
    let scanned = 0;
    let incomplete = false;
    const skipped = [];
    if (code.trim()) {
      if (new Blob([code]).size <= maxBytes) {
        findings.push(...previewScan('pasted-snippet.txt', code));
        scanned++;
      } else {
        skipped.push('Pasted snippet exceeds 256 KiB.');
        incomplete = true;
      }
    }
    if (files.length > maxFiles) {
      incomplete = true;
      skipped.push('Only the first 30 selected files are processed.');
    }
    for (const file of files.slice(0, maxFiles)) {
      if (file.size > maxBytes) {
        incomplete = true;
        skipped.push(file.name + ' exceeds 256 KiB.');
        continue;
      }
      if (!/\.(?:js|jsx|mjs|cjs|ts|tsx|json|yml|yaml|ps1|py|go|sh|bat|cmd|txt|env|csproj)$/i.test(file.name)) {
        incomplete = true;
        skipped.push(file.name + ' is not a supported text format.');
        continue;
      }
      try {
        const source = await file.text();
        scanned++;
        findings.push(...previewScan(file.name, source));
      } catch {
        incomplete = true;
        skipped.push(file.name + ' could not be read.');
      }
    }
    lastReport = {
      schema: 'devshield.browser-preview.v1',
      mode: 'browser-only-heuristic',
      generatedAt: new Date().toISOString(),
      filesReviewed: scanned, incomplete, skipped, findings,
      disclaimer: 'Not a complete security analysis or proof of safety. No data uploaded.'
    };
    showReport(lastReport);
  } catch {
    summaryBox.textContent = 'The local preview could not complete.';
    statusBox.textContent = 'No information was submitted to a server.';
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = 'Run local preview';
  }
}
scanButton.addEventListener('click', runPreview);
resetButton.addEventListener('click', () => {
  snippet.value = '';
  fileBox.value = '';
  lastReport = null;
  showReport(null);
});
exportButton.addEventListener('click', () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'devshield-local-preview.json';
  anchor.click();
  URL.revokeObjectURL(url);
});
showReport(null);
