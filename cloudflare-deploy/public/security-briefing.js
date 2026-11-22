// Read-only questions about the most recent browser-local DevShield heuristic scan.
// No network requests, credentials, live traffic data, or AI provider calls.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const countSeverity = findings => Object.fromEntries(
  SEVERITY_ORDER.map(level => [level, findings.filter(f => f.severity === level).length])
);
const caveat = report => report.incomplete
  ? ' This preview was incomplete; skipped inputs may contain additional issues.'
  : ' This is a limited heuristic scan, not a verdict that the code or website is safe.';

export function answerSecurityQuestion(question, report = null) {
  const q = String(question ?? '').trim().toLowerCase();
  if (!q) return { answer: 'Enter a security question or choose a suggested question.', source: 'No question submitted' };

  // Fail closed for all connected-service, attribution and live-state claims.
  if (/\b(attack|attacked|breach|breached|intrusion|hacked|hackers|incident|live|real[- ]?time|today|yesterday|this week|last (?:24|seven|7)|cloudflare|waf|firewall|server|website|websites|domain|domains|country|countries|location|traffic|requests|ip address|bot|bots|blocked|challenge|threats? online|under attack)\b/i.test(q)) {
    return {
      answer: 'Unknown. No live Cloudflare, server, or web-traffic telemetry is connected to this preview. Browser-local code indicators cannot establish whether an attack occurred, where traffic came from, or whether a website is secure.',
      source: 'Live security telemetry: Not connected'
    };
  }

  if (!report || report.schema !== 'devshield.browser-preview.v1' || !Array.isArray(report.findings)) {
    return {
      answer: 'There is no completed local scan to summarize. Run the browser-local security preview first, then ask about its findings.',
      source: 'Local scan: Not available'
    };
  }

  const findings = report.findings;
  const counts = countSeverity(findings);
  const summary = `${findings.length} indicator(s) in ${report.filesReviewed} reviewed item(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, and ${counts.low} low.`;
  const source = `Browser-local heuristic scan at ${report.generatedAt || 'unknown time'}${report.incomplete ? ' (incomplete)' : ''}`;
  const ordered = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  if (/\b(safe|secure|clean|guarantee|proof|compromised|exploit|exploitable)\b/i.test(q)) {
    return {
      answer: 'Unknown. A local indicator scan cannot certify safety, determine exploitability, or confirm compromise. ' + summary + caveat(report),
      source
    };
  }
  if (/\b(next|fix|repair|remediat|recommend|priority|prioriti|action|step|what should)\b/i.test(q)) {
    if (ordered.length === 0) return { answer: 'No matching indicators were observed. Review the full project with the DevShield CLI and your normal security process; this preview is not a safety certificate.' + caveat(report), source };
    const first = ordered[0];
    return {
      answer: `Review the highest-priority ${first.severity} indicator, "${first.rule}". ${first.remediation || 'Verify the finding with a human security reviewer.'} Never execute untrusted material solely to investigate it.` + caveat(report),
      source
    };
  }
  if (/\b(critical|high|severity|severe|urgent|important|risk|risks)\b/i.test(q)) {
    return { answer: summary + (ordered.length ? ` The highest-ranked rule is "${ordered[0].rule}" (${ordered[0].severity}).` : '') + caveat(report), source };
  }
  if (/\b(scan|finding|findings|result|results|indicator|indicators|summary|count|how many|what did|show|report|explain)\b/i.test(q)) {
    return { answer: summary + (ordered.length ? ` First identified rule: "${ordered[0].rule}".` : ' No matching indicators were observed.') + caveat(report), source };
  }
  return {
    answer: 'I can answer questions about the last local scan, its severity counts, and recommended review steps. I cannot infer other facts from this limited report.',
    source
  };
}

if (typeof document !== 'undefined') {
  const byId = id => document.getElementById(id);
  const questionInput = byId('briefing-question');
  const ask = byId('briefing-ask');
  const mic = byId('briefing-mic');
  const stop = byId('briefing-stop');
  const read = byId('briefing-read');
  const answerBox = byId('briefing-answer');
  const sourceBox = byId('briefing-source');
  const statusBox = byId('briefing-status');
  let lastLocalReport = null;
  let lastAnswer = '';
  let recognition = null;
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

  function present(question) {
    const response = answerSecurityQuestion(question, lastLocalReport);
    lastAnswer = response.answer;
    answerBox.textContent = response.answer;
    sourceBox.textContent = response.source;
    read.disabled = !('speechSynthesis' in window) || !lastAnswer;
    statusBox.textContent = 'Read-only explanation. No security settings were changed.';
  }

  window.addEventListener('devshield:local-report', event => {
    lastLocalReport = event.detail && event.detail.schema === 'devshield.browser-preview.v1'
      ? event.detail : null;
    lastAnswer = '';
    answerBox.textContent = lastLocalReport
      ? 'A local scan is ready. Ask what it found or which indicator to review first.'
      : 'Run the local scan above, then ask a question about its findings.';
    sourceBox.textContent = lastLocalReport ? 'Latest browser-local scan available' : 'No scan available';
    read.disabled = true;
    statusBox.textContent = 'No website telemetry is connected.';
  });

  ask.addEventListener('click', () => present(questionInput.value));
  questionInput.addEventListener('keydown', event => {
    if (event.key === 'Enter') { event.preventDefault(); present(questionInput.value); }
  });
  for (const button of document.querySelectorAll('[data-briefing-question]')) {
    button.addEventListener('click', () => {
      questionInput.value = button.dataset.briefingQuestion;
      present(questionInput.value);
    });
  }

  if (!SpeechRecognition) {
    mic.disabled = true;
    mic.title = 'Speech recognition is unavailable in this browser; type your question instead.';
    statusBox.textContent = 'Microphone dictation unavailable in this browser. Text questions work.';
  } else {
    mic.addEventListener('click', () => {
      // Recognition is activated only by an explicit user gesture. The browser may
      // send audio to its speech provider; never dictate credentials.
      try {
        if (recognition) recognition.abort();
        recognition = new SpeechRecognition();
        recognition.lang = 'en-NG';
        recognition.interimResults = false;
        recognition.maxAlternatives = 1;
        recognition.onresult = event => {
          const transcript = event.results?.[0]?.[0]?.transcript;
          if (typeof transcript === 'string' && transcript.trim()) {
            questionInput.value = transcript.slice(0, 240);
            present(questionInput.value);
          }
        };
        recognition.onerror = () => {
          statusBox.textContent = 'Speech recognition failed or permission was denied. Type instead.';
        };
        recognition.onend = () => { recognition = null; };
        recognition.start();
        statusBox.textContent = 'Listening by request. Your browser may process audio through its speech provider.';
      } catch {
        statusBox.textContent = 'Speech recognition could not start. Type your question instead.';
      }
    });
  }
  read.addEventListener('click', () => {
    if (!lastAnswer || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(lastAnswer);
    utterance.lang = 'en-NG';
    utterance.rate = 0.95;
    window.speechSynthesis.speak(utterance);
    statusBox.textContent = 'Speaking the displayed answer.';
  });
  stop.addEventListener('click', () => {
    if (recognition) recognition.abort();
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
    statusBox.textContent = 'Voice stopped.';
  });
}
