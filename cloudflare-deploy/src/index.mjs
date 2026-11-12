// Public informational DevShield entry point and browser-local heuristic preview.
// Does not import Node scanner modules or expose any hosted scanning/billing APIs.
// Source pasted in the browser is processed in /app.js; this Worker never receives it.
const github = 'https://github.com/mabrig1/mabrig-devshield-ai';
const html = String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#080e19">
  <meta name="description" content="MABRIG DevShield AI — offline-first developer security checks, CI security, and supply-chain threat preflight.">
  <title>DevShield AI — Protect code before deployment</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/app.css">
  <script defer src="/app.js"></script>
</head>
<body>
  <a class="sr-only" href="#main">Skip to content</a>
  <header class="topbar"><div class="shell toprow">
    <a class="brand" href="/" aria-label="DevShield AI home"><span class="brandmark" aria-hidden="true">✓</span><span><small>MABRIG TECHNOLOGIES</small><strong>DevShield <span class="brand-accent">AI</span></strong></span></a>
    <nav class="nav" aria-label="Main navigation">
      <a href="#capabilities">Capabilities</a><a href="#scanner">Local scanner</a><a href="#getting-started">Get started</a><a href="#status">Platform status</a>
      <a class="button ghost" href="https://github.com/mabrig1/mabrig-devshield-ai" target="_blank" rel="noopener noreferrer">View GitHub ↗</a>
    </nav>
  </div></header>
  <main id="main">
    <section class="hero shell"><div class="hero-grid">
      <div>
        <div class="overline">DEVELOPER SECURITY · BEFORE THE FIRST COMMIT</div>
        <h1>Find threats before they <span class="glow">reach production.</span></h1>
        <p>Security checks for modern developers, AI-built software, and open-source projects. Inspect high-risk build hooks, credentials, and supply-chain indicators—without running untrusted code.</p>
        <div class="actions">
          <a class="button primary" href="#scanner">Try browser-local scan <span aria-hidden="true">↗</span></a>
          <a class="button" href="#getting-started">Set up DevShield CLI</a>
        </div>
        <div class="facts"><span class="fact"><span class="dot"></span> Offline-first</span><span class="fact"><span class="dot"></span> Open source</span><span class="fact"><span class="dot"></span> No code upload in the browser preview</span></div>
      </div>
      <div class="hero-visual" aria-label="Illustration of a developer security review interface">
        <div class="visual-header"><span class="bulb"></span><span class="bulb"></span><span class="bulb"></span><span class="visual-title">DEVSHIELD / SECURITY REVIEW</span></div>
        <div class="visual-body">
          <div class="overline">Threat preflight workflow</div><h3>Know what your project tries to do</h3>
          <div class="signal"><span class="num">01</span><span>Read files as untrusted data<small>Never install or execute unknown code</small></span></div>
          <div class="signal warn"><span class="num">02</span><span>Inspect suspicious indicators<small>Build hooks · encoded commands · secrets</small></span></div>
          <div class="signal"><span class="num">03</span><span>Review evidence and decide<small>Human-controlled remediation</small></span></div>
          <div class="terminal">$ devshield-preflight ./unknown-project
<span class="terminal-note"># Inspect first. Run only after review.</span></div>
        </div>
      </div>
    </div></section>
    <section class="section shell" id="capabilities">
      <div class="overline">FULL-LIFECYCLE SECURITY</div><h2 class="section-title">One workflow. Multiple defensive layers.</h2>
      <p class="section-desc">The public command-line tools and GitHub Action perform deeper checks than this browser preview. Enterprise cloud functionality is being developed separately and is not presented as live.</p>
      <div class="grid3">
        <article class="tile"><div class="tile-ico">⌘</div><h3>Repository preflight</h3><p>Screen suspicious build hooks, encoded PowerShell, supply-chain indicators, and other risky patterns without executing project code.</p><div class="eyebrow">CLI available</div></article>
        <article class="tile"><div class="tile-ico">◎</div><h3>Pull request security</h3><p>Integrate security policy and diff-aware checks into GitHub workflows, with documented findings and configurable thresholds.</p><div class="eyebrow">GitHub Action available</div></article>
        <article class="tile"><div class="tile-ico">⬡</div><h3>Security graph</h3><p>Trace relationships among files, dependencies and security evidence. Contextual edges are investigation clues, not exploitability proof.</p><div class="eyebrow">Repository tooling</div></article>
        <article class="tile"><div class="tile-ico">≋</div><h3>API and agent trust</h3><p>Review static API controls and AI-agent trust boundaries. Detect indicators requiring closer human security review.</p><div class="eyebrow">Repository tooling</div></article>
        <article class="tile"><div class="tile-ico">▣</div><h3>Developer endpoint guard</h3><p>An experimental read-only scanner for folders and downloads. Not a general antivirus, EDR, or live OS-level blocker.</p><div class="eyebrow future">Experimental</div></article>
        <article class="tile"><div class="tile-ico">↗</div><h3>Cloud Scan API</h3><p>Tenant reports, API credits, policies and managed scanning are under review. No public paid scanning service is active here.</p><div class="eyebrow future">In development</div></article>
      </div>
    </section>
    <section class="section shell" id="scanner">
      <div class="overline">TRY IT — IN YOUR BROWSER</div><h2 class="section-title">Local code indicator preview</h2>
      <p class="section-desc">Paste a snippet or select up to 30 small text files. The browser checks selected content in memory and does not send it to our server. This is a limited heuristic preview, not the full DevShield CLI or a malware certificate.</p>
      <div class="workstation">
        <div class="workstation-head"><div><h3>Quick security check</h3><p>Client-side static indicators · no execution · no uploads</p></div><span class="privacy">● Processing stays on this device</span></div>
        <div class="scanner-grid">
          <div class="editor">
            <div class="field-title"><label for="code-input">Source snippet</label></div>
            <textarea id="code-input" spellcheck="false" aria-label="Paste code to inspect" placeholder="Paste a short code snippet to check for common indicators…"></textarea>
            <div class="fileline"><label for="scan-files">Choose text files</label><input id="scan-files" type="file" multiple accept=".js,.jsx,.mjs,.cjs,.ts,.tsx,.json,.yml,.yaml,.ps1,.py,.go,.sh,.bat,.cmd,.txt,.env,.csproj" aria-label="Choose local files to inspect"></div>
            <div class="hint">Maximum 30 files, 256 KiB each. Executables, archives and large files require the installed offline scanner. Selected material never leaves your browser.</div>
            <div class="controls"><button id="scan-button" type="button" class="button primary">Run local preview</button><button id="reset-button" type="button" class="button">Clear</button><button id="export-button" type="button" class="button" disabled>Export JSON</button></div>
          </div>
          <div class="results" aria-live="polite" aria-atomic="false">
            <div class="field-title">Review results</div><h3 id="result-summary" class="report-status">Awaiting input</h3>
            <div id="findings" class="result-empty"><span class="big" aria-hidden="true">◇</span><h4>No scan has been run</h4><p>Paste code or choose local text files, then select Run local preview.</p></div>
            <div class="note" id="scan-status">No files or code leave this browser.</div>
          </div>
        </div>
      </div>
    </section>
    <section class="section shell" id="getting-started">
      <div class="overline">WORK WITH YOUR EXISTING STACK</div><h2 class="section-title">From a local project to safer builds.</h2>
      <div class="steps">
        <article class="step"><em>01</em><h3>Inspect before install</h3><p>Clone an untrusted repository into a disposable workspace. Run read-only preflight before installing dependencies.</p></article>
        <article class="step"><em>02</em><h3>Review findings</h3><p>Investigate network indicators and build scripts; remove hazards, rotate exposed keys, and decide whether code can be trusted.</p></article>
        <article class="step"><em>03</em><h3>Automate future checks</h3><p>Add the DevShield GitHub Action to pull requests with appropriately reviewed permission and policy settings.</p></article>
      </div>
      <h3 class="code-title">Run the local repository preflight</h3>
      <div class="codebar"><code>node bin/repository-preflight.mjs ./untrusted-project --fail-on high</code><a class="button" href="https://github.com/mabrig1/mabrig-devshield-ai" target="_blank" rel="noopener noreferrer">Get CLI ↗</a></div>
      <p class="hint small-top">Command runs from the DevShield repository. Inspect downloaded projects without launching install/build scripts.</p>
    </section>
    <section class="section shell" id="status">
      <div class="overline">TRANSPARENT STATUS</div><h2 class="section-title">What is available today?</h2>
      <div class="status-grid">
        <div class="status-tile"><div class="status-tag">● AVAILABLE IN REPOSITORY</div><b>Open-source Action and CLI</b><span>Source code, tests, documentation and optional security checks.</span></div>
        <div class="status-tile"><div class="status-tag">● AVAILABLE HERE</div><b>Browser-local indicator preview</b><span>A narrow set of static rules; no server-side scan or data upload.</span></div>
        <div class="status-tile"><div class="status-tag review">◐ NOT ACTIVE HERE</div><b>Managed cloud API and billing</b><span>Requires database provisioning, protected tenant accounts and production certification.</span></div>
      </div>
      <p class="note">A returned “no indicators observed” result is not proof that software is safe. Never run an untrusted repository solely because a preview shows no matches.</p>
    </section>
  </main>
  <footer class="footer"><div class="shell footrow">
    <span>© 2026 MABRIG Technologies · DevShield AI<br>Developer-native security, with people in control.</span>
    <div class="footlinks"><a href="https://github.com/mabrig1/mabrig-devshield-ai" target="_blank" rel="noopener noreferrer">GitHub</a><a href="https://github.com/mabrig1/mabrig-devshield-ai/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer">Report vulnerability</a><a href="https://github.com/mabrig1/mabrig-devshield-ai/blob/main/PRIVACY.md" target="_blank" rel="noopener noreferrer">Privacy</a><a href="mailto:victoryonline1@gmail.com">Contact</a></div>
  </div></footer>
</body>
</html>`;

const baseHeaders = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; font-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
};
function respond(content, type, status = 200, method = 'GET') {
  return new Response(method === 'HEAD' ? null : content, {
    status,
    headers: { ...baseHeaders, 'content-type': type }
  });
}
function json(body, status, method) {
  return respond(JSON.stringify(body), 'application/json; charset=utf-8', status, method);
}
export default {
  async fetch(request, env = {}) {
    const url = new URL(request.url);
    const method = request.method;
    if (method !== 'GET' && method !== 'HEAD') {
      return json({ error: 'method_not_allowed' }, 405, method);
    }
    if (url.pathname === '/health') {
      return json({
        ok: true,
        component: 'DevShield Website',
        website: 'available',
        browserPreview: 'client-only',
        hostedScanning: false,
        billing: false
      }, 200, method);
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return respond(html, 'text/html; charset=utf-8', 200, method);
    }
    if (['/app.css', '/app.js', '/favicon.svg'].includes(url.pathname)) {
      if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') {
        return json({ error: 'assets_not_configured' }, 503, method);
      }
      return env.ASSETS.fetch(request);
    }
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/v1/')) {
      return json({ error: 'api_not_configured' }, 503, method);
    }
    return json({ error: 'not_found' }, 404, method);
  }
};
