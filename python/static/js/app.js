/* ── State ──────────────────────────────────── */

let currentJobId = null;

/* ── DOM refs ───────────────────────────────── */

const urlInput      = document.getElementById('urlInput');
const analyzeBtn    = document.getElementById('analyzeBtn');
const clearBtn      = document.getElementById('clearBtn');
const refreshBtn    = document.getElementById('statusGroup');
const statusDot     = document.getElementById('statusDot');
const statusLabel   = document.getElementById('statusLabel');
const statusBar     = document.getElementById('statusBar');
const emptyState    = document.getElementById('emptyState');
const loadingState  = document.getElementById('loadingState');
const loadingStep   = document.getElementById('loadingStep');
const errorState    = document.getElementById('errorState');
const errorTitle    = document.getElementById('errorTitle');
const errorSub      = document.getElementById('errorSub');
const results       = document.getElementById('results');
const exportPdfBtn  = document.getElementById('exportPdfBtn');
const viewCloneBtn  = document.getElementById('viewCloneBtn');

/* ── Utility ────────────────────────────────── */

function setStatus(msg) {
  statusBar.textContent = msg;
}

function setLoadingStep(text) {
  loadingStep.innerHTML = '<span class="terminal-cursor"></span>' + text;
}

function buildBarText(score) {
  const total = 10;
  const filled = Math.round((score / 100) * total);
  const empty  = total - filled;
  return '█'.repeat(filled) + '░'.repeat(empty);
}

function scoreColor(score) {
  if (score <= 20) return '#16a34a';
  if (score <= 40) return '#0d9488';
  if (score <= 60) return '#d97706';
  if (score <= 80) return '#dc2626';
  return '#7f1d1d';
}

function verdictClass(verdict) {
  if (!verdict) return '';
  const v = verdict.toLowerCase();
  if (v === 'safe')     return 'safe';
  if (v === 'low')      return 'low';
  if (v === 'moderate') return 'moderate';
  if (v === 'high')     return 'high';
  if (v === 'critical') return 'critical';
  return '';
}

function showPanel(name) {
  emptyState.style.display   = 'none';
  loadingState.style.display = 'none';
  errorState.style.display   = 'none';
  results.style.display      = 'none';

  if (name === 'empty')   emptyState.style.display   = 'flex';
  if (name === 'loading') loadingState.style.display = 'flex';
  if (name === 'error')   errorState.style.display   = 'flex';
  if (name === 'results') results.style.display      = 'flex';
}

/* ── Health Check ───────────────────────────── */

async function checkHealth() {
  try {
    const res = await fetch('/health');
    if (res.ok) {
      statusDot.className     = 'status-dot online';
      statusLabel.textContent = 'online';
    } else {
      throw new Error('non-ok');
    }
  } catch {
    statusDot.className     = 'status-dot offline';
    statusLabel.textContent = 'offline';
  }
}

checkHealth();
setInterval(checkHealth, 30000);
refreshBtn.addEventListener('click', checkHealth);

/* ── Analyze ────────────────────────────────── */

async function analyze() {
  let url = urlInput.value.trim();
  if (!url) {
    urlInput.focus();
    return;
  }

  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
    urlInput.value = url;
  }

  currentJobId = null;
  exportPdfBtn.disabled = true;
  viewCloneBtn.disabled = true;
  clearBtn.style.display = 'none';
  analyzeBtn.disabled = true;

  showPanel('loading');
  setLoadingStep('→ Fetching page...');
  setStatus('Starting analysis for ' + url);

  try {
    /* Step 1 — clone */
    const cloneRes = await fetch('/clone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!cloneRes.ok) {
      const err = await cloneRes.json().catch(() => ({ detail: 'Clone failed' }));
      throw new Error(err.detail || 'Clone request failed');
    }

    const cloneData = await cloneRes.json();
    currentJobId = cloneData.job_id;

    /* Step 2 — report */
    setLoadingStep('→ Running AI analysis...');
    setStatus('Fetching report for job ' + currentJobId);

    const reportRes = await fetch('/report/' + currentJobId);
    if (!reportRes.ok) {
      const err = await reportRes.json().catch(() => ({ detail: 'Report not found' }));
      throw new Error(err.detail || 'Could not retrieve report');
    }

    const report = await reportRes.json();
    renderReport(report);
    showPanel('results');
    clearBtn.style.display = '';
    setStatus('Analysis complete — job ' + currentJobId);

  } catch (err) {
    errorTitle.textContent = 'Analysis failed';
    errorSub.textContent   = err.message || 'An unexpected error occurred. Please try again.';
    showPanel('error');
    clearBtn.style.display = '';
    setStatus('Error: ' + (err.message || 'unknown'));
  } finally {
    analyzeBtn.disabled = false;
  }
}

analyzeBtn.addEventListener('click', analyze);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyze(); });

/* ── Render Report ──────────────────────────── */

function renderReport(report) {
  const risk      = report.phishing_risk || {};
  const clone     = report.clone        || {};
  const intel     = report.intelligence || {};
  const score     = risk.score ?? 0;
  const verdict   = risk.verdict ?? 'Unknown';
  const color     = scoreColor(score);

  /* Score + bar */
  const riskScore = document.getElementById('riskScore');
  riskScore.textContent = score;
  riskScore.style.color = color;

  document.getElementById('scoreBarText').textContent = buildBarText(score);

  const badge = document.getElementById('verdictBadge');
  badge.textContent = verdict;
  badge.className   = 'verdict-pill ' + verdictClass(verdict);

  /* Clone info */
  document.getElementById('infoTitle').textContent      = clone.page_title      || '—';
  document.getElementById('infoFetcher').textContent    = clone.fetcher_used    || '—';
  document.getElementById('infoAssetsOk').textContent   = clone.assets_downloaded ?? '—';
  document.getElementById('infoAssetsFail').textContent = clone.assets_failed   ?? '—';
  document.getElementById('infoForms').textContent      = clone.forms_found     ?? '—';
  document.getElementById('infoLinks').textContent      = clone.links_found     ?? '—';

  /* Page intelligence */
  const techStack = Array.isArray(intel.tech_stack) && intel.tech_stack.length
    ? intel.tech_stack.join(', ')
    : (intel.tech_stack || '—');

  document.getElementById('infoPageType').textContent  = intel.page_type      || '—';
  document.getElementById('infoTechStack').textContent = techStack;
  document.getElementById('infoExtLinks').textContent  = intel.external_links ?? '—';
  document.getElementById('infoIntLinks').textContent  = intel.internal_links ?? '—';
  document.getElementById('infoSummary').textContent   = intel.summary        || '—';

  /* Red flags */
  const redFlagsCard = document.getElementById('redFlagsCard');
  const redFlagList  = document.getElementById('redFlagList');
  const flags = risk.red_flags || [];

  redFlagList.innerHTML = '';
  if (flags.length > 0) {
    flags.forEach(flag => {
      const li = document.createElement('li');
      li.className = 'red-flag-item';
      li.textContent = flag;
      redFlagList.appendChild(li);
    });
    redFlagsCard.style.display = '';
  } else {
    redFlagsCard.style.display = 'none';
  }

  /* Assessment */
  document.getElementById('assessmentText').textContent = risk.explanation || '—';

  /* Enable action buttons */
  exportPdfBtn.disabled = false;
  viewCloneBtn.disabled = false;
}

/* ── Export PDF ─────────────────────────────── */

async function exportPdf() {
  if (!currentJobId) return;
  setStatus('Downloading PDF report...');

  try {
    const res = await fetch('/report/' + currentJobId + '/pdf');
    if (!res.ok) throw new Error('PDF generation failed');

    const blob     = await res.blob();
    const blobUrl  = URL.createObjectURL(blob);
    const anchor   = document.createElement('a');
    anchor.href     = blobUrl;
    anchor.download = 'weblens-report-' + currentJobId.slice(0, 8) + '.pdf';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(blobUrl);
    setStatus('PDF downloaded.');
  } catch (err) {
    setStatus('PDF error: ' + err.message);
  }
}

exportPdfBtn.addEventListener('click', exportPdf);

/* ── View Clone ─────────────────────────────── */

function viewClone() {
  if (!currentJobId) return;
  console.log('Opening clone for job:', currentJobId);
  window.open('http://localhost:8000/clone/' + currentJobId, '_blank');
}

viewCloneBtn.addEventListener('click', viewClone);

/* ── Clear ──────────────────────────────────── */

function clearAll() {
  currentJobId = null;
  urlInput.value = '';
  exportPdfBtn.disabled = true;
  viewCloneBtn.disabled = true;
  clearBtn.style.display = 'none';
  analyzeBtn.disabled = false;

  document.getElementById('scoreBarText').textContent = '';

  showPanel('empty');
  setStatus('');
}

clearBtn.addEventListener('click', clearAll);
