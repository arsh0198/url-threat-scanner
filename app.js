/* ── ThreatScan Frontend ── */

// Point this at your Render backend URL after deploying
// e.g. "https://threatscan-api.onrender.com"
// Leave empty string to run purely client-side heuristics
const BACKEND_URL = '';

const SUSPICIOUS_TLDS = ['xyz','top','click','tk','ml','ga','cf','gq','pw','buzz','loan','download','zip','mov','monster','rest','icu','vip'];
const URL_SHORTENERS  = ['bit.ly','tinyurl.com','t.co','ow.ly','goo.gl','is.gd','buff.ly','rebrand.ly','cutt.ly','short.io','rb.gy','tiny.cc'];
const PHISH_KEYWORDS  = ['login','signin','account','verify','update','secure','banking','paypal','amazon','apple','microsoft','google','facebook','netflix','password','wallet','confirm','suspend','unlock','ebay','chase','wellsfargo','coinbase'];
const MALWARE_WORDS   = ['download','install','setup','crack','keygen','torrent','warez','free-download','nulled','serial','patch','loader'];
const HOMOGLYPH_RE    = /[а-яёА-ЯЁ\u0400-\u04FF\u0370-\u03FF]/;
const TYPOSQUAT_BRANDS = ['google','microsoft','apple','amazon','facebook','instagram','twitter','netflix','paypal','ebay','github','linkedin','dropbox','spotify'];

let scanHistory = JSON.parse(localStorage.getItem('threatscan_history') || '[]');
let currentScan = null;

/* ── Helpers ── */
function ts() {
  return new Date().toTimeString().slice(0,8);
}
function log(msg, type='info') {
  const wrap = document.getElementById('terminalLog');
  if (!wrap) return;
  const cls = { info:'log-info', ok:'log-ok', warn:'log-warn', bad:'log-bad' }[type] || '';
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="log-time">[${ts()}]</span><span class="${cls}">${msg}</span>`;
  wrap.appendChild(line);
  wrap.scrollTop = wrap.scrollHeight;
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function loadExample(url) {
  document.getElementById('urlInput').value = url;
}

/* ── Main scan ── */
async function startScan() {
  let raw = document.getElementById('urlInput').value.trim();
  if (!raw) return;
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('results').style.display = 'none';
  document.getElementById('terminalWrap').style.display = 'block';
  document.getElementById('terminalLog').innerHTML = '';

  log(`Initializing scan for: ${raw}`, 'info');
  await sleep(300);

  let result;
  if (BACKEND_URL) {
    result = await backendScan(raw);
  } else {
    result = await clientScan(raw);
  }

  currentScan = result;
  showResults(result, raw);
  addHistory(raw, result);

  document.getElementById('scanBtn').disabled = false;
}

/* ── Client-side heuristic scan ── */
async function clientScan(url) {
  let checks = [];
  let riskScore = 0;

  let parsed;
  try { parsed = new URL(url); }
  catch(e) {
    log('ERROR: Invalid URL format', 'bad');
    return { verdict:'danger', score:100, checks:[{ name:'Invalid URL', desc:'Could not parse URL.', status:'bad', icon:'💀' }], dns:{}, ssl:{}, redirects:[], recs:[] };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = url.toLowerCase();
  const path     = parsed.pathname + parsed.search;
  const tldParts = hostname.split('.');
  const tld      = tldParts[tldParts.length - 1];

  log(`Target: ${hostname}`, 'info');
  await sleep(200);
  log('Running heuristic checks...', 'info');

  // 1. HTTPS
  await sleep(120);
  const isHttps = parsed.protocol === 'https:';
  log(`Protocol: ${parsed.protocol} ${isHttps ? '✓' : '⚠'}`, isHttps ? 'ok' : 'warn');
  checks.push({ name: isHttps ? 'HTTPS Secured' : 'No HTTPS', desc: isHttps ? 'Connection is encrypted.' : 'Unencrypted HTTP — data can be intercepted.', status: isHttps ? 'ok' : 'warn', icon: isHttps ? '🔒' : '🔓' });
  if (!isHttps) riskScore += 20;

  // 2. IP host
  await sleep(100);
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  log(`Host type: ${isIP ? 'RAW IP (suspicious)' : 'domain'}`, isIP ? 'bad' : 'ok');
  checks.push({ name: isIP ? 'IP Address as Host' : 'Domain Name Used', desc: isIP ? 'Raw IP addresses are commonly used in phishing attacks.' : 'Domain name in use — no IP spoofing detected.', status: isIP ? 'bad' : 'ok', icon: isIP ? '🚨' : '🌐' });
  if (isIP) riskScore += 35;

  // 3. TLD
  await sleep(100);
  const badTLD = SUSPICIOUS_TLDS.includes(tld);
  log(`TLD: .${tld} ${badTLD ? '— risky' : '— ok'}`, badTLD ? 'warn' : 'ok');
  checks.push({ name: badTLD ? `Risky TLD (.${tld})` : `TLD Normal (.${tld})`, desc: badTLD ? `".${tld}" is commonly used in malicious sites.` : 'Top-level domain appears legitimate.', status: badTLD ? 'warn' : 'ok', icon: badTLD ? '⚠️' : '✅' });
  if (badTLD) riskScore += 20;

  // 4. URL shortener
  await sleep(100);
  const isShort = URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.'+s));
  log(`Shortener: ${isShort ? 'detected' : 'none'}`, isShort ? 'warn' : 'ok');
  checks.push({ name: isShort ? 'URL Shortener' : 'No URL Shortener', desc: isShort ? 'Shorteners mask real destinations — common in phishing.' : 'Full URL visible — no shortener masking.', status: isShort ? 'warn' : 'ok', icon: isShort ? '🔗' : '✅' });
  if (isShort) riskScore += 25;

  // 5. Phishing keywords
  await sleep(150);
  const phishHits = PHISH_KEYWORDS.filter(k => fullUrl.includes(k));
  log(`Phishing keywords: ${phishHits.length > 0 ? phishHits.join(', ') : 'none'}`, phishHits.length ? 'bad' : 'ok');
  checks.push({ name: phishHits.length ? `Phishing Keywords (${phishHits.length})` : 'No Phishing Keywords', desc: phishHits.length ? `Found: ${phishHits.slice(0,3).join(', ')}` : 'No phishing-related keywords detected.', status: phishHits.length ? 'bad' : 'ok', icon: phishHits.length ? '🎣' : '✅' });
  if (phishHits.length) riskScore += Math.min(phishHits.length * 12, 40);

  // 6. Malware keywords
  await sleep(100);
  const malHits = MALWARE_WORDS.filter(k => fullUrl.includes(k));
  checks.push({ name: malHits.length ? `Malware Indicators (${malHits.length})` : 'No Malware Indicators', desc: malHits.length ? `Flagged: ${malHits.slice(0,3).join(', ')}` : 'No malware-related keywords detected.', status: malHits.length ? 'bad' : 'ok', icon: malHits.length ? '🦠' : '✅' });
  if (malHits.length) riskScore += Math.min(malHits.length * 10, 30);

  // 7. Homoglyph
  await sleep(100);
  const hasHomo = HOMOGLYPH_RE.test(hostname);
  log(`Homoglyph check: ${hasHomo ? 'DETECTED' : 'clean'}`, hasHomo ? 'bad' : 'ok');
  checks.push({ name: hasHomo ? 'Homoglyph Attack' : 'No Homoglyphs', desc: hasHomo ? 'Non-Latin characters used to spoof legitimate domains.' : 'No character substitution tricks detected.', status: hasHomo ? 'bad' : 'ok', icon: hasHomo ? '🎭' : '✅' });
  if (hasHomo) riskScore += 40;

  // 8. Typosquatting
  await sleep(100);
  const typoHit = TYPOSQUAT_BRANDS.find(b => {
    if (hostname.includes(b)) return false; // exact match is fine
    const clean = hostname.replace(/[^a-z]/g,'');
    return levenshtein(clean, b) <= 2 && clean !== b && clean.length > 3;
  });
  checks.push({ name: typoHit ? `Typosquatting (≈${typoHit})` : 'No Typosquatting', desc: typoHit ? `Domain closely resembles "${typoHit}" — possible brand impersonation.` : 'Domain name does not impersonate known brands.', status: typoHit ? 'bad' : 'ok', icon: typoHit ? '👥' : '✅' });
  if (typoHit) riskScore += 35;

  // 9. Long hostname
  await sleep(80);
  const longHost = hostname.length > 40;
  checks.push({ name: longHost ? `Long Hostname (${hostname.length}c)` : 'Hostname Length OK', desc: longHost ? 'Unusually long hostnames are often used to obfuscate.' : 'Hostname length is within normal range.', status: longHost ? 'warn' : 'ok', icon: longHost ? '📏' : '✅' });
  if (longHost) riskScore += 15;

  // 10. Subdomain depth
  await sleep(80);
  const subCount = tldParts.length - 2;
  const manySubdomains = subCount > 2;
  checks.push({ name: manySubdomains ? `Deep Subdomains (${subCount})` : 'Subdomain Depth OK', desc: manySubdomains ? `${subCount} subdomain levels — often used to mislead.` : 'Subdomain structure looks normal.', status: manySubdomains ? 'warn' : 'ok', icon: manySubdomains ? '🗂️' : '✅' });
  if (manySubdomains) riskScore += 15;

  // 11. URL encoding
  await sleep(80);
  const encCount  = (path.match(/%[0-9a-f]{2}/gi) || []).length;
  const heavyEnc  = encCount > 4;
  checks.push({ name: heavyEnc ? `Heavy URL Encoding (${encCount})` : 'Encoding Normal', desc: heavyEnc ? 'Excessive percent-encoding may hide malicious content.' : 'URL encoding is within normal range.', status: heavyEnc ? 'warn' : 'ok', icon: heavyEnc ? '🔢' : '✅' });
  if (heavyEnc) riskScore += 15;

  // 12. @ trick
  await sleep(80);
  const hasAt = parsed.username !== '';
  checks.push({ name: hasAt ? 'Credential Trick (@)' : 'No @ Trick', desc: hasAt ? 'URL uses @ to hide real destination before the symbol.' : 'No credential trick found in URL.', status: hasAt ? 'bad' : 'ok', icon: hasAt ? '🪤' : '✅' });
  if (hasAt) riskScore += 30;

  riskScore = Math.min(Math.round(riskScore), 100);
  const verdict = riskScore >= 60 ? 'danger' : riskScore >= 25 ? 'warning' : 'safe';

  log(`Scan complete. Risk score: ${riskScore}/100`, verdict === 'safe' ? 'ok' : verdict === 'warning' ? 'warn' : 'bad');
  await sleep(200);
  log(`Verdict: ${verdict.toUpperCase()}`, verdict === 'safe' ? 'ok' : verdict === 'warning' ? 'warn' : 'bad');

  // Build DNS/SSL info from URL parsing (no real DNS without backend)
  const dns = {
    hostname,
    protocol: parsed.protocol.replace(':',''),
    port: parsed.port || (isHttps ? '443' : '80'),
    path: parsed.pathname || '/',
    tld: `.${tld}`,
    subdomains: subCount > 0 ? tldParts.slice(0, -2).join('.') : '—',
  };

  const ssl = isHttps ? {
    status: 'Present',
    protocol: 'HTTPS',
    note: 'SSL certificate exists (backend needed for details)',
  } : {
    status: 'Missing',
    protocol: 'HTTP',
    note: 'No SSL — connection is plaintext',
  };

  const recs = buildRecs(verdict, checks, riskScore);

  return { verdict, score: riskScore, checks, dns, ssl, redirects: [], recs };
}

/* ── Backend scan (when BACKEND_URL is set) ── */
async function backendScan(url) {
  log('Connecting to scan API...', 'info');
  try {
    const res  = await fetch(`${BACKEND_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    log('Backend analysis complete.', 'ok');
    return data;
  } catch(e) {
    log('Backend unreachable — falling back to client-side scan.', 'warn');
    return clientScan(url);
  }
}

/* ── Levenshtein distance ── */
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

/* ── Build recommendations ── */
function buildRecs(verdict, checks, score) {
  const recs = [];
  const bad  = checks.filter(c => c.status === 'bad');
  const warn = checks.filter(c => c.status === 'warn');

  if (verdict === 'danger')  recs.push({ icon:'🚫', text:'Do not visit this URL. High probability of phishing or malware.' });
  if (verdict === 'warning') recs.push({ icon:'⚠️', text:'Proceed with extreme caution. Verify the source independently before visiting.' });
  if (verdict === 'safe')    recs.push({ icon:'✅', text:'URL appears safe based on heuristic analysis. Always stay vigilant.' });

  if (bad.some(c => c.name.includes('Phishing')))   recs.push({ icon:'🎣', text:'Phishing keywords detected. Never enter credentials on this page.' });
  if (bad.some(c => c.name.includes('Typosquat')))  recs.push({ icon:'👥', text:'Domain may be impersonating a known brand. Double-check the URL carefully.' });
  if (bad.some(c => c.name.includes('Homoglyph'))) recs.push({ icon:'🎭', text:'Homoglyph attack suspected. Characters look similar but are different Unicode symbols.' });
  if (warn.some(c => c.name.includes('Shortener'))) recs.push({ icon:'🔗', text:'URL shortener hides the real destination. Use a link expander to preview.' });
  if (warn.some(c => c.name.includes('HTTPS')))     recs.push({ icon:'🔓', text:'Connection is not encrypted. Never submit personal data over HTTP.' });

  if (score === 0) recs.push({ icon:'💡', text:'For definitive analysis, pair with VirusTotal or Google Safe Browsing.' });

  return recs;
}

/* ── Render results ── */
function showResults(result, rawUrl) {
  const { verdict, score, checks, dns, ssl, redirects, recs } = result;

  // Verdict banner
  const banner = document.getElementById('verdictBanner');
  banner.className = `verdict-banner ${verdict}`;
  const icons   = { safe: '🛡️', warning: '⚠️', danger: '☠️' };
  const labels  = { safe: 'SAFE', warning: 'SUSPICIOUS', danger: 'DANGEROUS' };
  const colorCl = { safe: 'safe-color', warning: 'warn-color', danger: 'danger-color' };
  document.getElementById('verdictIcon').textContent  = icons[verdict];
  document.getElementById('verdictLabel').textContent = labels[verdict];
  document.getElementById('verdictLabel').className   = `verdict-label ${colorCl[verdict]}`;
  document.getElementById('verdictUrl').textContent   = rawUrl.length > 60 ? rawUrl.slice(0,60)+'…' : rawUrl;
  document.getElementById('riskScore').textContent    = score;
  document.getElementById('riskScore').className      = `risk-score ${colorCl[verdict]}`;

  // Score bar
  const barColor = verdict === 'safe' ? 'var(--safe)' : verdict === 'warning' ? 'var(--warn)' : 'var(--danger)';
  const bar = document.getElementById('scoreBar');
  bar.style.width      = '0%';
  bar.style.background = barColor;
  setTimeout(() => { bar.style.width = score + '%'; }, 80);

  // Stats
  const badCount  = checks.filter(c => c.status === 'bad').length;
  const warnCount = checks.filter(c => c.status === 'warn').length;
  const okCount   = checks.filter(c => c.status === 'ok').length;
  document.getElementById('statsRow').innerHTML = [
    { val: score,     key: 'RISK SCORE',  color: colorCl[verdict] },
    { val: checks.length, key: 'CHECKS RUN', color: '' },
    { val: badCount,  key: 'THREATS',     color: badCount  ? 'danger-color' : '' },
    { val: warnCount, key: 'WARNINGS',    color: warnCount ? 'warn-color'   : '' },
    { val: okCount,   key: 'PASSED',      color: okCount   ? 'safe-color'   : '' },
  ].map(s => `
    <div class="stat-card">
      <div class="stat-val ${s.color}">${s.val}</div>
      <div class="stat-key">${s.key}</div>
    </div>`).join('');

  // Checks
  document.getElementById('checksGrid').innerHTML = checks.map(c => {
    const col = c.status === 'ok' ? '#00ffaa' : c.status === 'warn' ? '#ffaa00' : '#ff4444';
    return `
      <div class="check-card" style="border-left: 3px solid ${col}">
        <div class="check-icon">${c.icon}</div>
        <div class="check-info">
          <div class="check-name" style="color:${col}">${c.name}</div>
          <div class="check-desc">${c.desc}</div>
        </div>
      </div>`;
  }).join('');

  // DNS
  document.getElementById('dnsContent').innerHTML = dns && Object.keys(dns).length
    ? Object.entries(dns).map(([k,v]) => `
        <div class="panel-row">
          <span class="panel-key">${k}</span>
          <span class="panel-val">${v}</span>
        </div>`).join('')
    : '<div class="panel-empty">No DNS data (backend needed)</div>';

  // SSL
  document.getElementById('sslContent').innerHTML = ssl && Object.keys(ssl).length
    ? Object.entries(ssl).map(([k,v]) => `
        <div class="panel-row">
          <span class="panel-key">${k}</span>
          <span class="panel-val">${v}</span>
        </div>`).join('')
    : '<div class="panel-empty">No SSL data (backend needed)</div>';

  // Redirects
  document.getElementById('redirectContent').innerHTML = redirects && redirects.length
    ? redirects.map((r,i) => `
        <div class="panel-row">
          <span class="panel-key">${i+1}</span>
          <span class="panel-val">${r}</span>
        </div>`).join('')
    : '<div class="panel-empty">No redirects detected</div>';

  // Recs
  document.getElementById('recsList').innerHTML = recs.map(r =>
    `<div class="rec-item"><span class="rec-bullet">${r.icon}</span><span>${r.text}</span></div>`
  ).join('');

  document.getElementById('results').style.display = 'block';
  document.getElementById('results').scrollIntoView({ behavior:'smooth', block:'start' });
}

/* ── History ── */
function addHistory(url, result) {
  scanHistory = [
    { url, verdict: result.verdict, score: result.score, time: new Date().toLocaleTimeString() },
    ...scanHistory.filter(h => h.url !== url)
  ].slice(0, 8);
  localStorage.setItem('threatscan_history', JSON.stringify(scanHistory));
  renderHistory();
}

function renderHistory() {
  const sec  = document.getElementById('historySection');
  const list = document.getElementById('historyList');
  if (!scanHistory.length) { sec.style.display = 'none'; return; }
  sec.style.display = 'block';
  const icons  = { safe:'🛡️', warning:'⚠️', danger:'☠️' };
  const colors = { safe:'#00ffaa', warning:'#ffaa00', danger:'#ff4444' };
  list.innerHTML = scanHistory.map(h => {
    const label = h.url.replace(/^https?:\/\//, '').slice(0, 50);
    return `
      <div class="history-item" onclick="rerunScan('${h.url.replace(/'/g,"\\'")}')">
        <span class="history-verdict">${icons[h.verdict]}</span>
        <span class="history-url">${label}</span>
        <span class="history-score" style="color:${colors[h.verdict]}">${h.score}/100</span>
        <span class="history-time">${h.time}</span>
      </div>`;
  }).join('');
}

function rerunScan(url) {
  document.getElementById('urlInput').value = url;
  startScan();
}

/* ── Keyboard ── */
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

/* ── Init ── */
renderHistory();
