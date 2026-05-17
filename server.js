/**
 * ThreatScan API — Backend Server
 * Author: Arsh Abbasi (github.com/arsh0198)
 *
 * Deploy free on Render.com:
 * 1. Push this repo to GitHub
 * 2. New Web Service on Render → connect repo
 * 3. Build command: npm install
 * 4. Start command: node server.js
 * 5. Add env var: VIRUSTOTAL_API_KEY (get free at virustotal.com)
 * 6. Copy your Render URL into public/app.js → BACKEND_URL
 */

const express  = require('express');
const cors     = require('cors');
const dns      = require('dns').promises;
const https    = require('https');
const http     = require('http');
const { URL }  = require('url');
const tls      = require('tls');

const app  = express();
const PORT = process.env.PORT || 3000;

const VT_KEY = process.env.VIRUSTOTAL_API_KEY || '';

// ── Middleware ──
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// ── Constants ──
const SUSPICIOUS_TLDS  = ['xyz','top','click','tk','ml','ga','cf','gq','pw','buzz','loan','download','zip','mov','monster','rest','icu','vip'];
const URL_SHORTENERS   = ['bit.ly','tinyurl.com','t.co','ow.ly','goo.gl','is.gd','buff.ly','rebrand.ly','cutt.ly','short.io','rb.gy','tiny.cc'];
const PHISH_KEYWORDS   = ['login','signin','account','verify','update','secure','banking','paypal','amazon','apple','microsoft','google','facebook','netflix','password','wallet','confirm','suspend','unlock','ebay','chase','wellsfargo','coinbase'];
const MALWARE_WORDS    = ['download','install','setup','crack','keygen','torrent','warez','free-download','nulled','serial','patch','loader'];
const HOMOGLYPH_RE     = /[а-яёА-ЯЁ\u0400-\u04FF\u0370-\u03FF]/;
const TYPOSQUAT_BRANDS = ['google','microsoft','apple','amazon','facebook','instagram','twitter','netflix','paypal','ebay','github','linkedin','dropbox','spotify'];

// ── Levenshtein ──
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

// ── DNS Lookup ──
async function getDNSInfo(hostname) {
  const result = {};
  try {
    const addresses = await dns.resolve4(hostname).catch(() => []);
    result.ipv4 = addresses[0] || 'N/A';
    const mx = await dns.resolveMx(hostname).catch(() => []);
    result.mx = mx.length ? mx[0].exchange : 'None';
    const ns = await dns.resolveNs(hostname).catch(() => []);
    result.nameserver = ns[0] || 'N/A';
    const txt = await dns.resolveTxt(hostname).catch(() => []);
    result.spf = txt.flat().find(r => r.startsWith('v=spf')) ? 'Present' : 'Missing';
  } catch (e) {
    result.error = 'DNS lookup failed';
  }
  return result;
}

// ── SSL Info ──
async function getSSLInfo(hostname) {
  return new Promise((resolve) => {
    const options = { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false };
    const socket  = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();
      if (!cert || !cert.subject) return resolve({ status: 'No certificate' });
      resolve({
        status:   'Valid',
        issuer:   cert.issuer?.O || 'Unknown',
        subject:  cert.subject?.CN || hostname,
        expires:  cert.valid_to || 'Unknown',
        protocol: socket.getProtocol() || 'TLS',
      });
    });
    socket.on('error', () => resolve({ status: 'SSL check failed' }));
    setTimeout(() => { socket.destroy(); resolve({ status: 'Timeout' }); }, 5000);
  });
}

// ── Redirect Chain ──
async function followRedirects(urlStr, maxHops = 5) {
  const chain = [urlStr];
  let current = urlStr;

  for (let i = 0; i < maxHops; i++) {
    const loc = await getRedirectLocation(current);
    if (!loc || loc === current) break;
    chain.push(loc);
    current = loc;
  }
  return chain;
}

function getRedirectLocation(urlStr) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(urlStr);
      const mod    = parsed.protocol === 'https:' ? https : http;
      const req    = mod.get(urlStr, { timeout: 5000, headers: { 'User-Agent': 'ThreatScan/2.0' } }, res => {
        const loc = res.headers.location;
        req.destroy();
        resolve(loc ? (loc.startsWith('http') ? loc : new URL(loc, urlStr).href) : null);
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    } catch(e) { resolve(null); }
  });
}

// ── VirusTotal ──
async function checkVirusTotal(url) {
  if (!VT_KEY) return null;
  try {
    const encoded = Buffer.from(url).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    const res     = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: { 'x-apikey': VT_KEY }
    });
    if (!res.ok) return null;
    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) return null;
    return {
      malicious:  stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless || 0,
      undetected: stats.undetected || 0,
    };
  } catch(e) { return null; }
}

// ── Heuristic checks ──
function runHeuristics(url) {
  let checks = [];
  let riskScore = 0;
  const parsed   = new URL(url);
  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = url.toLowerCase();
  const path     = parsed.pathname + parsed.search;
  const tldParts = hostname.split('.');
  const tld      = tldParts[tldParts.length - 1];

  const isHttps = parsed.protocol === 'https:';
  checks.push({ name: isHttps ? 'HTTPS Secured' : 'No HTTPS', desc: isHttps ? 'Connection encrypted.' : 'Unencrypted HTTP.', status: isHttps ? 'ok' : 'warn', icon: isHttps ? '🔒' : '🔓' });
  if (!isHttps) riskScore += 20;

  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  checks.push({ name: isIP ? 'IP Address as Host' : 'Domain Name Used', desc: isIP ? 'Raw IP used — common in phishing.' : 'Domain name in use.', status: isIP ? 'bad' : 'ok', icon: isIP ? '🚨' : '🌐' });
  if (isIP) riskScore += 35;

  const badTLD = SUSPICIOUS_TLDS.includes(tld);
  checks.push({ name: badTLD ? `Risky TLD (.${tld})` : `TLD Normal (.${tld})`, desc: badTLD ? `".${tld}" is high-risk.` : 'TLD appears legitimate.', status: badTLD ? 'warn' : 'ok', icon: badTLD ? '⚠️' : '✅' });
  if (badTLD) riskScore += 20;

  const isShort = URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.'+s));
  checks.push({ name: isShort ? 'URL Shortener' : 'No URL Shortener', desc: isShort ? 'Shorteners mask real destinations.' : 'No shortener masking.', status: isShort ? 'warn' : 'ok', icon: isShort ? '🔗' : '✅' });
  if (isShort) riskScore += 25;

  const phishHits = PHISH_KEYWORDS.filter(k => fullUrl.includes(k));
  checks.push({ name: phishHits.length ? `Phishing Keywords (${phishHits.length})` : 'No Phishing Keywords', desc: phishHits.length ? `Found: ${phishHits.slice(0,3).join(', ')}` : 'None detected.', status: phishHits.length ? 'bad' : 'ok', icon: phishHits.length ? '🎣' : '✅' });
  if (phishHits.length) riskScore += Math.min(phishHits.length * 12, 40);

  const malHits = MALWARE_WORDS.filter(k => fullUrl.includes(k));
  checks.push({ name: malHits.length ? `Malware Indicators (${malHits.length})` : 'No Malware Indicators', desc: malHits.length ? `Found: ${malHits.slice(0,3).join(', ')}` : 'None detected.', status: malHits.length ? 'bad' : 'ok', icon: malHits.length ? '🦠' : '✅' });
  if (malHits.length) riskScore += Math.min(malHits.length * 10, 30);

  const hasHomo = HOMOGLYPH_RE.test(hostname);
  checks.push({ name: hasHomo ? 'Homoglyph Attack' : 'No Homoglyphs', desc: hasHomo ? 'Non-Latin chars detected.' : 'No character tricks.', status: hasHomo ? 'bad' : 'ok', icon: hasHomo ? '🎭' : '✅' });
  if (hasHomo) riskScore += 40;

  const typoHit = TYPOSQUAT_BRANDS.find(b => {
    if (hostname.includes(b)) return false;
    const clean = hostname.replace(/[^a-z]/g,'');
    return levenshtein(clean, b) <= 2 && clean !== b && clean.length > 3;
  });
  checks.push({ name: typoHit ? `Typosquatting (≈${typoHit})` : 'No Typosquatting', desc: typoHit ? `Resembles "${typoHit}".` : 'No brand impersonation.', status: typoHit ? 'bad' : 'ok', icon: typoHit ? '👥' : '✅' });
  if (typoHit) riskScore += 35;

  const longHost = hostname.length > 40;
  checks.push({ name: longHost ? `Long Hostname (${hostname.length}c)` : 'Hostname Length OK', desc: longHost ? 'Unusual length detected.' : 'Length normal.', status: longHost ? 'warn' : 'ok', icon: longHost ? '📏' : '✅' });
  if (longHost) riskScore += 15;

  const subCount = tldParts.length - 2;
  checks.push({ name: subCount > 2 ? `Deep Subdomains (${subCount})` : 'Subdomain Depth OK', desc: subCount > 2 ? `${subCount} levels — suspicious.` : 'Normal.', status: subCount > 2 ? 'warn' : 'ok', icon: subCount > 2 ? '🗂️' : '✅' });
  if (subCount > 2) riskScore += 15;

  const encCount = (path.match(/%[0-9a-f]{2}/gi) || []).length;
  checks.push({ name: encCount > 4 ? `Heavy Encoding (${encCount})` : 'Encoding Normal', desc: encCount > 4 ? 'Excessive percent-encoding.' : 'Normal.', status: encCount > 4 ? 'warn' : 'ok', icon: encCount > 4 ? '🔢' : '✅' });
  if (encCount > 4) riskScore += 15;

  const hasAt = parsed.username !== '';
  checks.push({ name: hasAt ? 'Credential Trick (@)' : 'No @ Trick', desc: hasAt ? '@ used to spoof destination.' : 'No @ trick.', status: hasAt ? 'bad' : 'ok', icon: hasAt ? '🪤' : '✅' });
  if (hasAt) riskScore += 30;

  return { checks, riskScore: Math.min(Math.round(riskScore), 100) };
}

// ── Build recommendations ──
function buildRecs(verdict, checks, vt) {
  const recs = [];
  if (verdict === 'danger')  recs.push({ icon:'🚫', text:'Do not visit this URL — high risk of phishing or malware.' });
  if (verdict === 'warning') recs.push({ icon:'⚠️', text:'Proceed with extreme caution. Verify independently before visiting.' });
  if (verdict === 'safe')    recs.push({ icon:'✅', text:'URL appears safe. Always stay vigilant online.' });
  if (checks.some(c => c.name.includes('Phishing') && c.status === 'bad'))    recs.push({ icon:'🎣', text:'Phishing keywords detected. Never enter credentials here.' });
  if (checks.some(c => c.name.includes('Typosquat') && c.status === 'bad'))   recs.push({ icon:'👥', text:'Possible brand impersonation. Double-check the URL.' });
  if (checks.some(c => c.name.includes('Homoglyph') && c.status === 'bad'))   recs.push({ icon:'🎭', text:'Homoglyph attack suspected — characters look real but aren\'t.' });
  if (checks.some(c => c.name.includes('Shortener') && c.status === 'warn'))  recs.push({ icon:'🔗', text:'Use a link expander to preview the real destination.' });
  if (vt && vt.malicious > 0) recs.push({ icon:'🦠', text:`VirusTotal: ${vt.malicious} engine(s) flagged this URL as malicious.` });
  recs.push({ icon:'💡', text:'This tool uses heuristics + threat intelligence. Always verify with multiple sources.' });
  return recs;
}

// ── API Route ──
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  let parsed;
  try { parsed = new URL(url); }
  catch(e) { return res.status(400).json({ error: 'Invalid URL' }); }

  const hostname = parsed.hostname;

  try {
    const [dnsInfo, sslInfo, redirectChain, vtResult, heuristics] = await Promise.allSettled([
      getDNSInfo(hostname),
      getSSLInfo(hostname),
      followRedirects(url),
      checkVirusTotal(url),
      Promise.resolve(runHeuristics(url)),
    ]);

    const dns       = dnsInfo.status === 'fulfilled'      ? dnsInfo.value      : {};
    const ssl       = sslInfo.status === 'fulfilled'      ? sslInfo.value      : {};
    const redirects = redirectChain.status === 'fulfilled' ? redirectChain.value : [url];
    const vt        = vtResult.status === 'fulfilled'     ? vtResult.value     : null;
    const { checks, riskScore } = heuristics.value;

    // Boost score if VirusTotal flags
    let finalScore = riskScore;
    if (vt && vt.malicious > 0) finalScore = Math.min(100, finalScore + vt.malicious * 10);
    if (vt) checks.push({
      name: vt.malicious > 0 ? `VirusTotal: ${vt.malicious} Detections` : 'VirusTotal: Clean',
      desc: `${vt.malicious} malicious, ${vt.suspicious} suspicious, ${vt.harmless} harmless engines.`,
      status: vt.malicious > 0 ? 'bad' : vt.suspicious > 0 ? 'warn' : 'ok',
      icon: vt.malicious > 0 ? '🔴' : '🟢',
    });

    const verdict = finalScore >= 60 ? 'danger' : finalScore >= 25 ? 'warning' : 'safe';
    const recs    = buildRecs(verdict, checks, vt);

    // Format DNS for display
    const dnsDisplay = {
      hostname,
      'ipv4':        dns.ipv4 || 'N/A',
      'mx record':   dns.mx   || 'N/A',
      'nameserver':  dns.nameserver || 'N/A',
      'spf record':  dns.spf  || 'N/A',
    };

    res.json({ verdict, score: finalScore, checks, dns: dnsDisplay, ssl, redirects, recs, vt });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: 'Scan failed', message: e.message });
  }
});

app.get('/api/health', (_, res) => res.json({ status: 'ok', version: '2.0' }));

app.listen(PORT, () => console.log(`ThreatScan API running on port ${PORT}`));
