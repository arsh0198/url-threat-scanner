# ⬡ ThreatScan v2.0 — URL Security Analyzer

A full-stack URL threat scanner with deep analysis across DNS records, SSL certificates, redirect chains, heuristic detection, and VirusTotal integration.

**Live Demo:** [arsh0198.github.io/threat-scanner](https://arsh0198.github.io/threat-scanner)

---

## Features

### Frontend
- 🎯 **Risk Score** (0–100) with animated bar
- 🎣 **Phishing keyword detection**
- 🦠 **Malware indicator detection**
- 🎭 **Homoglyph / Cyrillic character detection**
- 👥 **Typosquatting detection** (Levenshtein distance vs 14 major brands)
- 🔗 **URL shortener detection**
- 🚨 **IP-as-host detection**
- 📏 **Hostname length & subdomain depth analysis**
- 🕓 **Persistent scan history** (localStorage)
- 🌙 **Dark terminal aesthetic**

### Backend (when deployed)
- 🌐 **Real DNS lookup** (A records, MX, NS, SPF)
- 🔒 **SSL/TLS certificate inspection** (issuer, expiry, protocol)
- 🔁 **Redirect chain following** (up to 5 hops)
- 🔴 **VirusTotal API integration** (70+ antivirus engines)
- ⚡ **Parallel async analysis** for fast results

---

## File Structure

```
threat-scanner/
├── public/
│   ├── index.html     # App UI
│   ├── style.css      # Dark terminal styles
│   └── app.js         # Frontend logic
├── server.js          # Express API backend
├── package.json
└── README.md
```

---

## Deployment

### Step 1 — GitHub Pages (Frontend)
1. Push this repo to GitHub
2. Go to **Settings → Pages → Source: main → / (root)**  
   *(Pages will serve `public/index.html` if root has no index.html)*  
   **Actually:** rename `public/index.html` → move files to root, OR use `/public` as the Pages source folder... or just follow Step 2 first.

> **Easiest:** upload the contents of the `public/` folder directly to the root of your repo (alongside `server.js`). GitHub Pages will find `index.html` at root.

### Step 2 — Render.com (Backend, free)
1. Go to [render.com](https://render.com) → New → **Web Service**
2. Connect your GitHub repo
3. Settings:
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
   - **Environment:** Node
4. Add environment variable:
   - `VIRUSTOTAL_API_KEY` → get your free key at [virustotal.com](https://www.virustotal.com/gui/join-us)
5. Click **Deploy**
6. Copy your Render URL (e.g. `https://threatscan-xyz.onrender.com`)

### Step 3 — Connect Frontend to Backend
Open `public/app.js` and update line 7:
```js
const BACKEND_URL = 'https://threatscan-xyz.onrender.com';
```
Commit and push — done!

---

## Risk Score Breakdown

| Check | Points |
|---|---|
| No HTTPS | +20 |
| IP as hostname | +35 |
| Suspicious TLD | +20 |
| URL shortener | +25 |
| Phishing keywords | +12 each (max 40) |
| Malware keywords | +10 each (max 30) |
| Homoglyph characters | +40 |
| Typosquatting | +35 |
| Long hostname | +15 |
| Deep subdomains | +15 |
| Heavy URL encoding | +15 |
| @ trick | +30 |
| VirusTotal detections | +10 per engine |

- **0–24** → 🛡️ Safe
- **25–59** → ⚠️ Suspicious
- **60–100** → ☠️ Dangerous

---

> **Disclaimer:** Heuristic analysis only. Not a replacement for professional security tools. Always verify with multiple sources.

---

Made by **Arsh Abbasi** · [github.com/arsh0198](https://github.com/arsh0198)
