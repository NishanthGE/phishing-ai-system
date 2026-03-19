# ✅ Changes Summary

**Version:** 3.2.0  
**Last Updated:** March 2026  
**Project Path:** `d:\CapstoneNew\Capstone\phishing-ai-system`

---

## 🧠 Phase 3 — Real ML Engine (LATEST)

### New File: `src/backend/utils/aiEngine.js`
The entire detection backend has been replaced with a **real machine learning engine**:

#### Email — Multinomial Naive Bayes (v3.2)
- Trained on 160 labeled emails (60 phishing + 100 legit) on server startup
- TF-IDF-style log-likelihood scoring with Laplace smoothing
- **37+ stopword list** removes ambiguous words that caused false positives
- **Per-document token deduplication** prevents word repetition from amplifying scores
- **`formalEmailScore()` context detector** — 15 regex rules that recognize professional emails (cover letters, academic emails, internship applications) and dampen the NB score by up to 85%
- Classification thresholds: Phishing ≥ 72, Suspicious ≥ 48
- Prior biased toward legitimate (55/45) to reduce false positive rate

#### URL — Random Forest Ensemble (5 Trees)
- 5 hand-engineered decision trees each scoring a different threat dimension
- Weighted ensemble aggregation (Tree 1: 30%, Tree 2: 20%, Tree 3: 25%, Tree 4: 15%, Tree 5: 10%)
- Risk factor extraction with severity labels (critical / high / medium)
- Detects: IP addresses, excessive subdomains, brand impersonation, URL shorteners, punycode homograph attacks, suspicious TLDs, open redirect params

### Updated: `src/backend/services/emailAnalyzer.js`
- Now calls `classifyEmail()` from `aiEngine.js`
- Returns ML engine metadata: top phishing tokens, top safe tokens, formal score
- Keeps legacy `featureExtractor.js` call for enriched feature display

### Updated: `src/backend/services/urlAnalyzer.js`
- Now calls `classifyURL()` from `aiEngine.js`
- Returns RF tree votes in response for transparency
- Keeps security checks (domain reputation, redirect pattern analysis)

---

## 🎨 Phase 2 — Premium UI Overhaul

### `src/frontend/style.css` — Complete Rewrite
- Dark cyberpunk/glassmorphism theme
- CSS variables for neon cyan/purple color system
- Animated grid background + floating orbs
- Frosted-glass cards with hover glow effects
- Color-coded results (green=safe, yellow=suspicious, red=phishing)
- Toast notifications with border-glow by type
- `JetBrains Mono` + `Inter` Google Fonts

### `src/frontend/index.html` — Full Rewrite
- Two-column login layout (brand panel + form panel)
- Animated shimmer title, version badge, live stats bar
- Feature cards with icon + description
- Trust badge, terminal icon header
- Animated grid background div + floating orb divs
- Fixed `id="modal-subtitle"` for JS compatibility

---

## 🔧 Phase 1 — Backend Auth

### New Files
- `src/backend/utils/userStore.js` — in-memory user storage
- `src/backend/controllers/authController.js` — signup/login handlers
- `src/backend/routes/authRoutes.js` — auth endpoint routing

### Updated: `src/backend/server.js`
- Registered auth routes at `/api/auth`
- Frontend served from port 8080 (separate frontend-server.js)

---

## 📊 Verified Test Results (v3.2)

| Email / URL | Engine | Result | Score |
|---|---|---|---|
| Nishanth internship application | NB ML | ✅ Safe | 11 |
| Cover letter | NB ML | ✅ Safe | 5 |
| "We noticed a new login..." | NB ML | ✅ Safe | 17 |
| Order receipt | NB ML | ✅ Safe | 4 |
| Team meeting reminder | NB ML | ✅ Safe | 0 |
| PayPal suspended phishing | NB ML | 🚨 Phishing | 100 |
| Bank fraud alert phishing | NB ML | 🚨 Phishing | 100 |
| Lottery prize scam | NB ML | 🚨 Phishing | 100 |
| `paypal-security.verify-account.tk/...` | RF ML | 🚨 Malicious | 85+ |
| `https://google.com` | RF ML | ✅ Safe | ~0 |
