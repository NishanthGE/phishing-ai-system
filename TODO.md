# Phishing Detection System — TODO / Roadmap

**Project Path:** `d:\CapstoneNew\Capstone\phishing-ai-system`  
**Last Updated:** March 2026

---

## ✅ Completed

### Phase 1 — Backend Auth Setup
- [x] Install bcryptjs, jsonwebtoken
- [x] Create `src/backend/utils/userStore.js` (in-memory users)
- [x] Create `src/backend/controllers/authController.js` (signup/login)
- [x] Create `src/backend/routes/authRoutes.js`
- [x] Update `src/backend/server.js` with auth routes

### Phase 2 — Frontend UI Overhaul
- [x] Complete rewrite of `style.css` — premium dark cyberpunk/glassmorphism theme
- [x] Updated `index.html` — animated grid background, floating orbs, neon accents
- [x] Login page redesigned — two-column layout, brand panel, demo credentials
- [x] Dashboard — frosted-glass cards, neon tabs, color-coded results
- [x] Google Fonts — Inter + JetBrains Mono

### Phase 3 — Real ML Engine (v3.2)
- [x] Created `src/backend/utils/aiEngine.js`
- [x] **Naive Bayes classifier** trained on 160 labeled emails
- [x] **Random Forest URL classifier** — 5 weighted decision trees
- [x] Replaced keyword-based `emailAnalyzer.js` with ML version
- [x] Replaced keyword-based `urlAnalyzer.js` with ML version
- [x] Fixed false positives — stopwords, deduplication, prior bias
- [x] Fixed professional email false positives — `formalEmailScore()` context detector
- [x] Raised classification thresholds (Phishing ≥ 72, Suspicious ≥ 48)
- [x] Updated all project MD files to reflect current state

---

## 🔮 Future Enhancements

### ML Improvements
- [ ] Expand training dataset (500+ emails each class)
- [ ] Integrate external phishing email datasets (CEAS, SpamAssassin)
- [ ] Persist trained model to disk (avoid retraining on each restart)
- [ ] Add TF-IDF weighting on top of token frequency
- [ ] Implement n-gram features (bigrams) for better phrase detection
- [ ] Add feedback loop — users can mark false positives/negatives

### Backend
- [ ] MongoDB integration for analysis history
- [ ] Redis caching for repeated URL lookups
- [ ] WebSocket support for real-time streaming results
- [ ] External threat intelligence API integration (VirusTotal, Google Safe Browsing)
- [ ] Email header analysis (SPF, DKIM, DMARC checks)
- [ ] Docker deployment setup

### Frontend
- [ ] Analysis history page
- [ ] Comparison view (side-by-side threat breakdown)
- [ ] Export results as PDF/CSV
- [ ] Dark/light theme toggle

### Security
- [ ] Database-backed user authentication (replace in-memory store)
- [ ] Password hashing strength upgrade
- [ ] Admin panel for monitoring analyses
